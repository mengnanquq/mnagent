package miaospeed

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/mengnanquq/mnagent/internal/model"
	"github.com/mengnanquq/mnagent/internal/probe"
)

// MiaospeedNode 描述解析出的代理节点。
type MiaospeedNode struct {
	Name     string
	Protocol string
	Server   string
	Port     int
	Payload  string // YAML 格式节点配置
	URL      string // 节点原始或生成的代理 URL
}

// 代理配置大小上限默认值。服务端会对 ≤12MB 的配置正文做内联下发
// （mengnanbot subscription.go），订阅下载默认 16MB；低内存设备还要按物理内存收紧。
// 超限直接报错而不是截断：截断后的 YAML/JSON 往往还能解析出半截节点，容易把
// “配置过大”误报成“没有有效节点”，也会让用户以为任务已按原样执行。
const (
	defaultMaxInlineProxyTargetBytes = 12 << 20
	defaultMaxSubscriptionBytes      = 16 << 20
	minProxyContentLimitBytes        = 2 << 20
)

var (
	// maxInlineProxyTargetBytes / maxSubscriptionBytes 是当前设备实际生效的上限，
	// 启动时按 /proc/meminfo 的 MemTotal 计算（非 Linux 或读取失败时用默认值）。
	maxInlineProxyTargetBytes       = defaultMaxInlineProxyTargetBytes
	maxSubscriptionBytes      int64 = defaultMaxSubscriptionBytes
	// readMemTotalKB 可在测试中注入，返回物理内存总量（KB）。
	readMemTotalKB = readLinuxMemTotalKB
)

func init() {
	refreshProxyContentLimits()
}

// refreshProxyContentLimits 按设备内存重算内联配置与订阅上限：
// 内联 min(12MB, MemTotal/8)，订阅 min(16MB, MemTotal/6)，两者下限均为 2MB。
// 32–64MB 的 OpenWrt 设备据此把上限压到 4–10MB，避免“上限没到但内存先耗尽”。
func refreshProxyContentLimits() {
	maxInlineProxyTargetBytes = defaultMaxInlineProxyTargetBytes
	maxSubscriptionBytes = defaultMaxSubscriptionBytes
	if runtime.GOOS != "linux" {
		return
	}
	memKB, ok := readMemTotalKB()
	if !ok || memKB <= 0 {
		return
	}
	memBytes := memKB * 1024
	maxInlineProxyTargetBytes = int(capProxyContentLimit(defaultMaxInlineProxyTargetBytes, memBytes/8))
	maxSubscriptionBytes = capProxyContentLimit(defaultMaxSubscriptionBytes, memBytes/6)
}

func capProxyContentLimit(def, byMemory int64) int64 {
	limit := def
	if byMemory > 0 && byMemory < limit {
		limit = byMemory
	}
	if limit < minProxyContentLimitBytes {
		limit = minProxyContentLimitBytes
	}
	return limit
}

// readLinuxMemTotalKB 读取 /proc/meminfo 的 MemTotal（KB）。
func readLinuxMemTotalKB() (int64, bool) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "MemTotal:" {
			continue
		}
		kb, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil || kb <= 0 {
			return 0, false
		}
		return kb, true
	}
	return 0, false
}

// parseProxyTarget 将任务 Target（单节点链接、订阅 URL 或代理配置文件内容）解析为节点列表。
func parseProxyTarget(ctx context.Context, target string, allowPrivate ...bool) ([]MiaospeedNode, error) {
	if len(target) > maxInlineProxyTargetBytes {
		return nil, fmt.Errorf("内联代理配置过大：%d 字节，超过当前设备上限 %d MB（请改用订阅 URL，或减少配置中的节点数量）",
			len(target), maxInlineProxyTargetBytes>>20)
	}
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, errors.New("目标地址不能为空")
	}

	// 1. 如果是以 http:// 或 https:// 开头的订阅地址，拉取并解析。
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return fetchAndParseSubscription(ctx, target, allowPrivate...)
	}

	// 2. 解析本地/直接传入的配置文件或节点文本（支持 Clash YAML、Sing-box JSON、Base64 订阅、多行 URI 及单节点）。
	return parseProxyContent(target)
}

// parseProxyContent 解析代理配置文件或节点文本内容，支持：
// 1. Clash/Meta 配置文件（包含 proxies:）
// 2. Sing-box JSON 配置文件（包含 outbounds 或节点数组）
// 3. 裸 YAML 代理节点列表（以 - name: / - { 开头）
// 4. Base64 编码的订阅/配置内容
// 5. 多行代理 URI 列表（ss/ssr/vmess/vless/trojan/hysteria2/tuic/anytls/socks5/snell）
// 6. 单个原生 YAML 节点或单节点 URI
func parseProxyContent(content string) ([]MiaospeedNode, error) {
	content = strings.TrimSpace(content)
	content = strings.TrimPrefix(content, "\xef\xbb\xbf") // 移除 UTF-8 BOM
	content = strings.ReplaceAll(content, "\r\n", "\n")
	content = strings.TrimSpace(content)
	if content == "" {
		return nil, errors.New("代理配置内容为空")
	}

	// 1. Clash YAML 配置（包含 proxies:）
	if strings.Contains(content, "proxies:") {
		nodes := parseClashYAMLProxies(content)
		if len(nodes) > 0 {
			return nodes, nil
		}
	}

	// 2. Sing-box JSON 配置文件（以 { 或 [ 开头）
	if strings.HasPrefix(content, "{") || strings.HasPrefix(content, "[") {
		nodes := parseSingBoxJSON(content)
		if len(nodes) > 0 {
			return nodes, nil
		}
	}

	// 3. 裸 YAML 代理列表（无顶层 proxies:，直接以 - name: 或 - { 开头）
	trimmedLines := strings.Split(content, "\n")
	firstNonEmpty := ""
	for _, l := range trimmedLines {
		tl := strings.TrimSpace(l)
		if tl != "" && !strings.HasPrefix(tl, "#") {
			firstNonEmpty = tl
			break
		}
	}
	if strings.HasPrefix(firstNonEmpty, "-") && (strings.Contains(content, "name:") || strings.Contains(content, "type:")) {
		nodes := parseClashYAMLProxies("proxies:\n" + content)
		if len(nodes) > 0 {
			return nodes, nil
		}
	}

	// 4. Base64 编码的配置文件或订阅内容
	if isPossibleBase64(content) {
		if decoded, err := decodeBase64Safe(content); err == nil && len(decoded) > 0 {
			decStr := strings.TrimSpace(string(decoded))
			if decStr != "" && decStr != content {
				if nodes, err := parseProxyContent(decStr); err == nil && len(nodes) > 0 {
					return nodes, nil
				}
			}
		}
	}

	// 5. 多行代理 URI 列表扫描：同样受候选节点上限约束，超出部分只计数、
	// 不再构造 MiaospeedNode（不保留 URL/凭据）并停止继续累积。
	var uriNodes []MiaospeedNode
	uriOverflow := 0
	for _, line := range trimmedLines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		// 先判断上限再解析：超限行只计数，避免对 12MB 列表逐行构造节点/URL
		// 后又立刻丢弃，造成数倍于输入的内存峰值。
		if len(uriNodes) >= maxNodeFilterCandidates {
			uriOverflow++
			continue
		}
		n, err := parseProxyURI(line)
		if err != nil || n == nil {
			continue
		}
		uriNodes = append(uriNodes, *n)
	}
	if uriOverflow > 0 {
		slog.Warn("URI 列表节点数超过单次安全检查上限，超出部分未参与测速",
			"limit", maxNodeFilterCandidates, "overflow", uriOverflow)
	}
	if len(uriNodes) > 0 {
		return uriNodes, nil
	}

	// 6. 单个原生 YAML 节点（包含 type: 与 server:/port:）
	if strings.Contains(content, "type:") && (strings.Contains(content, "server:") || strings.Contains(content, "port:")) {
		name := "Custom-Node"
		pType := ""
		server := ""
		port := ""
		for _, line := range trimmedLines {
			// 只认顶层键：嵌套映射（如 notes:
			//   server: ...）里的 server 不能覆盖顶层 server，否则会校验诱饵地址、
			// 实际把未校验地址原样交给 miaospeed。
			if len(line)-len(strings.TrimLeft(line, " \t")) != 0 {
				continue
			}
			parseLineKeyValue(strings.TrimSpace(line), &name, &pType, &server, &port)
		}
		srv := formatServerPortString(server, port)
		return []MiaospeedNode{{
			Name:     name,
			Protocol: pType,
			Server:   srv,
			Payload:  content,
		}}, nil
	}

	// 7. 单节点 URI 解析（保留单条 URI 的具体报错信息）
	node, err := parseProxyURI(content)
	if err != nil {
		return nil, err
	}
	return []MiaospeedNode{*node}, nil
}

// isPossibleBase64 判断字符串是否可能为 Base64 编码的订阅文本。
func isPossibleBase64(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) < 8 || strings.Contains(s, "://") || strings.Contains(s, "proxies:") {
		return false
	}
	for _, r := range s {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') ||
			r == '+' || r == '/' || r == '=' || r == '-' || r == '_' ||
			r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			continue
		}
		return false
	}
	return true
}

// newSafeSubscriptionClient 构建具备 SSRF 防护的 HTTP 客户端，禁止向回环、内网私有与云元数据地址拉取订阅。
func newSafeSubscriptionClient(allowPrivate bool) *http.Client {
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	transport := &http.Transport{
		// 禁止使用环境代理：设置 HTTP(S)_PROXY 时 DialContext 拿到的是代理地址，
		// 代理会自行解析并连接目标，下面按解析 IP 做的 SSRF 校验会被完全绕过（与 probe 包一致）。
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
			if err != nil {
				return nil, err
			}
			if !allowPrivate {
				for _, ip := range ips {
					if probe.IsBlockedProbeIP(ip) {
						return nil, fmt.Errorf("安全拦截：禁止向私有内网或云元数据地址请求订阅 (%s)", ip.String())
					}
				}
			}
			if len(ips) == 0 {
				return nil, fmt.Errorf("无法解析目标主机: %s", host)
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
		},
	}
	return &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("重定向次数过多")
			}
			// 重定向目标同样经过 DialContext 的 IP 校验；这里额外拒绝非 http(s) 协议。
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
				return fmt.Errorf("不支持的重定向协议: %s", req.URL.Scheme)
			}
			return nil
		},
	}
}

// fetchAndParseSubscription 拉取订阅并提取节点，支持 Base64 URI 列表、Clash YAML 与 Sing-box JSON。
func fetchAndParseSubscription(ctx context.Context, subURL string, allowPrivate ...bool) ([]MiaospeedNode, error) {
	allowPriv := len(allowPrivate) > 0 && allowPrivate[0]
	// 依次尝试主流订阅客户端 User-Agent，优先获取原生 Clash-Meta 配置（miaospeed 基于 Clash-Meta 核心），避免手动逆向协议丢失 TLS/证书指纹与高级参数
	userAgents := []string{"ClashMeta", "clash.meta", "Clash.Meta; mihomo", "mihomo", "v2rayng", "clash"}
	client := newSafeSubscriptionClient(allowPriv)

	var lastErr error
	for _, ua := range userAgents {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, subURL, nil)
		if err != nil {
			return nil, fmt.Errorf("构建订阅请求失败: %w", err)
		}
		req.Header.Set("User-Agent", ua)

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			lastErr = fmt.Errorf("拉取订阅返回 HTTP %d", resp.StatusCode)
			continue
		}
		// 响应声明了 Content-Length 且已超限时，读取 body 之前就拒绝，
		// 避免先把超限内容读入内存再报错。
		if resp.ContentLength > maxSubscriptionBytes {
			resp.Body.Close()
			return nil, fmt.Errorf("订阅内容超过当前设备上限（%d MB），已拒绝解析；请精简订阅或改用较小的配置", maxSubscriptionBytes>>20)
		}

		// 多读 1 字节用于判断是否超限：超限必须明确报错，不能静默截断成半截配置。
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxSubscriptionBytes+1))
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		if int64(len(body)) > maxSubscriptionBytes {
			return nil, fmt.Errorf("订阅内容超过当前设备上限（%d MB），已拒绝解析；请精简订阅或改用较小的配置", maxSubscriptionBytes>>20)
		}

		content := strings.TrimSpace(string(body))
		if nodes, err := parseProxyContent(content); err == nil && len(nodes) > 0 {
			return nodes, nil
		}
		lastErr = errors.New("订阅中未找到有效代理节点")
	}

	if lastErr != nil {
		return nil, errors.New(redactProxyError(lastErr.Error(), subURL))
	}
	return nil, errors.New("订阅中未找到有效代理节点")
}

var (
	httpURLRegex  = regexp.MustCompile(`https?://[^\s"'<>\(\)]+`)
	proxyURIRegex = regexp.MustCompile(`(?i)\b(?:vmess|vless|ss|ssr|trojan|hysteria2|hy2|hysteria|hy|tuic|anytls|clash)://[^\s"'<>\(\)]+`)

	// targetURISchemeRegex 只匹配文本起始处的合法 URI scheme；多行配置或正文里
	// 偶然出现的 :// 不应把整段内容当作单节点 URI 处理。
	targetURISchemeRegex = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9+.-]{0,31})://`)
)

// redactURL 对 HTTP/HTTPS 订阅 URL 进行脱敏，保留 scheme 与 host（含非默认端口），
// 将敏感的 path、query、userinfo 及 fragment 替换为 /***。
func redactURL(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		if idx := strings.Index(rawURL, "://"); idx != -1 {
			scheme := rawURL[:idx]
			return scheme + "://***"
		}
		return "***"
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme == "" {
		scheme = "http"
	}
	hasSensitiveParts := (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil || u.Fragment != ""
	if hasSensitiveParts {
		return fmt.Sprintf("%s://%s/***", scheme, u.Host)
	}
	if strings.HasSuffix(rawURL, "/") {
		return fmt.Sprintf("%s://%s/", scheme, u.Host)
	}
	return fmt.Sprintf("%s://%s", scheme, u.Host)
}

// RedactTargetForLog 返回适合写入日志的 miaospeed 目标描述，避免泄露订阅令牌或节点凭据。
// HTTP(S) 订阅只保留 scheme 与 host；其他代理 URI 只保留 scheme；非 URL 文本
// （Clash YAML、Base64 订阅、多行节点等）只记录字节数与行数。
func RedactTargetForLog(target string) string {
	t := strings.TrimSpace(target)
	if t == "" {
		return ""
	}
	// 只有“整个目标就是一条 URI”时才按 URI 脱敏。Clash YAML 等多行配置里
	// 可能包含 http:// 健康检查地址，若用 strings.Index 找第一个 ://，会把
	// 它前面含 password/uuid 的配置原样带进日志。
	if !strings.ContainsAny(t, "\r\n") {
		if m := targetURISchemeRegex.FindStringSubmatch(t); m != nil {
			scheme := m[1]
			if strings.EqualFold(scheme, "http") || strings.EqualFold(scheme, "https") {
				return redactURL(t)
			}
			// vmess/ss 等 URI 的主体本身就是凭据（甚至被当作 host 解析），不能复用 redactURL。
			return scheme + "://***"
		}
	}
	lines := strings.Count(t, "\n") + 1
	return fmt.Sprintf("[已脱敏：%d 字节，%d 行]", len(t), lines)
}

func trimTrailingPunct(raw string) (cleaned string, trailing string) {
	cut := 0
	for i := len(raw) - 1; i >= 0; i-- {
		ch := raw[i]
		if ch == ':' || ch == ',' || ch == '.' || ch == ';' || ch == ')' || ch == ']' || ch == '}' || ch == '?' || ch == '!' {
			cut++
		} else {
			break
		}
	}
	if cut > 0 {
		return raw[:len(raw)-cut], raw[len(raw)-cut:]
	}
	return raw, ""
}

// redactProxyError 对测速目标解析与执行中的错误文本进行脱敏，防止泄露订阅 URL 或代理密钥凭据。
func redactProxyError(errText string, targets ...string) string {
	if strings.TrimSpace(errText) == "" {
		return errText
	}
	result := errText
	for _, target := range targets {
		t := strings.TrimSpace(target)
		if len(t) < 6 {
			continue
		}
		if strings.HasPrefix(strings.ToLower(t), "http://") || strings.HasPrefix(strings.ToLower(t), "https://") {
			redactedT := redactURL(t)
			result = strings.ReplaceAll(result, t, redactedT)
			if u, err := url.Parse(t); err == nil && u != nil {
				cleanPath := strings.Trim(u.Path, "/")
				if len(cleanPath) >= 8 && strings.Contains(result, cleanPath) {
					result = strings.ReplaceAll(result, cleanPath, "***")
				}
				if u.RawQuery != "" && len(u.RawQuery) >= 8 && strings.Contains(result, u.RawQuery) {
					result = strings.ReplaceAll(result, u.RawQuery, "***")
				}
			}
		} else if strings.Contains(t, "://") {
			schemeEnd := strings.Index(t, "://")
			scheme := t[:schemeEnd]
			result = strings.ReplaceAll(result, t, fmt.Sprintf("%s://***", scheme))
		} else {
			if strings.Contains(result, t) {
				result = strings.ReplaceAll(result, t, "[代理配置内容已脱敏]")
			}
		}
	}
	result = httpURLRegex.ReplaceAllStringFunc(result, func(matched string) string {
		cleaned, trailing := trimTrailingPunct(matched)
		return redactURL(cleaned) + trailing
	})
	result = proxyURIRegex.ReplaceAllStringFunc(result, func(matched string) string {
		cleaned, trailing := trimTrailingPunct(matched)
		schemeEnd := strings.Index(cleaned, "://")
		if schemeEnd != -1 {
			scheme := cleaned[:schemeEnd]
			return fmt.Sprintf("%s://***", scheme) + trailing
		}
		return "***" + trailing
	})
	return result
}

// maxStartupOutputBytes 限制随错误回传的子进程输出长度，避免把整段启动日志
// 写进错误/日志；只保留最后一段，通常就是导致启动失败的真正原因。
const maxStartupOutputBytes = 512

// redactMiaospeedStartupOutput 先脱敏再截断子进程输出，防止 miaospeed 启动失败时
// 把配置中的订阅 URL、代理凭据或健康检查地址原样带进错误和日志。
// 若输出直接包含任务目标配置中的任意一行（长度 ≥ 8），则无法可靠枚举并脱敏
// 节点 server/password 等字段，整体省略输出。
func redactMiaospeedStartupOutput(output string, targets ...string) string {
	target := ""
	if len(targets) > 0 {
		target = targets[0]
	}
	for _, line := range strings.Split(target, "\n") {
		line = strings.TrimSpace(line)
		if len(line) >= 8 && strings.Contains(output, line) {
			return "[输出包含任务配置，已省略]"
		}
	}
	redacted := redactProxyError(output)
	if len(redacted) <= maxStartupOutputBytes {
		return redacted
	}
	tail := redacted[len(redacted)-maxStartupOutputBytes:]
	for len(tail) > 0 && !utf8.RuneStart(tail[0]) {
		tail = tail[1:]
	}
	return "…" + tail
}

// parseClashYAMLProxies 从原生 Clash/Meta 配置文件中提取 proxies 节点。
func parseClashYAMLProxies(content string) []MiaospeedNode {
	content = strings.TrimPrefix(content, "\xef\xbb\xbf")
	content = strings.ReplaceAll(content, "\r\n", "\n")
	lines := strings.Split(content, "\n")
	var nodes []MiaospeedNode
	overflow := 0
	inProxies := false
	baseIndent := -1
	stopBuilding := false

	var currentItem strings.Builder
	currentName := ""
	currentType := ""
	currentServer := ""
	currentPort := ""
	inItem := false

	flushItem := func() {
		if inItem && currentItem.Len() > 0 {
			payload := strings.TrimSpace(currentItem.String())
			if currentName != "" && payload != "" {
				if len(nodes) >= maxNodeFilterCandidates {
					// 超出候选上限的节点不再构造 MiaospeedNode（不保留 payload、不生成 URL），
					// 但仍计数并写日志，保持 fail-closed 的可观测性。
					overflow++
				} else {
					nodes = append(nodes, MiaospeedNode{
						Name:     currentName,
						Protocol: currentType,
						Server:   formatServerPortString(currentServer, currentPort),
						Payload:  payload,
					})
				}
			}
		}
		currentItem.Reset()
		currentName = ""
		currentType = ""
		currentServer = ""
		currentPort = ""
		inItem = false
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !inProxies {
			if trimmed == "proxies:" || strings.HasPrefix(trimmed, "proxies: ") || strings.HasPrefix(trimmed, "proxies:\t") || strings.HasPrefix(trimmed, "proxies:#") {
				inProxies = true
			}
			continue
		}
		if inProxies {
			// 先过滤空行与注释行，避免顶格注释行被误判为下一个顶级配置段而提前中断
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}

			// 退出 proxies 块（遇到未缩进的下一个顶级配置段）
			if len(line) > 0 && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") && !strings.HasPrefix(line, "-") {
				flushItem()
				break
			}

			// 计算当前行前置空白缩进
			indent := len(line) - len(strings.TrimLeft(line, " \t"))

			// 已达到候选上限：不再构造 currentItem / 解析字段，只用轻量的
			// 顶层列表项计数说明还有多少节点被丢弃。
			if stopBuilding {
				if strings.HasPrefix(trimmed, "-") && (baseIndent == -1 || indent == baseIndent) {
					overflow++
				}
				continue
			}

			// 单行格式: - {name: ..., server: ..., ...}
			if strings.HasPrefix(trimmed, "- {") || strings.HasPrefix(trimmed, "-{") {
				flushItem()
				baseIndent = indent
				if len(nodes) >= maxNodeFilterCandidates {
					stopBuilding = true
					overflow++
					continue
				}
				rawItem := strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
				if closeIdx := strings.LastIndex(rawItem, "}"); closeIdx != -1 {
					rawItem = rawItem[:closeIdx+1]
				}
				name := extractField(rawItem, "name")
				pType := extractField(rawItem, "type")
				server := extractField(rawItem, "server")
				port := extractField(rawItem, "port")
				if name != "" {
					if len(nodes) >= maxNodeFilterCandidates {
						overflow++
					} else {
						nodes = append(nodes, MiaospeedNode{
							Name:     name,
							Protocol: pType,
							Server:   formatServerPortString(server, port),
							Payload:  rawItem,
						})
					}
				}
				continue
			}

			// 判断是否是列表新项：前缀为 "-"，且其缩进等于 baseIndent（或初次确定 baseIndent）
			isNewItem := false
			if strings.HasPrefix(trimmed, "-") {
				if baseIndent == -1 {
					baseIndent = indent
					isNewItem = true
				} else if indent == baseIndent {
					isNewItem = true
				}
			}

			if isNewItem {
				flushItem()
				if len(nodes) >= maxNodeFilterCandidates {
					stopBuilding = true
					overflow++
					continue
				}
				inItem = true
				contentAfterDash := strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
				if contentAfterDash != "" {
					currentItem.WriteString(contentAfterDash + "\n")
					parseLineKeyValue(contentAfterDash, &currentName, &currentType, &currentServer, &currentPort)
				}
			} else if inItem {
				// 保持子项的相对缩进
				relIndent := indent - (baseIndent + 2)
				if relIndent < 0 {
					relIndent = 0
				}
				currentItem.WriteString(strings.Repeat(" ", relIndent) + trimmed + "\n")
				if relIndent == 0 {
					parseLineKeyValue(trimmed, &currentName, &currentType, &currentServer, &currentPort)
				}
			}
		}
	}
	flushItem()
	if overflow > 0 {
		slog.Warn("Clash 配置节点数超过单次安全检查上限，超出部分未参与测速",
			"limit", maxNodeFilterCandidates, "overflow", overflow)
	}
	return nodes
}

func parseLineKeyValue(line string, name, pType, server, port *string) {
	// 先去掉引号外的行尾注释，避免 `server: 1.2.3.4 # 备注` 把注释一起当成地址，
	// 进而导致合法公网节点被误剔除。
	line = stripYAMLInlineComment(line)
	if idx := strings.Index(line, ":"); idx != -1 {
		k := strings.ToLower(strings.TrimSpace(line[:idx]))
		v := strings.Trim(strings.TrimSpace(line[idx+1:]), "\"'")
		switch k {
		case "name":
			*name = v
		case "type":
			*pType = v
		case "server":
			*server = v
		case "port":
			*port = v
		}
	}
}

// stripYAMLInlineComment 去掉 YAML 行内注释：从引号外、前面为空白（或行首）的 '#'
// 开始直到行尾。与 YAML 一致，`value#not-comment` 不视作注释。
func stripYAMLInlineComment(line string) string {
	var quote byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		if quote != 0 {
			if quote == '"' && c == '\\' {
				i++
				continue
			}
			if c == quote {
				if quote == '\'' && i+1 < len(line) && line[i+1] == '\'' {
					i++
					continue
				}
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case '#':
			if i == 0 || line[i-1] == ' ' || line[i-1] == '\t' {
				return strings.TrimRight(line[:i], " \t")
			}
		}
	}
	return line
}

// extractField 从单行 YAML 项（如 {name: '...', type: hysteria2}）中安全提取指定键对应的值。
// 只接受映射顶层的键：嵌套映射里的同名键（如 ws-opts: { server: ... }）不会被误当成顶层字段。
func extractField(raw, key string) string {
	key = strings.TrimSuffix(strings.TrimSpace(key), ":")
	if key == "" || raw == "" {
		return ""
	}
	valStart, valEnd, ok := topLevelFieldValueSpan(raw, key)
	if !ok || valStart >= valEnd {
		return ""
	}
	val := raw[valStart:valEnd]
	switch val[0] {
	case '\'', '"':
		if len(val) >= 2 && val[len(val)-1] == val[0] {
			return val[1 : len(val)-1]
		}
		return strings.TrimSpace(val[1:])
	case '{', '[':
		return strings.TrimSpace(val)
	default:
		return strings.Trim(strings.TrimSpace(val), "\"'")
	}
}

type singBoxOutbound struct {
	Type              string `json:"type"`
	Tag               string `json:"tag"`
	Name              string `json:"name"`
	Server            string `json:"server"`
	ServerPort        int    `json:"server_port"`
	Port              int    `json:"port"`
	Method            string `json:"method"`
	Cipher            string `json:"cipher"`
	Password          string `json:"password"`
	Username          string `json:"username"`
	UUID              string `json:"uuid"`
	Flow              string `json:"flow"`
	Security          string `json:"security"`
	AlterID           int    `json:"alter_id"`
	AuthStr           string `json:"auth_str"`
	UpMbps            int    `json:"up_mbps"`
	DownMbps          int    `json:"down_mbps"`
	CongestionControl string `json:"congestion_control"`
	UDPRelayMode      string `json:"udp_relay_mode"`

	TLS *struct {
		Enabled    bool     `json:"enabled"`
		ServerName string   `json:"server_name"`
		Insecure   bool     `json:"insecure"`
		ALPN       []string `json:"alpn"`
		UTLS       *struct {
			Enabled     bool   `json:"enabled"`
			Fingerprint string `json:"fingerprint"`
		} `json:"utls"`
		Reality *struct {
			Enabled   bool   `json:"enabled"`
			PublicKey string `json:"public_key"`
			ShortID   string `json:"short_id"`
		} `json:"reality"`
	} `json:"tls"`

	Transport *struct {
		Type        string            `json:"type"`
		Path        string            `json:"path"`
		Headers     map[string]string `json:"headers"`
		ServiceName string            `json:"service_name"`
	} `json:"transport"`

	Obfs *singBoxObfs `json:"obfs"`
}

// singBoxObfs 统一两种 obfs 写法：hysteria(1) 的 obfs 是字符串（obfs 密码，
// 对应 mihomo HysteriaOption.Obfs），hysteria2 的 obfs 是 {type, password} 对象。
// 按对象解析会让 hy/hysteria 节点的整个 outbound 解码失败（等于静默丢弃），
// 因此用自定义 UnmarshalJSON 兼容两种形式。
type singBoxObfs struct {
	Type     string
	Password string
}

func (o *singBoxObfs) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err == nil {
		o.Type = ""
		o.Password = text
		return nil
	}
	var obj struct {
		Type     string `json:"type"`
		Password string `json:"password"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	o.Type = obj.Type
	o.Password = obj.Password
	return nil
}

// parseSingBoxJSON 从 Sing-box JSON 配置文件（或节点数组/单节点 JSON）中提取代理节点。
// 使用 json.Decoder 流式读取，只物化前 maxNodeFilterCandidates 个 outbounds/proxies
// 的 RawMessage：避免 []byte(content) 的整份拷贝，也不把超大数组一次解成全字段结构体。
// outbounds 与 proxies 两种顶层键都支持，且不依赖它们在 JSON 中出现的先后顺序。
func parseSingBoxJSON(content string) []MiaospeedNode {
	content = strings.TrimSpace(content)
	var (
		rawOutbounds []json.RawMessage
		overflow     int
	)

	switch {
	case strings.HasPrefix(content, "["):
		dec := json.NewDecoder(strings.NewReader(content))
		raws, over, err := decodeSingBoxArrayLimited(dec, maxNodeFilterCandidates)
		if err == nil {
			rawOutbounds, overflow = raws, over
		}
	case strings.HasPrefix(content, "{"):
		var outbounds, proxies []json.RawMessage
		var outboundOverflow, proxyOverflow int
		objectOK := true
		dec := json.NewDecoder(strings.NewReader(content))
		if tok, err := dec.Token(); err == nil && tok == json.Delim('{') {
		objectLoop:
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					objectOK = false
					break
				}
				key, ok := keyTok.(string)
				if !ok {
					objectOK = false
					break
				}
				switch key {
				case "outbounds":
					raws, over, err := decodeSingBoxArrayLimited(dec, maxNodeFilterCandidates)
					if err != nil {
						objectOK = false
						break objectLoop
					}
					outbounds, outboundOverflow = raws, over
					if len(outbounds) > 0 {
						// outbounds 优先于 proxies，与原有语义一致；已被 outbounds 取代的
						// proxies 立即释放，避免两份候选同时驻留。
						proxies, proxyOverflow = nil, 0
					}
				case "proxies":
					raws, over, err := decodeSingBoxArrayLimited(dec, maxNodeFilterCandidates)
					if err != nil {
						objectOK = false
						break objectLoop
					}
					proxies, proxyOverflow = raws, over
					if len(outbounds) > 0 {
						proxies, proxyOverflow = nil, 0
					}
				default:
					if err := skipJSONValue(dec); err != nil {
						objectOK = false
						break objectLoop
					}
				}
			}
			if objectOK {
				if closing, err := dec.Token(); err != nil || closing != json.Delim('}') {
					objectOK = false
				}
			}
		} else {
			objectOK = false
		}
		if objectOK {
			if len(outbounds) > 0 {
				rawOutbounds, overflow = outbounds, outboundOverflow
			} else if len(proxies) > 0 {
				rawOutbounds, overflow = proxies, proxyOverflow
			}
		}
	}

	if len(rawOutbounds) == 0 {
		// 单节点 JSON：只在没有 outbounds/proxies 数组时回退，避免把配置对象误当节点。
		var single singBoxOutbound
		if err := json.Unmarshal([]byte(content), &single); err == nil && single.Type != "" && single.Server != "" {
			if n := convertSingBoxOutbound(single); n != nil {
				return []MiaospeedNode{*n}
			}
			return nil
		}
		return nil
	}
	if overflow > 0 {
		slog.Warn("Sing-box 配置节点数超过单次安全检查上限，超出部分未参与测速",
			"limit", maxNodeFilterCandidates, "overflow", overflow)
	}

	nodes := make([]MiaospeedNode, 0, len(rawOutbounds))
	for _, raw := range rawOutbounds {
		var ob singBoxOutbound
		if err := json.Unmarshal(raw, &ob); err != nil {
			continue
		}
		if n := convertSingBoxOutbound(ob); n != nil {
			nodes = append(nodes, *n)
		}
	}
	return nodes
}

// decodeSingBoxArrayLimited 流式读取一个 JSON 数组，只保留前 limit 个元素的
// RawMessage；超出的元素用 Token 递归跳过并计数，不再整段物化。
func decodeSingBoxArrayLimited(dec *json.Decoder, limit int) ([]json.RawMessage, int, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, 0, err
	}
	if tok != json.Delim('[') {
		return nil, 0, fmt.Errorf("期望 JSON 数组，实际为 %v", tok)
	}
	raws := make([]json.RawMessage, 0, min(limit, 16))
	overflow := 0
	for dec.More() {
		if len(raws) < limit {
			var raw json.RawMessage
			if err := dec.Decode(&raw); err != nil {
				return nil, overflow, err
			}
			raws = append(raws, raw)
			continue
		}
		if err := skipJSONValue(dec); err != nil {
			return nil, overflow, err
		}
		overflow++
	}
	if _, err := dec.Token(); err != nil { // 消费 ']'
		return nil, overflow, err
	}
	return raws, overflow, nil
}

// skipJSONValue 用 Decoder.Token 递归跳过一个 JSON 值，不保留任何内容。
func skipJSONValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		for dec.More() {
			if _, err := dec.Token(); err != nil { // key
				return err
			}
			if err := skipJSONValue(dec); err != nil {
				return err
			}
		}
		_, err = dec.Token()
		return err
	case '[':
		for dec.More() {
			if err := skipJSONValue(dec); err != nil {
				return err
			}
		}
		_, err = dec.Token()
		return err
	default:
		return nil
	}
}

func convertSingBoxOutbound(ob singBoxOutbound) *MiaospeedNode {
	pType := strings.ToLower(strings.TrimSpace(ob.Type))
	switch pType {
	case "", "direct", "block", "dns", "selector", "urltest", "tor", "ssh", "wireguard":
		return nil
	case "shadowsocks":
		pType = "ss"
	case "hy2":
		pType = "hysteria2"
	case "hy":
		pType = "hysteria"
	case "socks":
		pType = "socks5"
	}

	port := ob.ServerPort
	if port == 0 {
		port = ob.Port
	}
	server := strings.TrimSpace(ob.Server)
	if server == "" || port <= 0 {
		return nil
	}

	name := strings.TrimSpace(ob.Tag)
	if name == "" {
		name = strings.TrimSpace(ob.Name)
	}
	if name == "" {
		name = fmt.Sprintf("%s-%s:%d", pType, server, port)
	}

	cleanServer := strings.Trim(strings.TrimSpace(server), "[]")

	var sb strings.Builder
	switch pType {
	case "ss":
		cipher := ob.Method
		if cipher == "" {
			cipher = ob.Cipher
		}
		if cipher == "" {
			cipher = "aes-256-gcm"
		}
		sb.WriteString(fmt.Sprintf("name: %s\ntype: ss\nserver: %s\nport: %d\ncipher: %s\npassword: %s\nudp: true\n",
			quoteYAML(name), quoteYAML(cleanServer), port, quoteYAML(cipher), quoteYAML(ob.Password)))
	case "vmess":
		cipher := ob.Security
		if cipher == "" {
			cipher = "auto"
		}
		netType := "tcp"
		if ob.Transport != nil && ob.Transport.Type != "" {
			netType = ob.Transport.Type
		}
		sb.WriteString(fmt.Sprintf("name: %s\ntype: vmess\nserver: %s\nport: %d\nuuid: %s\nalterId: %d\ncipher: %s\nudp: true\nnetwork: %s\n",
			quoteYAML(name), quoteYAML(cleanServer), port, quoteYAML(ob.UUID), ob.AlterID, quoteYAML(cipher), quoteYAML(netType)))
		writeSingBoxTLSAndTransport(&sb, ob, "servername")
	case "vless":
		netType := "tcp"
		if ob.Transport != nil && ob.Transport.Type != "" {
			netType = ob.Transport.Type
		}
		sb.WriteString(fmt.Sprintf("name: %s\ntype: vless\nserver: %s\nport: %d\nuuid: %s\nudp: true\nnetwork: %s\n",
			quoteYAML(name), quoteYAML(cleanServer), port, quoteYAML(ob.UUID), quoteYAML(netType)))
		if ob.Flow != "" {
			sb.WriteString(fmt.Sprintf("flow: %s\n", quoteYAML(ob.Flow)))
		}
		writeSingBoxTLSAndTransport(&sb, ob, "servername")
	case "trojan":
		netType := "tcp"
		if ob.Transport != nil && ob.Transport.Type != "" {
			netType = ob.Transport.Type
		}
		sb.WriteString(fmt.Sprintf("name: %s\ntype: trojan\nserver: %s\nport: %d\npassword: %s\nudp: true\n",
			quoteYAML(name), quoteYAML(cleanServer), port, quoteYAML(ob.Password)))
		if netType != "tcp" {
			sb.WriteString(fmt.Sprintf("network: %s\n", quoteYAML(netType)))
		}
		writeSingBoxTLSAndTransport(&sb, ob, "sni")
	case "hysteria":
		// sing-box 的 hy/hysteria 会被归一成 type: hysteria（mihomo 的 HysteriaOption），
		// 字段对照与 hysteria:// URI 的生成逻辑（parseHysteria1URI）保持一致：
		// protocol / auth-str / up / down / sni / alpn / skip-cert-verify / obfs。
		// mihomo 的 HysteriaOption.Up/Down 是必填字段（proxy tag 无 omitempty，
		// hysteria.go:109/111），Speed() 解出 0 会直接报错（hysteria.go:131-144），
		// 因此节点 JSON 缺 up_mbps/down_mbps 时补一个可用的默认值，否则节点会在
		// mihomo 创建代理时失败，等于仍被静默丢弃。
		up := "100 mbps"
		if ob.UpMbps > 0 {
			up = fmt.Sprintf("%d mbps", ob.UpMbps)
		}
		down := "100 mbps"
		if ob.DownMbps > 0 {
			down = fmt.Sprintf("%d mbps", ob.DownMbps)
		}
		sb.WriteString(fmt.Sprintf("name: %s\ntype: hysteria\nserver: %s\nport: %d\nprotocol: %s\nup: %s\ndown: %s\n",
			quoteYAML(name), quoteYAML(cleanServer), port, quoteYAML("udp"), quoteYAML(up), quoteYAML(down)))
		if ob.AuthStr != "" {
			sb.WriteString(fmt.Sprintf("auth-str: %s\n", quoteYAML(ob.AuthStr)))
		}
		if ob.Obfs != nil {
			// hysteria(1) 的 obfs 是字符串形式，落在 Password（见 singBoxObfs）。
			obfsValue := ob.Obfs.Type
			if obfsValue == "" {
				obfsValue = ob.Obfs.Password
			}
			if obfsValue != "" {
				sb.WriteString(fmt.Sprintf("obfs: %s\n", quoteYAML(obfsValue)))
			}
		}
		if ob.TLS != nil {
			if ob.TLS.ServerName != "" {
				sb.WriteString(fmt.Sprintf("sni: %s\n", quoteYAML(ob.TLS.ServerName)))
			}
			if ob.TLS.Insecure {
				sb.WriteString("skip-cert-verify: true\n")
			}
			if len(ob.TLS.ALPN) > 0 {
				sb.WriteString("alpn:\n")
				for _, a := range ob.TLS.ALPN {
					sb.WriteString(fmt.Sprintf("  - %s\n", quoteYAML(a)))
				}
			}
		}
	case "hysteria2":
		sb.WriteString(fmt.Sprintf("name: %s\ntype: hysteria2\nserver: %s\nport: %d\npassword: %s\nudp: true\n",
			quoteYAML(name), quoteYAML(cleanServer), port, quoteYAML(ob.Password)))
		if ob.TLS != nil {
			if ob.TLS.ServerName != "" {
				sb.WriteString(fmt.Sprintf("sni: %s\n", quoteYAML(ob.TLS.ServerName)))
			}
			if ob.TLS.Insecure {
				sb.WriteString("skip-cert-verify: true\n")
			}
			if len(ob.TLS.ALPN) > 0 {
				sb.WriteString("alpn:\n")
				for _, a := range ob.TLS.ALPN {
					sb.WriteString(fmt.Sprintf("  - %s\n", quoteYAML(a)))
				}
			}
		}
		if ob.Obfs != nil && ob.Obfs.Type != "" {
			sb.WriteString(fmt.Sprintf("obfs: %s\n", quoteYAML(ob.Obfs.Type)))
			if ob.Obfs.Password != "" {
				sb.WriteString(fmt.Sprintf("obfs-password: %s\n", quoteYAML(ob.Obfs.Password)))
			}
		}
	case "tuic":
		cc := ob.CongestionControl
		if cc == "" {
			cc = "bbr"
		}
		urm := ob.UDPRelayMode
		if urm == "" {
			urm = "native"
		}
		sb.WriteString(fmt.Sprintf("name: %s\ntype: tuic\nserver: %s\nport: %d\nuuid: %s\npassword: %s\nudp: true\ncongestion-controller: %s\nudp-relay-mode: %s\n",
			quoteYAML(name), quoteYAML(cleanServer), port, quoteYAML(ob.UUID), quoteYAML(ob.Password), quoteYAML(cc), quoteYAML(urm)))
		if ob.TLS != nil {
			if ob.TLS.ServerName != "" {
				sb.WriteString(fmt.Sprintf("sni: %s\n", quoteYAML(ob.TLS.ServerName)))
			}
			if ob.TLS.Insecure {
				sb.WriteString("skip-cert-verify: true\n")
			}
		}
	case "anytls":
		sb.WriteString(fmt.Sprintf("name: %s\ntype: anytls\nserver: %s\nport: %d\npassword: %s\nudp: true\n",
			quoteYAML(name), quoteYAML(cleanServer), port, quoteYAML(ob.Password)))
		writeSingBoxTLSAndTransport(&sb, ob, "sni")
	case "socks5":
		sb.WriteString(fmt.Sprintf("name: %s\ntype: socks5\nserver: %s\nport: %d\nudp: true\n",
			quoteYAML(name), quoteYAML(cleanServer), port))
		if ob.Username != "" {
			sb.WriteString(fmt.Sprintf("username: %s\n", quoteYAML(ob.Username)))
		}
		if ob.Password != "" {
			sb.WriteString(fmt.Sprintf("password: %s\n", quoteYAML(ob.Password)))
		}
	default:
		return nil
	}

	return &MiaospeedNode{
		Name:     name,
		Protocol: pType,
		Server:   formatServerAddress(server, port),
		Port:     port,
		Payload:  sb.String(),
	}
}

func writeSingBoxTLSAndTransport(sb *strings.Builder, ob singBoxOutbound, sniKey string) {
	if ob.TLS != nil && ob.TLS.Enabled {
		if sniKey == "servername" {
			sb.WriteString("tls: true\n")
		}
		if ob.TLS.ServerName != "" {
			sb.WriteString(fmt.Sprintf("%s: %s\n", sniKey, quoteYAML(ob.TLS.ServerName)))
		}
		if ob.TLS.Insecure {
			sb.WriteString("skip-cert-verify: true\n")
		}
		if ob.TLS.UTLS != nil && ob.TLS.UTLS.Fingerprint != "" {
			sb.WriteString(fmt.Sprintf("client-fingerprint: %s\n", quoteYAML(ob.TLS.UTLS.Fingerprint)))
		}
		if len(ob.TLS.ALPN) > 0 {
			sb.WriteString("alpn:\n")
			for _, a := range ob.TLS.ALPN {
				sb.WriteString(fmt.Sprintf("  - %s\n", quoteYAML(a)))
			}
		}
		if ob.TLS.Reality != nil && ob.TLS.Reality.Enabled && ob.TLS.Reality.PublicKey != "" {
			sb.WriteString("reality-opts:\n")
			sb.WriteString(fmt.Sprintf("  public-key: %s\n", quoteYAML(ob.TLS.Reality.PublicKey)))
			if ob.TLS.Reality.ShortID != "" {
				sb.WriteString(fmt.Sprintf("  short-id: %s\n", quoteYAML(ob.TLS.Reality.ShortID)))
			}
		}
	}
	if ob.Transport != nil {
		switch ob.Transport.Type {
		case "ws":
			sb.WriteString("ws-opts:\n")
			if ob.Transport.Path != "" {
				sb.WriteString(fmt.Sprintf("  path: %s\n", quoteYAML(ob.Transport.Path)))
			}
			if host := ob.Transport.Headers["Host"]; host != "" {
				sb.WriteString(fmt.Sprintf("  headers:\n    Host: %s\n", quoteYAML(host)))
			}
		case "grpc":
			if ob.Transport.ServiceName != "" {
				sb.WriteString(fmt.Sprintf("grpc-opts:\n  grpc-service-name: %s\n", quoteYAML(ob.Transport.ServiceName)))
			}
		}
	}
}

// parseProxyURI 解析主流代理协议 URI 为 MiaospeedNode。
func parseProxyURI(rawURI string) (*MiaospeedNode, error) {
	rawURI = strings.TrimSpace(rawURI)
	u, err := url.Parse(rawURI)
	if err != nil {
		return nil, fmt.Errorf("无法解析节点链接: %w", err)
	}

	var node *MiaospeedNode
	switch strings.ToLower(u.Scheme) {
	case "anytls":
		node, err = parseAnyTLSURI(u)
	case "ss":
		node, err = parseShadowsocksURI(rawURI, u)
	case "ssr":
		node, err = parseSSRURI(rawURI)
	case "vmess":
		node, err = parseVmessURI(rawURI)
	case "trojan":
		node, err = parseTrojanURI(u)
	case "vless":
		node, err = parseVlessURI(u)
	case "hysteria2", "hy2":
		node, err = parseHysteria2URI(u)
	case "hysteria", "hy":
		node, err = parseHysteria1URI(u)
	case "tuic":
		node, err = parseTuicURI(u)
	case "socks5", "socks":
		node, err = parseSocks5URI(u)
	case "snell":
		node, err = parseSnellURI(u)
	default:
		return nil, fmt.Errorf("不支持的代理协议：%s", u.Scheme)
	}
	if err != nil {
		return nil, err
	}
	if node != nil {
		node.URL = rawURI
	}
	return node, nil
}

func parseShadowsocksURI(rawURI string, u *url.URL) (*MiaospeedNode, error) {
	name := u.Fragment
	if name == "" {
		name = "SS-Node"
	}
	name, _ = url.QueryUnescape(name)

	var method, password, host string
	var port int

	if u.User != nil {
		user := u.User.Username()
		pwd, hasPwd := u.User.Password()
		if hasPwd {
			method = user
			password = pwd
		} else {
			// 尝试解码 base64(method:password)
			dec, err := decodeBase64Safe(user)
			if err == nil && strings.Contains(string(dec), ":") {
				parts := strings.SplitN(string(dec), ":", 2)
				method = parts[0]
				password = parts[1]
			} else {
				method = user
			}
		}
		host = u.Hostname()
		p, err := strconv.Atoi(u.Port())
		if err == nil {
			port = p
		}
	} else {
		// SIP002 格式：ss://BASE64(cipher:password@host:port)#name 或 ss://BASE64(cipher:password)@host:port
		encoded := u.Host
		if idx := strings.Index(encoded, "@"); idx != -1 {
			userDec, err := decodeBase64Safe(encoded[:idx])
			if err == nil {
				parts := strings.SplitN(string(userDec), ":", 2)
				if len(parts) == 2 {
					method = parts[0]
					password = parts[1]
				}
			}
			h, pStr, err := net.SplitHostPort(encoded[idx+1:])
			if err == nil {
				host = h
				port, _ = strconv.Atoi(pStr)
			}
		} else {
			dec, err := decodeBase64Safe(encoded)
			if err == nil {
				str := string(dec)
				parts := strings.SplitN(str, "@", 2)
				if len(parts) == 2 {
					userParts := strings.SplitN(parts[0], ":", 2)
					if len(userParts) == 2 {
						method = userParts[0]
						password = userParts[1]
					}
					h, pStr, err := net.SplitHostPort(parts[1])
					if err == nil {
						host = h
						port, _ = strconv.Atoi(pStr)
					}
				}
			}
		}
	}

	if host == "" || port == 0 || method == "" {
		return nil, errors.New("无效的 Shadowsocks 节点配置")
	}

	cleanHost := strings.Trim(strings.TrimSpace(host), "[]")
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("name: %s\ntype: ss\nserver: %s\nport: %d\ncipher: %s\npassword: %s\nudp: true\n",
		quoteYAML(name), quoteYAML(cleanHost), port, quoteYAML(method), quoteYAML(password)))
	if plugin := u.Query().Get("plugin"); plugin != "" {
		parts := strings.SplitN(plugin, ";", 2)
		sb.WriteString(fmt.Sprintf("plugin: %s\n", quoteYAML(parts[0])))
		if len(parts) > 1 && parts[1] != "" {
			sb.WriteString(fmt.Sprintf("plugin-opts:\n  opts: %s\n", quoteYAML(parts[1])))
		}
	}

	return &MiaospeedNode{
		Name:     name,
		Protocol: "ss",
		Server:   formatServerAddress(host, port),
		Port:     port,
		Payload:  sb.String(),
	}, nil
}

func decodeBase64Safe(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimRight(s, "/")
	if d, err := base64.StdEncoding.DecodeString(s); err == nil {
		return d, nil
	}
	if d, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return d, nil
	}
	if d, err := base64.URLEncoding.DecodeString(s); err == nil {
		return d, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}

func parseVmessURI(rawURI string) (*MiaospeedNode, error) {
	b64Part := strings.TrimPrefix(rawURI, "vmess://")
	b64Part = strings.TrimPrefix(b64Part, "VMESS://")
	data, err := decodeBase64Safe(b64Part)
	if err != nil {
		return nil, fmt.Errorf("解密 vmess 节点数据失败: %w", err)
	}

	var v map[string]any
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("解析 vmess JSON 失败: %w", err)
	}

	name := getString(v, "ps")
	if name == "" {
		name = "VMess-Node"
	}
	server := getString(v, "add")
	port := getInt(v, "port")
	uuid := getString(v, "id")
	alterID := getInt(v, "aid")
	cipher := getString(v, "scy")
	if cipher == "" {
		cipher = "auto"
	}
	netType := strings.ToLower(getString(v, "net"))
	if netType == "" {
		netType = "tcp"
	}
	tls := strings.EqualFold(getString(v, "tls"), "tls")
	host := getString(v, "host")
	path := getString(v, "path")
	sni := getString(v, "sni")
	fp := getString(v, "fp")
	alpn := getString(v, "alpn")

	cleanServer := strings.Trim(strings.TrimSpace(server), "[]")
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("name: %s\ntype: vmess\nserver: %s\nport: %d\nuuid: %s\nalterId: %d\ncipher: %s\nnetwork: %s\nudp: true\n",
		quoteYAML(name), quoteYAML(cleanServer), port, quoteYAML(uuid), alterID, quoteYAML(cipher), quoteYAML(netType)))
	if tls {
		sb.WriteString("tls: true\n")
		if sni != "" {
			sb.WriteString(fmt.Sprintf("servername: %s\n", quoteYAML(sni)))
		}
		if fp != "" {
			sb.WriteString(fmt.Sprintf("client-fingerprint: %s\n", quoteYAML(fp)))
		}
		if alpn != "" {
			sb.WriteString(fmt.Sprintf("alpn:\n  - %s\n", quoteYAML(alpn)))
		}
	}
	switch netType {
	case "ws":
		sb.WriteString("ws-opts:\n")
		if path != "" {
			sb.WriteString(fmt.Sprintf("  path: %s\n", quoteYAML(path)))
		}
		if host != "" {
			sb.WriteString(fmt.Sprintf("  headers:\n    Host: %s\n", quoteYAML(host)))
		}
	case "grpc":
		svcName := path
		if svcName == "" {
			svcName = host
		}
		if svcName != "" {
			sb.WriteString(fmt.Sprintf("grpc-opts:\n  grpc-service-name: %s\n", quoteYAML(svcName)))
		}
	case "h2", "http":
		sb.WriteString("h2-opts:\n")
		if path != "" {
			sb.WriteString(fmt.Sprintf("  path: %s\n", quoteYAML(path)))
		}
		if host != "" {
			sb.WriteString(fmt.Sprintf("  host:\n    - %s\n", quoteYAML(host)))
		}
	}

	return &MiaospeedNode{
		Name:     name,
		Protocol: "vmess",
		Server:   formatServerAddress(server, port),
		Port:     port,
		Payload:  sb.String(),
	}, nil
}

func parseTrojanURI(u *url.URL) (*MiaospeedNode, error) {
	name := u.Fragment
	if name == "" {
		name = "Trojan-Node"
	}
	name, _ = url.QueryUnescape(name)
	password := u.User.Username()
	server := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	if port == 0 {
		port = 443
	}
	q := u.Query()
	sni := q.Get("sni")
	if sni == "" {
		sni = q.Get("peer")
	}
	fp := q.Get("fp")
	insecure := q.Get("allowInsecure")
	if insecure == "" {
		insecure = q.Get("insecure")
	}
	alpn := q.Get("alpn")

	cleanServer := strings.Trim(strings.TrimSpace(server), "[]")
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("name: %s\ntype: trojan\nserver: %s\nport: %d\npassword: %s\nudp: true\n",
		quoteYAML(name), quoteYAML(cleanServer), port, quoteYAML(password)))
	if sni != "" {
		sb.WriteString(fmt.Sprintf("sni: %s\n", quoteYAML(sni)))
	}
	if fp != "" {
		sb.WriteString(fmt.Sprintf("client-fingerprint: %s\n", quoteYAML(fp)))
	}
	if insecure == "1" || strings.EqualFold(insecure, "true") {
		sb.WriteString("skip-cert-verify: true\n")
	}
	if alpn != "" {
		sb.WriteString(fmt.Sprintf("alpn:\n  - %s\n", quoteYAML(alpn)))
	}

	return &MiaospeedNode{
		Name:     name,
		Protocol: "trojan",
		Server:   formatServerAddress(server, port),
		Port:     port,
		Payload:  sb.String(),
	}, nil
}

func parseVlessURI(u *url.URL) (*MiaospeedNode, error) {
	name := u.Fragment
	if name == "" {
		name = "VLESS-Node"
	}
	name, _ = url.QueryUnescape(name)
	uuid := ""
	if u.User != nil {
		uuid = u.User.Username()
	}
	server := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	if port == 0 {
		port = 443
	}
	q := u.Query()
	security := strings.ToLower(q.Get("security"))
	sni := q.Get("sni")
	if sni == "" {
		sni = q.Get("peer")
	}
	netType := strings.ToLower(q.Get("type"))
	if netType == "" {
		netType = "tcp"
	}
	flow := q.Get("flow")
	fp := q.Get("fp")
	insecure := q.Get("insecure")
	if insecure == "" {
		insecure = q.Get("allowInsecure")
	}
	alpn := q.Get("alpn")

	cleanServer := strings.Trim(strings.TrimSpace(server), "[]")
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("name: %s\ntype: vless\nserver: %s\nport: %d\nuuid: %s\nnetwork: %s\nudp: true\n",
		quoteYAML(name), quoteYAML(cleanServer), port, quoteYAML(uuid), quoteYAML(netType)))
	if flow != "" {
		sb.WriteString(fmt.Sprintf("flow: %s\n", quoteYAML(flow)))
	}
	if security == "tls" || security == "reality" {
		sb.WriteString("tls: true\n")
		if sni != "" {
			sb.WriteString(fmt.Sprintf("servername: %s\n", quoteYAML(sni)))
		}
		if fp != "" {
			sb.WriteString(fmt.Sprintf("client-fingerprint: %s\n", quoteYAML(fp)))
		}
		if alpn != "" {
			sb.WriteString(fmt.Sprintf("alpn:\n  - %s\n", quoteYAML(alpn)))
		}
		if insecure == "1" || strings.EqualFold(insecure, "true") {
			sb.WriteString("skip-cert-verify: true\n")
		}
		if security == "reality" {
			pbk := q.Get("pbk")
			sid := q.Get("sid")
			spx := q.Get("spx")
			if pbk != "" || sid != "" || spx != "" {
				sb.WriteString("reality-opts:\n")
				if pbk != "" {
					sb.WriteString(fmt.Sprintf("  public-key: %s\n", quoteYAML(pbk)))
				}
				if sid != "" {
					sb.WriteString(fmt.Sprintf("  short-id: %s\n", quoteYAML(sid)))
				}
				if spx != "" {
					sb.WriteString(fmt.Sprintf("  spider-x: %s\n", quoteYAML(spx)))
				}
			}
		}
	}
	switch netType {
	case "ws":
		path := q.Get("path")
		host := q.Get("host")
		if path != "" || host != "" {
			sb.WriteString("ws-opts:\n")
			if path != "" {
				sb.WriteString(fmt.Sprintf("  path: %s\n", quoteYAML(path)))
			}
			if host != "" {
				sb.WriteString(fmt.Sprintf("  headers:\n    Host: %s\n", quoteYAML(host)))
			}
		}
	case "grpc":
		svcName := q.Get("serviceName")
		if svcName == "" {
			svcName = q.Get("servicename")
		}
		if svcName != "" {
			sb.WriteString(fmt.Sprintf("grpc-opts:\n  grpc-service-name: %s\n", quoteYAML(svcName)))
		}
	case "h2", "http":
		path := q.Get("path")
		host := q.Get("host")
		if path != "" || host != "" {
			sb.WriteString("h2-opts:\n")
			if path != "" {
				sb.WriteString(fmt.Sprintf("  path: %s\n", quoteYAML(path)))
			}
			if host != "" {
				sb.WriteString(fmt.Sprintf("  host:\n    - %s\n", quoteYAML(host)))
			}
		}
	}

	return &MiaospeedNode{
		Name:     name,
		Protocol: "vless",
		Server:   formatServerAddress(server, port),
		Port:     port,
		Payload:  sb.String(),
	}, nil
}

func parseHysteria2URI(u *url.URL) (*MiaospeedNode, error) {
	name := u.Fragment
	if name == "" {
		name = "Hysteria2-Node"
	}
	name, _ = url.QueryUnescape(name)
	var password string
	if u.User != nil {
		if p, ok := u.User.Password(); ok && p != "" {
			password = p
		} else {
			password = u.User.Username()
		}
	}
	server := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	if port == 0 {
		port = 443
	}
	q := u.Query()
	sni := q.Get("sni")
	if sni == "" {
		sni = q.Get("peer")
	}
	pinSHA256 := q.Get("pinSHA256")
	if pinSHA256 == "" {
		pinSHA256 = q.Get("pin-sha256")
	}
	insecure := q.Get("insecure")
	if insecure == "" {
		insecure = q.Get("allowInsecure")
	}
	mport := q.Get("mport")
	if mport == "" {
		mport = q.Get("ports")
	}
	obfs := q.Get("obfs")
	obfsPassword := q.Get("obfs-password")
	alpn := q.Get("alpn")

	cleanServer := strings.Trim(strings.TrimSpace(server), "[]")
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("name: %s\ntype: hysteria2\nserver: %s\nport: %d\npassword: %s\nudp: true\n",
		quoteYAML(name), quoteYAML(cleanServer), port, quoteYAML(password)))
	if sni != "" {
		sb.WriteString(fmt.Sprintf("sni: %s\n", quoteYAML(sni)))
	}
	if pinSHA256 != "" {
		sb.WriteString(fmt.Sprintf("fingerprint: %s\n", quoteYAML(pinSHA256)))
		sb.WriteString("skip-cert-verify: true\n")
	} else if insecure == "1" || strings.EqualFold(insecure, "true") {
		sb.WriteString("skip-cert-verify: true\n")
	}
	if mport != "" {
		sb.WriteString(fmt.Sprintf("ports: %s\n", quoteYAML(mport)))
	}
	if obfs != "" {
		sb.WriteString(fmt.Sprintf("obfs: %s\n", quoteYAML(obfs)))
		if obfsPassword != "" {
			sb.WriteString(fmt.Sprintf("obfs-password: %s\n", quoteYAML(obfsPassword)))
		}
	}
	if alpn != "" {
		sb.WriteString(fmt.Sprintf("alpn:\n  - %s\n", quoteYAML(alpn)))
	}

	return &MiaospeedNode{
		Name:     name,
		Protocol: "hysteria2",
		Server:   formatServerAddress(server, port),
		Port:     port,
		Payload:  sb.String(),
	}, nil
}

func parseTuicURI(u *url.URL) (*MiaospeedNode, error) {
	name := u.Fragment
	if name == "" {
		name = "TUIC-Node"
	}
	name, _ = url.QueryUnescape(name)
	uuid := ""
	password := ""
	if u.User != nil {
		uuid = u.User.Username()
		if p, ok := u.User.Password(); ok {
			password = p
		}
	}
	server := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	if port == 0 {
		port = 8443
	}
	q := u.Query()
	if password == "" {
		password = q.Get("password")
	}
	sni := q.Get("sni")
	if sni == "" {
		sni = q.Get("peer")
	}
	alpn := q.Get("alpn")
	insecure := q.Get("insecure")
	if insecure == "" {
		insecure = q.Get("allow_insecure")
	}
	if insecure == "" {
		insecure = q.Get("allowInsecure")
	}
	congestion := q.Get("congestion_control")
	if congestion == "" {
		congestion = q.Get("congestion")
	}
	if congestion == "" {
		congestion = "bbr"
	}
	udpRelay := q.Get("udp_relay_mode")
	if udpRelay == "" {
		udpRelay = q.Get("udp_relay")
	}
	if udpRelay == "" {
		udpRelay = "native"
	}

	cleanServer := strings.Trim(strings.TrimSpace(server), "[]")
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("name: %s\ntype: tuic\nserver: %s\nport: %d\nuuid: %s\npassword: %s\nudp: true\n",
		quoteYAML(name), quoteYAML(cleanServer), port, quoteYAML(uuid), quoteYAML(password)))
	if sni != "" {
		sb.WriteString(fmt.Sprintf("sni: %s\n", quoteYAML(sni)))
	}
	if alpn != "" {
		sb.WriteString(fmt.Sprintf("alpn:\n  - %s\n", quoteYAML(alpn)))
	} else {
		sb.WriteString("alpn:\n  - h3\n")
	}
	if insecure == "1" || strings.EqualFold(insecure, "true") {
		sb.WriteString("skip-cert-verify: true\n")
	}
	sb.WriteString(fmt.Sprintf("congestion-controller: %s\n", quoteYAML(congestion)))
	sb.WriteString(fmt.Sprintf("udp-relay-mode: %s\n", quoteYAML(udpRelay)))

	return &MiaospeedNode{
		Name:     name,
		Protocol: "tuic",
		Server:   formatServerAddress(server, port),
		Port:     port,
		Payload:  sb.String(),
	}, nil
}

func parseSSRURI(rawURI string) (*MiaospeedNode, error) {
	b64 := strings.TrimPrefix(rawURI, "ssr://")
	b64 = strings.TrimPrefix(b64, "SSR://")
	data, err := decodeBase64Safe(b64)
	if err != nil {
		return nil, fmt.Errorf("解码 SSR 配置失败: %w", err)
	}
	str := string(data)

	// 格式: host:port:protocol:method:obfs:base64(password)/?params
	var paramPart string
	if idx := strings.Index(str, "/?"); idx != -1 {
		paramPart = str[idx+2:]
		str = str[:idx]
	}
	parts := strings.Split(str, ":")
	if len(parts) < 6 {
		return nil, fmt.Errorf("无效的 SSR 配置格式: %s", str)
	}
	host := parts[0]
	port, _ := strconv.Atoi(parts[1])
	protocol := parts[2]
	method := parts[3]
	obfs := parts[4]
	password := parts[5]
	if passBytes, err := decodeBase64Safe(parts[5]); err == nil && len(passBytes) > 0 {
		password = string(passBytes)
	}

	name := "SSR-Node"
	obfsParam := ""
	protoParam := ""
	if paramPart != "" {
		if q, err := url.ParseQuery(paramPart); err == nil {
			if r := q.Get("remarks"); r != "" {
				if rDec, err := decodeBase64Safe(r); err == nil && len(rDec) > 0 {
					name = string(rDec)
				}
			}
			if op := q.Get("obfsparam"); op != "" {
				if opDec, err := decodeBase64Safe(op); err == nil && len(opDec) > 0 {
					obfsParam = string(opDec)
				}
			}
			if pp := q.Get("protoparam"); pp != "" {
				if ppDec, err := decodeBase64Safe(pp); err == nil && len(ppDec) > 0 {
					protoParam = string(ppDec)
				}
			}
		}
	}

	cleanHost := strings.Trim(strings.TrimSpace(host), "[]")
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("name: %s\ntype: ssr\nserver: %s\nport: %d\ncipher: %s\npassword: %s\nprotocol: %s\nobfs: %s\nudp: true\n",
		quoteYAML(name), quoteYAML(cleanHost), port, quoteYAML(method), quoteYAML(password), quoteYAML(protocol), quoteYAML(obfs)))
	if obfsParam != "" {
		sb.WriteString(fmt.Sprintf("obfs-param: %s\n", quoteYAML(obfsParam)))
	}
	if protoParam != "" {
		sb.WriteString(fmt.Sprintf("protocol-param: %s\n", quoteYAML(protoParam)))
	}

	return &MiaospeedNode{
		Name:     name,
		Protocol: "ssr",
		Server:   formatServerAddress(host, port),
		Port:     port,
		Payload:  sb.String(),
	}, nil
}

func parseHysteria1URI(u *url.URL) (*MiaospeedNode, error) {
	name := u.Fragment
	if name == "" {
		name = "Hysteria-Node"
	}
	name, _ = url.QueryUnescape(name)
	server := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	if port == 0 {
		port = 443
	}
	q := u.Query()
	auth := q.Get("auth")
	if auth == "" && u.User != nil {
		auth = u.User.Username()
	}
	protocol := q.Get("protocol")
	if protocol == "" {
		protocol = "udp"
	}
	up := q.Get("up")
	if up == "" {
		up = q.Get("upmbps")
	}
	down := q.Get("down")
	if down == "" {
		down = q.Get("downmbps")
	}
	alpn := q.Get("alpn")
	sni := q.Get("sni")
	if sni == "" {
		sni = q.Get("peer")
	}
	insecure := q.Get("insecure")
	if insecure == "" {
		insecure = q.Get("allow_insecure")
	}
	if insecure == "" {
		insecure = q.Get("allowInsecure")
	}

	cleanServer := strings.Trim(strings.TrimSpace(server), "[]")
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("name: %s\ntype: hysteria\nserver: %s\nport: %d\nprotocol: %s\n",
		quoteYAML(name), quoteYAML(cleanServer), port, quoteYAML(protocol)))
	if auth != "" {
		sb.WriteString(fmt.Sprintf("auth-str: %s\n", quoteYAML(auth)))
	}
	if up != "" {
		sb.WriteString(fmt.Sprintf("up: %s\n", quoteYAML(up)))
	}
	if down != "" {
		sb.WriteString(fmt.Sprintf("down: %s\n", quoteYAML(down)))
	}
	if sni != "" {
		sb.WriteString(fmt.Sprintf("sni: %s\n", quoteYAML(sni)))
	}
	if alpn != "" {
		sb.WriteString(fmt.Sprintf("alpn:\n  - %s\n", quoteYAML(alpn)))
	}
	if insecure == "1" || strings.EqualFold(insecure, "true") {
		sb.WriteString("skip-cert-verify: true\n")
	}

	return &MiaospeedNode{
		Name:     name,
		Protocol: "hysteria",
		Server:   formatServerAddress(server, port),
		Port:     port,
		Payload:  sb.String(),
	}, nil
}

func parseSocks5URI(u *url.URL) (*MiaospeedNode, error) {
	name := u.Fragment
	if name == "" {
		name = "Socks5-Node"
	}
	name, _ = url.QueryUnescape(name)
	server := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	if port == 0 {
		port = 1080
	}
	var username, password string
	if u.User != nil {
		username = u.User.Username()
		password, _ = u.User.Password()
	}

	cleanServer := strings.Trim(strings.TrimSpace(server), "[]")
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("name: %s\ntype: socks5\nserver: %s\nport: %d\nudp: true\n",
		quoteYAML(name), quoteYAML(cleanServer), port))
	if username != "" {
		sb.WriteString(fmt.Sprintf("username: %s\n", quoteYAML(username)))
	}
	if password != "" {
		sb.WriteString(fmt.Sprintf("password: %s\n", quoteYAML(password)))
	}

	return &MiaospeedNode{
		Name:     name,
		Protocol: "socks5",
		Server:   formatServerAddress(server, port),
		Port:     port,
		Payload:  sb.String(),
	}, nil
}

func parseSnellURI(u *url.URL) (*MiaospeedNode, error) {
	name := u.Fragment
	if name == "" {
		name = "Snell-Node"
	}
	name, _ = url.QueryUnescape(name)
	server := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	if port == 0 {
		port = 443
	}
	q := u.Query()
	psk := q.Get("psk")
	if psk == "" && u.User != nil {
		psk = u.User.Username()
	}
	version := q.Get("version")
	if version == "" {
		version = "4"
	}
	// snell 的 version 在 Clash 配置里是整数；从 URI 取到的值先做数字校验，
	// 非法（如带引号/换行/非数字）时丢弃整个节点，避免把注入内容写进 YAML，
	// 也避免 quoteYAML 把合法版本号写成字符串 "4"。
	versionNum, err := strconv.Atoi(version)
	if err != nil || versionNum < 1 {
		return nil, fmt.Errorf("snell version 非法：%q（只允许正整数）", version)
	}
	obfs := q.Get("obfs")
	obfsHost := q.Get("host")

	cleanServer := strings.Trim(strings.TrimSpace(server), "[]")
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("name: %s\ntype: snell\nserver: %s\nport: %d\npsk: %s\nversion: %d\nudp: true\n",
		quoteYAML(name), quoteYAML(cleanServer), port, quoteYAML(psk), versionNum))
	if obfs != "" || obfsHost != "" {
		sb.WriteString("obfs-opts:\n")
		if obfs != "" {
			sb.WriteString(fmt.Sprintf("  mode: %s\n", quoteYAML(obfs)))
		}
		if obfsHost != "" {
			sb.WriteString(fmt.Sprintf("  host: %s\n", quoteYAML(obfsHost)))
		}
	}

	return &MiaospeedNode{
		Name:     name,
		Protocol: "snell",
		Server:   formatServerAddress(server, port),
		Port:     port,
		Payload:  sb.String(),
	}, nil
}

func parseAnyTLSURI(u *url.URL) (*MiaospeedNode, error) {
	name := u.Fragment
	if name == "" {
		name = "AnyTLS-Node"
	}
	name, _ = url.QueryUnescape(name)

	password := ""
	if u.User != nil {
		if p, ok := u.User.Password(); ok {
			password = p
		} else {
			password = u.User.Username()
		}
		password, _ = url.QueryUnescape(password)
	}

	server := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	if port == 0 {
		port = 443
	}

	q := u.Query()
	sni := q.Get("sni")
	if sni == "" {
		sni = q.Get("peer")
	}
	fp := q.Get("fp")
	if fp == "" {
		fp = q.Get("client-fingerprint")
	}
	insecure := q.Get("insecure")
	if insecure == "" {
		insecure = q.Get("allowInsecure")
	}
	if insecure == "" {
		insecure = q.Get("allow_insecure")
	}
	alpn := q.Get("alpn")

	cleanServer := strings.Trim(strings.TrimSpace(server), "[]")
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("name: %s\ntype: anytls\nserver: %s\nport: %d\npassword: %s\nudp: true\n",
		quoteYAML(name), quoteYAML(cleanServer), port, quoteYAML(password)))
	if sni != "" {
		sb.WriteString(fmt.Sprintf("sni: %s\n", quoteYAML(sni)))
	}
	if fp != "" {
		sb.WriteString(fmt.Sprintf("client-fingerprint: %s\n", quoteYAML(fp)))
	}
	if insecure == "1" || strings.EqualFold(insecure, "true") {
		sb.WriteString("skip-cert-verify: true\n")
	}
	if alpn != "" {
		sb.WriteString("alpn:\n")
		for _, a := range strings.Split(alpn, ",") {
			a = strings.TrimSpace(a)
			if a != "" {
				sb.WriteString(fmt.Sprintf("  - %s\n", quoteYAML(a)))
			}
		}
	}

	srvAddr := formatServerAddress(server, port)

	return &MiaospeedNode{
		Name:     name,
		Protocol: "anytls",
		Server:   srvAddr,
		Port:     port,
		Payload:  sb.String(),
	}, nil
}

// formatServerAddress 将服务器地址与端口安全拼装为标准 host:port 字符串；对于 IPv6 字面量地址自动添加中括号。
func formatServerAddress(server string, port int) string {
	cleanServer := strings.Trim(strings.TrimSpace(server), "[]")
	if port > 0 {
		return net.JoinHostPort(cleanServer, strconv.Itoa(port))
	}
	return cleanServer
}

// formatServerPortString 将字符串类型的端口与服务器地址安全拼装为 host:port 字符串；
// 自动规整 IPv6 字面量格式并补充端口，避免 IPv6 冒号导致端口丢失。
func formatServerPortString(server, portStr string) string {
	cleanServer := strings.Trim(strings.TrimSpace(server), "[]")
	portStr = strings.TrimSpace(portStr)
	if portStr != "" {
		p, err := strconv.Atoi(portStr)
		if err == nil && p > 0 {
			return net.JoinHostPort(cleanServer, strconv.Itoa(p))
		}
	}
	if host, p, err := net.SplitHostPort(cleanServer); err == nil {
		return net.JoinHostPort(strings.Trim(host, "[]"), p)
	}
	return cleanServer
}

// quoteYAML 把字符串包装成 YAML 双引号标量并转义特殊字符：
// 反斜杠/双引号/CR/LF/TAB，以及其余 C0 控制字符与 DEL（\x00-\x1f、\x7f，
// 用 \xNN 形式）。不转义控制字符会被 YAML 解析器当作非法字符或注入换行。
func quoteYAML(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\r':
			b.WriteString(`\r`)
		case '\n':
			b.WriteString(`\n`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if c < 0x20 || c == 0x7f {
				fmt.Fprintf(&b, `\x%02x`, c)
			} else {
				b.WriteByte(c)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

func sanitizeYAMLToken(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == '\t' || r < 0x20 {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
}

func getString(m map[string]any, k string) string {
	if v, ok := m[k]; ok {
		if s, ok := v.(string); ok {
			return sanitizeYAMLToken(s)
		}
	}
	return ""
}

func getInt(m map[string]any, k string) int {
	if v, ok := m[k]; ok {
		switch n := v.(type) {
		case float64:
			return int(n)
		case int:
			return n
		case string:
			p, _ := strconv.Atoi(n)
			return p
		}
	}
	return 0
}

// maxMiaospeedNodes 是单次测速任务的节点数上限。
// 服务端目前没有节点数上限，agent 侧按 3 小时任务预算反推上限，避免超大订阅
// 把内存、任务预算与结果体积同时撑爆；超过时截断而不是整单失败，保持与
// 服务端“有多少测多少”的语义一致，并在日志与报告总节点数中说明。
//
// 必须保证 CalcMiaospeedTimeout(maxMiaospeedNodes) + miaospeedTimeoutReserve
// <= model.JobMiaospeedMaxTimeout，否则订阅下载、启动、结果上传等环节会挤占
// 测速预算，任务可能在动态预算还没用完时被模型层的 3 小时上限提前截断。
var maxMiaospeedNodes = int((model.JobMiaospeedMaxTimeout - miaospeedBaseTimeout - miaospeedTimeoutReserve) / miaospeedPerNodeTimeout)

// selectJobNodes 根据任务请求选取测速节点；默认全量测速（受 maxMiaospeedNodes 限制），
// 明确指定 Count 时截取前 Count 个节点。
func selectJobNodes(allNodes []MiaospeedNode, count int) []MiaospeedNode {
	limit := len(allNodes)
	if limit > maxMiaospeedNodes {
		limit = maxMiaospeedNodes
	}
	if count > 0 && count < limit {
		limit = count
	}
	if limit == len(allNodes) {
		return allNodes
	}
	return allNodes[:limit]
}

// formatClashPayloadToURI 将 Clash YAML 节点 payload 还原为标准代理 URI。
func formatClashPayloadToURI(payload, name, pType, server, port string) string {
	if name == "" || server == "" || port == "" {
		return ""
	}
	f := make(map[string]string)
	f["name"] = name
	f["type"] = pType
	f["server"] = server
	f["port"] = port

	lines := strings.Split(payload, "\n")
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if idx := strings.Index(l, ":"); idx != -1 {
			k := strings.ToLower(strings.TrimSpace(l[:idx]))
			v := strings.Trim(strings.TrimSpace(l[idx+1:]), "\"'")
			if k != "" && v != "" {
				f[k] = v
			}
		}
	}

	for _, k := range []string{"uuid", "password", "auth", "cipher", "sni", "servername", "tls", "network", "flow", "alterid", "skip-cert-verify"} {
		if _, ok := f[k]; !ok {
			if v := extractField(payload, k); v != "" {
				f[k] = v
			}
		}
	}

	frag := url.QueryEscape(name)
	switch strings.ToLower(pType) {
	case "ss", "shadowsocks":
		cipher := f["cipher"]
		pwd := f["password"]
		if cipher == "" || pwd == "" {
			return ""
		}
		userInfo := base64.URLEncoding.EncodeToString([]byte(cipher + ":" + pwd))
		return fmt.Sprintf("ss://%s@%s:%s#%s", userInfo, server, port, frag)

	case "trojan":
		pwd := f["password"]
		if pwd == "" {
			return ""
		}
		sni := f["sni"]
		if sni == "" {
			sni = f["servername"]
		}
		q := url.Values{}
		if sni != "" {
			q.Set("sni", sni)
		}
		var qStr string
		if len(q) > 0 {
			qStr = "?" + q.Encode()
		}
		return fmt.Sprintf("trojan://%s@%s:%s%s#%s", url.QueryEscape(pwd), server, port, qStr, frag)

	case "vless":
		uuid := f["uuid"]
		if uuid == "" {
			return ""
		}
		q := url.Values{}
		q.Set("encryption", "none")
		if net := f["network"]; net != "" {
			q.Set("type", net)
		}
		sni := f["sni"]
		if sni == "" {
			sni = f["servername"]
		}
		if sni != "" {
			q.Set("sni", sni)
		}
		if tls := strings.ToLower(f["tls"]); tls == "true" || tls == "1" || sni != "" {
			q.Set("security", "tls")
		}
		if flow := f["flow"]; flow != "" {
			q.Set("flow", flow)
		}
		return fmt.Sprintf("vless://%s@%s:%s?%s#%s", uuid, server, port, q.Encode(), frag)

	case "hysteria2", "hy2":
		pwd := f["password"]
		if pwd == "" {
			pwd = f["auth"]
		}
		if pwd == "" {
			return ""
		}
		sni := f["sni"]
		if sni == "" {
			sni = f["servername"]
		}
		q := url.Values{}
		if sni != "" {
			q.Set("sni", sni)
		}
		if ins := strings.ToLower(f["skip-cert-verify"]); ins == "true" || ins == "1" {
			q.Set("insecure", "1")
		}
		var qStr string
		if len(q) > 0 {
			qStr = "?" + q.Encode()
		}
		return fmt.Sprintf("hysteria2://%s@%s:%s%s#%s", url.QueryEscape(pwd), server, port, qStr, frag)

	case "vmess":
		uuid := f["uuid"]
		if uuid == "" {
			return ""
		}
		pNum, _ := strconv.Atoi(port)
		aid := 0
		if aStr := f["alterid"]; aStr != "" {
			aid, _ = strconv.Atoi(aStr)
		}
		netType := f["network"]
		if netType == "" {
			netType = "tcp"
		}
		tls := ""
		if strings.ToLower(f["tls"]) == "true" || strings.ToLower(f["tls"]) == "1" {
			tls = "tls"
		}
		sni := f["sni"]
		if sni == "" {
			sni = f["servername"]
		}

		vmJSON := map[string]any{
			"v":    "2",
			"ps":   name,
			"add":  server,
			"port": pNum,
			"id":   uuid,
			"aid":  aid,
			"net":  netType,
			"type": "none",
			"host": sni,
			"tls":  tls,
		}
		jBytes, err := json.Marshal(vmJSON)
		if err != nil {
			return ""
		}
		return "vmess://" + base64.StdEncoding.EncodeToString(jBytes)

	case "tuic":
		uuid := f["uuid"]
		pwd := f["password"]
		if uuid == "" && pwd == "" {
			return ""
		}
		auth := uuid
		if auth == "" {
			auth = pwd
		}
		return fmt.Sprintf("tuic://%s@%s:%s#%s", auth, server, port, frag)

	default:
		return ""
	}
}
