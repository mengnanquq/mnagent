package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// MiaospeedNode 描述解析出的代理节点。
type MiaospeedNode struct {
	Name     string
	Protocol string
	Server   string
	Port     int
	Payload  string // YAML 格式节点配置
}

// parseProxyTarget 将任务 Target（单节点链接、订阅 URL 或代理配置文件内容）解析为节点列表。
func parseProxyTarget(ctx context.Context, target string, allowPrivate ...bool) ([]MiaospeedNode, error) {
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

	// 5. 多行代理 URI 列表扫描
	var uriNodes []MiaospeedNode
	for _, line := range trimmedLines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		if n, err := parseProxyURI(line); err == nil && n != nil {
			uriNodes = append(uriNodes, *n)
		}
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
		Proxy: http.ProxyFromEnvironment,
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
					if isBlockedProbeIP(ip) {
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

		body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20)) // 限制 8MB
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
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

// parseClashYAMLProxies 从原生 Clash/Meta 配置文件中提取 proxies 节点。
func parseClashYAMLProxies(content string) []MiaospeedNode {
	content = strings.TrimPrefix(content, "\xef\xbb\xbf")
	content = strings.ReplaceAll(content, "\r\n", "\n")
	lines := strings.Split(content, "\n")
	var nodes []MiaospeedNode
	inProxies := false
	baseIndent := -1

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
				srv := formatServerPortString(currentServer, currentPort)
				nodes = append(nodes, MiaospeedNode{
					Name:     currentName,
					Protocol: currentType,
					Server:   srv,
					Payload:  payload,
				})
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

			// 单行格式: - {name: ..., server: ..., ...}
			if strings.HasPrefix(trimmed, "- {") || strings.HasPrefix(trimmed, "-{") {
				flushItem()
				baseIndent = indent
				rawItem := strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
				if closeIdx := strings.LastIndex(rawItem, "}"); closeIdx != -1 {
					rawItem = rawItem[:closeIdx+1]
				}
				name := extractField(rawItem, "name")
				pType := extractField(rawItem, "type")
				server := extractField(rawItem, "server")
				port := extractField(rawItem, "port")
				if name != "" {
					srv := formatServerPortString(server, port)
					nodes = append(nodes, MiaospeedNode{
						Name:     name,
						Protocol: pType,
						Server:   srv,
						Payload:  rawItem,
					})
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
	return nodes
}

func parseLineKeyValue(line string, name, pType, server, port *string) {
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

// extractField 从单行 YAML 项（如 {name: '...', type: hysteria2}）中安全提取指定键对应的值。
func extractField(raw, key string) string {
	key = strings.TrimSuffix(strings.TrimSpace(key), ":")
	if key == "" || len(raw) == 0 {
		return ""
	}

	rawLen := len(raw)
	start := 0
	for {
		idx := strings.Index(raw[start:], key)
		if idx == -1 {
			return ""
		}
		actualIdx := start + idx

		// 检查 key 前置边界：必须是开头、空白、'{' 或 ','
		validPrefix := false
		if actualIdx == 0 {
			validPrefix = true
		} else {
			prev := raw[actualIdx-1]
			if prev == '{' || prev == ',' || unicode.IsSpace(rune(prev)) {
				validPrefix = true
			}
		}

		// 检查 key 后置边界：必须紧跟可选空白与冒号 ':'
		valStart := -1
		if validPrefix {
			afterKey := actualIdx + len(key)
			k := afterKey
			for k < rawLen && unicode.IsSpace(rune(raw[k])) {
				k++
			}
			if k < rawLen && raw[k] == ':' {
				k++ // 跳过 ':'
				for k < rawLen && unicode.IsSpace(rune(raw[k])) {
					k++
				}
				valStart = k
			}
		}

		if valStart != -1 {
			if valStart >= rawLen {
				return ""
			}

			firstChar := raw[valStart]
			// 1. 引号包裹情况
			if firstChar == '\'' || firstChar == '"' {
				quote := firstChar
				escaped := false
				for i := valStart + 1; i < rawLen; i++ {
					c := raw[i]
					if escaped {
						escaped = false
						continue
					}
					if c == '\\' {
						escaped = true
						continue
					}
					if c == quote {
						// 支持单引号双写转义 ''
						if quote == '\'' && i+1 < rawLen && raw[i+1] == '\'' {
							i++
							continue
						}
						return raw[valStart+1 : i]
					}
				}
				return strings.TrimSpace(raw[valStart+1:])
			}

			// 2. 嵌套花括号情况
			if firstChar == '{' {
				braceDepth := 0
				for i := valStart; i < rawLen; i++ {
					if raw[i] == '{' {
						braceDepth++
					} else if raw[i] == '}' {
						braceDepth--
						if braceDepth == 0 {
							return strings.TrimSpace(raw[valStart : i+1])
						}
					}
				}
			}

			// 3. 普通标量值：截止到下一个 ',' 或最外层 '}'
			end := valStart
			for end < rawLen && raw[end] != ',' && raw[end] != '}' {
				end++
			}
			val := strings.TrimSpace(raw[valStart:end])
			return strings.Trim(val, "\"'")
		}

		start = actualIdx + len(key)
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

	Obfs *struct {
		Type     string `json:"type"`
		Password string `json:"password"`
	} `json:"obfs"`
}

// parseSingBoxJSON 从 Sing-box JSON 配置文件（或节点数组/单节点 JSON）中提取代理节点。
func parseSingBoxJSON(content string) []MiaospeedNode {
	content = strings.TrimSpace(content)
	var outbounds []singBoxOutbound

	if strings.HasPrefix(content, "[") {
		_ = json.Unmarshal([]byte(content), &outbounds)
	} else if strings.HasPrefix(content, "{") {
		var wrapper struct {
			Outbounds []singBoxOutbound `json:"outbounds"`
			Proxies   []singBoxOutbound `json:"proxies"`
		}
		if err := json.Unmarshal([]byte(content), &wrapper); err == nil {
			if len(wrapper.Outbounds) > 0 {
				outbounds = wrapper.Outbounds
			} else if len(wrapper.Proxies) > 0 {
				outbounds = wrapper.Proxies
			}
		}
		if len(outbounds) == 0 {
			var single singBoxOutbound
			if err := json.Unmarshal([]byte(content), &single); err == nil && single.Type != "" && single.Server != "" {
				outbounds = []singBoxOutbound{single}
			}
		}
	}

	var nodes []MiaospeedNode
	for _, ob := range outbounds {
		if n := convertSingBoxOutbound(ob); n != nil {
			nodes = append(nodes, *n)
		}
	}
	return nodes
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
			quoteYAML(name), quoteYAML(cleanServer), port, cipher, quoteYAML(ob.Password)))
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
			quoteYAML(name), quoteYAML(cleanServer), port, ob.UUID, ob.AlterID, cipher, netType))
		writeSingBoxTLSAndTransport(&sb, ob, "servername")
	case "vless":
		netType := "tcp"
		if ob.Transport != nil && ob.Transport.Type != "" {
			netType = ob.Transport.Type
		}
		sb.WriteString(fmt.Sprintf("name: %s\ntype: vless\nserver: %s\nport: %d\nuuid: %s\nudp: true\nnetwork: %s\n",
			quoteYAML(name), quoteYAML(cleanServer), port, ob.UUID, netType))
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
			sb.WriteString(fmt.Sprintf("network: %s\n", netType))
		}
		writeSingBoxTLSAndTransport(&sb, ob, "sni")
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

	switch strings.ToLower(u.Scheme) {
	case "anytls":
		return parseAnyTLSURI(u)
	case "ss":
		return parseShadowsocksURI(rawURI, u)
	case "ssr":
		return parseSSRURI(rawURI)
	case "vmess":
		return parseVmessURI(rawURI)
	case "trojan":
		return parseTrojanURI(u)
	case "vless":
		return parseVlessURI(u)
	case "hysteria2", "hy2":
		return parseHysteria2URI(u)
	case "hysteria", "hy":
		return parseHysteria1URI(u)
	case "tuic":
		return parseTuicURI(u)
	case "socks5", "socks":
		return parseSocks5URI(u)
	case "snell":
		return parseSnellURI(u)
	default:
		return nil, fmt.Errorf("不支持的代理协议：%s", u.Scheme)
	}
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
		quoteYAML(name), quoteYAML(cleanHost), port, method, quoteYAML(password)))
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
		quoteYAML(name), quoteYAML(cleanServer), port, uuid, alterID, cipher, netType))
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
		quoteYAML(name), quoteYAML(cleanServer), port, uuid, netType))
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
		quoteYAML(name), quoteYAML(cleanHost), port, method, quoteYAML(password), protocol, obfs))
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
		quoteYAML(name), quoteYAML(cleanServer), port, protocol))
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
	obfs := q.Get("obfs")
	obfsHost := q.Get("host")

	cleanServer := strings.Trim(strings.TrimSpace(server), "[]")
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("name: %s\ntype: snell\nserver: %s\nport: %d\npsk: %s\nversion: %s\nudp: true\n",
		quoteYAML(name), quoteYAML(cleanServer), port, quoteYAML(psk), version))
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

func quoteYAML(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\t", `\t`)
	return `"` + s + `"`
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

// selectJobNodes 根据任务请求选取测速节点，默认无上限全量测速；仅在明确指定 Count 时截取前 Count 个节点。
func selectJobNodes(allNodes []MiaospeedNode, count int) []MiaospeedNode {
	if count > 0 && count < len(allNodes) {
		return allNodes[:count]
	}
	return allNodes
}
