package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"

	"golang.org/x/net/websocket"
)

// 常量定义：MiaoSpeed 任务类型与官方通用构建凭证。
const (
	kindMiaospeed = "miaospeed"
	kindSpeed     = "speed"

	// defaultBuildToken 是 AirportR/miaospeed 官方发布的默认嵌入凭证，
	// 与主流客户端（FullTclash、miaolib、Koipy 等）保持完全一致。
	defaultBuildToken = "MIAOKO4|580JxAo049R|GEnERAl|1X571R930|T0kEN"

	defaultSTUNServer = "udp://stunserver2025.stunprotocol.org:3478"
	defaultSpeedFile  = "https://speed.cloudflare.com/__down?bytes=50000000"
	defaultPingURL    = "https://cp.cloudflare.com/generate_204"
)

// 7 种测试类型与全量模式常量。
const (
	ModeConnectivity = "connectivity" // 代理连通性测试
	ModeTopology     = "topology"     // 拓扑测试
	ModeMultiSpeed   = "multithread"  // 多线程测速 (下行)
	ModeSingleSpeed  = "singlethread" // 单线程测速 (下行)
	ModeFull         = "full"         // 全量测试
	ModeLatency      = "latency"      // 延迟测试
	ModeUDP          = "udp"          // UDP 类型测试
)

// MiaoSpeed 官方测试项 Matrix 常量。
const (
	matrixRTTPing       = "TEST_PING_RTT"
	matrixHTTPPing      = "TEST_PING_CONN"
	matrixPacketLoss    = "TEST_PING_PACKET_LOSS"
	matrixMaxRTTPing    = "TEST_PING_MAX_RTT"
	matrixSDRTTPing     = "TEST_PING_SD_RTT"
	matrixHTTPCode      = "TEST_HTTP_CODE"
	matrixInboundGeoIP  = "GEOIP_INBOUND"
	matrixOutboundGeoIP = "GEOIP_OUTBOUND"
	matrixHijack        = "TEST_HIJACK_DETECTION"
	matrixUDPType       = "UDP_TYPE"
	matrixAverageSpeed  = "SPEED_AVERAGE"
	matrixMaxSpeed      = "SPEED_MAX"
)

// MiaospeedNode 描述解析出的代理节点。
type MiaospeedNode struct {
	Name     string
	Protocol string
	Server   string
	Port     int
	Payload  string // YAML 格式节点配置
}

// MiaospeedReport 包含测速任务的结构化结果。
type MiaospeedReport struct {
	TotalNodes      int               `json:"total_nodes,omitempty"`
	TestMode        string            `json:"test_mode,omitempty"`
	NodeName        string            `json:"node_name"`
	Protocol        string            `json:"protocol,omitempty"`
	Server          string            `json:"server,omitempty"`
	HTTPCode        int               `json:"http_code,omitempty"`
	PingRTTMs       float64           `json:"ping_rtt_ms,omitempty"`
	PingConnMs      float64           `json:"ping_conn_ms,omitempty"`
	MaxRTTMs        float64           `json:"max_rtt_ms,omitempty"`
	PacketLoss      float64           `json:"packet_loss_pct,omitempty"`
	UDPType         string            `json:"udp_type,omitempty"`
	DownloadThreads int               `json:"download_threads,omitempty"`
	AvgSpeedBps     float64           `json:"avg_speed_bps,omitempty"` // 字节/秒
	MaxSpeedBps     float64           `json:"max_speed_bps,omitempty"` // 字节/秒
	InboundGeo      string            `json:"inbound_geo,omitempty"`
	OutboundIP      string            `json:"outbound_ip,omitempty"`
	OutboundGeo     string            `json:"outbound_geo,omitempty"`
	Hijack          string            `json:"hijack,omitempty"`
	MediaUnlock     map[string]string `json:"media_unlock,omitempty"`
	SubReports      []MiaospeedReport `json:"sub_reports,omitempty"`
	DurationMs      int64             `json:"duration_ms"`
	RawResults      []slaveEntrySlot  `json:"raw_results,omitempty"`
}

// Format 格式化排版文本，供 Telegram 机器人展示。
func (r MiaospeedReport) Format() string {
	var b strings.Builder
	title := "⚡ MiaoSpeed 测速报告"
	if r.TestMode != "" {
		title += " · " + r.TestMode
	}
	b.WriteString(title + "\n\n")

	if r.NodeName != "" {
		proto := r.Protocol
		if proto == "" {
			proto = "proxy"
		}
		b.WriteString(fmt.Sprintf("节点: %s (%s)\n", r.NodeName, proto))
	}
	if r.Server != "" {
		b.WriteString(fmt.Sprintf("目标: %s\n", r.Server))
	}

	if r.HTTPCode > 0 {
		b.WriteString(fmt.Sprintf("连通性: HTTP 状态码 %d\n", r.HTTPCode))
	}

	isOffline := r.PacketLoss >= 100 && r.PingRTTMs == 0 && r.PingConnMs == 0
	if isOffline {
		b.WriteString("延迟: 节点不可达 (100% 丢包)\n")
	} else if r.PingRTTMs > 0 || r.PingConnMs > 0 || r.PacketLoss > 0 {
		var parts []string
		if r.PingRTTMs > 0 {
			parts = append(parts, fmt.Sprintf("RTT %.1f ms", r.PingRTTMs))
		}
		if r.PingConnMs > 0 {
			parts = append(parts, fmt.Sprintf("HTTP %.1f ms", r.PingConnMs))
		}
		if r.MaxRTTMs > 0 {
			parts = append(parts, fmt.Sprintf("峰值 %.1f ms", r.MaxRTTMs))
		}
		parts = append(parts, fmt.Sprintf("丢包 %.1f%%", r.PacketLoss))
		b.WriteString("延迟: " + strings.Join(parts, " | ") + "\n")
	}

	if r.UDPType != "" {
		b.WriteString(fmt.Sprintf("UDP NAT 类型: %s\n", describeNATType(r.UDPType)))
	}

	if r.AvgSpeedBps > 0 || r.MaxSpeedBps > 0 {
		thDesc := "多线程"
		if r.DownloadThreads == 1 {
			thDesc = "单线程"
		} else if r.DownloadThreads > 1 {
			thDesc = fmt.Sprintf("%d 线程", r.DownloadThreads)
		}
		b.WriteString(fmt.Sprintf("下行 (%s): 平均 %s | 峰值 %s\n",
			thDesc, formatBytesPerSec(r.AvgSpeedBps), formatBytesPerSec(r.MaxSpeedBps)))
	}

	if r.InboundGeo != "" || r.OutboundGeo != "" || r.Hijack != "" {
		b.WriteString("链路拓扑:\n")
		if r.InboundGeo != "" {
			b.WriteString(fmt.Sprintf("  - 入站: %s\n", r.InboundGeo))
		}
		if r.OutboundGeo != "" {
			b.WriteString(fmt.Sprintf("  - 出站: %s\n", r.OutboundGeo))
		}
		if r.Hijack != "" {
			b.WriteString(fmt.Sprintf("  - 劫持检测: %s\n", r.Hijack))
		}
	}

	if len(r.MediaUnlock) > 0 {
		b.WriteString("流媒体解锁:\n")
		for _, name := range []string{"YouTube", "Netflix", "Disney+", "OpenAI", "Claude", "Spotify", "TikTok", "Bilibili", "维基百科"} {
			if status, ok := r.MediaUnlock[name]; ok && status != "" {
				b.WriteString(fmt.Sprintf("  - %s: %s\n", name, status))
			}
		}
	}

	if r.DurationMs > 0 {
		b.WriteString(fmt.Sprintf("耗时: %.2f 秒\n", float64(r.DurationMs)/1000.0))
	}
	return strings.TrimSpace(b.String())
}

func describeNATType(t string) string {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "fullcone":
		return "FullCone (完全锥形 NAT / 开放)"
	case "restrictedcone":
		return "RestrictedCone (受限锥形 NAT)"
	case "portrestrictedcone":
		return "PortRestrictedCone (端口受限锥形 NAT)"
	case "symmetric":
		return "Symmetric (对称型 NAT)"
	case "blocked":
		return "Blocked (UDP 被阻断)"
	default:
		return t
	}
}

func formatBytesPerSec(bps float64) string {
	switch {
	case bps >= 1024*1024*1024:
		return fmt.Sprintf("%.2f GB/s", bps/(1024*1024*1024))
	case bps >= 1024*1024:
		return fmt.Sprintf("%.2f MB/s", bps/(1024*1024))
	case bps >= 1024:
		return fmt.Sprintf("%.2f KB/s", bps/1024)
	default:
		return fmt.Sprintf("%.0f B/s", bps)
	}
}

// --- MiaoSpeed API 请求与协议结构定义 ---

type slaveRequestMatrixEntry struct {
	Type   string
	Params string
}

type slaveRequestOptions struct {
	Filter   string
	Matrices []slaveRequestMatrixEntry
}

type slaveRequestBasics struct {
	ID        string
	Slave     string
	SlaveName string
	Invoker   string
	Version   string
}

type slaveRequestNode struct {
	Name    string
	Payload string
}

type slaveScript struct {
	ID            string
	Type          string
	Content       string
	TimeoutMillis uint64
}

type slaveRequestConfigs struct {
	STUNURL           string
	DownloadURL       string
	DownloadDuration  int64
	DownloadThreading uint

	PingAverageOver uint16
	PingAddress     string

	TaskRetry  uint
	DNSServers []string

	TaskTimeout uint
	Scripts     []slaveScript
}

type slaveRequest struct {
	Basics         slaveRequestBasics
	Options        slaveRequestOptions
	Configs        slaveRequestConfigs
	Vendor         string
	Nodes          []slaveRequestNode
	RandomSequence string
	Challenge      string
}

type matrixResponse struct {
	Type    string `json:"Type"`
	Payload string `json:"Payload"`
}

type slaveEntrySlot struct {
	Grouping       string           `json:"Grouping"`
	InvokeDuration int64            `json:"InvokeDuration"`
	Matrices       []matrixResponse `json:"Matrices"`
}

type slaveTask struct {
	Results []slaveEntrySlot `json:"Results"`
}

type slaveProgress struct {
	Index  int             `json:"Index"`
	Record *slaveEntrySlot `json:"Record"`
}

type slaveResponse struct {
	ID       string         `json:"ID"`
	Error    string         `json:"Error"`
	Result   *slaveTask     `json:"Result"`
	Progress *slaveProgress `json:"Progress"`
}

// signMiaoSpeedRequest 计算 MiaoSpeed 请求的 Challenge 签名。
// 算法与 AirportR/miaospeed 完全一致：
// 服务端反序列化后以 Clone() 副本计算签名；Clone() 会将 Challenge 置空且未复制 Vendor（置空）。
// 对深拷贝副本进行 json.Marshal 后计算 SHA512(request + token + buildToken)。
func signMiaoSpeedRequest(token, buildToken string, req slaveRequest) (string, error) {
	awaitSigned := req
	awaitSigned.Challenge = ""
	awaitSigned.Vendor = "" // miaospeed Clone() 漏拷 Vendor，服务端校验时此字段为空

	raw, err := json.Marshal(&awaitSigned)
	if err != nil {
		return "", err
	}
	reqJSON := strings.TrimSpace(string(raw))

	buildTokens := append([]string{token}, strings.Split(strings.TrimSpace(buildToken), "|")...)

	hasher := sha512.New()
	hasher.Write([]byte(reqJSON))

	for _, t := range buildTokens {
		if t == "" {
			t = "SOME_TOKEN"
		}
		hasher.Write(hasher.Sum([]byte(t)))
	}

	return base64.URLEncoding.EncodeToString(hasher.Sum(nil)), nil
}

// parseProxyTarget 将任务 Target（单节点链接、订阅 URL 或代理配置文件内容）解析为节点列表。
func parseProxyTarget(ctx context.Context, target string) ([]MiaospeedNode, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, errors.New("目标地址不能为空")
	}

	// 1. 如果是以 http:// 或 https:// 开头的订阅地址，拉取并解析。
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return fetchAndParseSubscription(ctx, target)
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
		srv := server
		if port != "" && !strings.Contains(server, ":") {
			srv += ":" + port
		}
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

// fetchAndParseSubscription 拉取订阅并提取节点，支持 Base64 URI 列表、Clash YAML 与 Sing-box JSON。
func fetchAndParseSubscription(ctx context.Context, subURL string) ([]MiaospeedNode, error) {
	// 依次尝试主流订阅客户端 User-Agent，优先获取原生 Clash-Meta 配置（miaospeed 基于 Clash-Meta 核心），避免手动逆向协议丢失 TLS/证书指纹与高级参数
	userAgents := []string{"ClashMeta", "clash.meta", "Clash.Meta; mihomo", "mihomo", "v2rayng", "clash"}
	client := &http.Client{Timeout: 15 * time.Second}

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
		return nil, lastErr
	}
	return nil, errors.New("订阅中未找到有效代理节点")
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
				srv := currentServer
				if currentPort != "" && !strings.Contains(currentServer, ":") {
					srv = fmt.Sprintf("%s:%s", currentServer, currentPort)
				}
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
					srv := server
					if port != "" && !strings.Contains(server, ":") {
						srv += ":" + port
					}
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
			quoteYAML(name), server, port, cipher, quoteYAML(ob.Password)))
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
			quoteYAML(name), server, port, ob.UUID, ob.AlterID, cipher, netType))
		writeSingBoxTLSAndTransport(&sb, ob, "servername")
	case "vless":
		netType := "tcp"
		if ob.Transport != nil && ob.Transport.Type != "" {
			netType = ob.Transport.Type
		}
		sb.WriteString(fmt.Sprintf("name: %s\ntype: vless\nserver: %s\nport: %d\nuuid: %s\nudp: true\nnetwork: %s\n",
			quoteYAML(name), server, port, ob.UUID, netType))
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
			quoteYAML(name), server, port, quoteYAML(ob.Password)))
		if netType != "tcp" {
			sb.WriteString(fmt.Sprintf("network: %s\n", netType))
		}
		writeSingBoxTLSAndTransport(&sb, ob, "sni")
	case "hysteria2":
		sb.WriteString(fmt.Sprintf("name: %s\ntype: hysteria2\nserver: %s\nport: %d\npassword: %s\nudp: true\n",
			quoteYAML(name), server, port, quoteYAML(ob.Password)))
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
			quoteYAML(name), server, port, quoteYAML(ob.UUID), quoteYAML(ob.Password), quoteYAML(cc), quoteYAML(urm)))
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
			quoteYAML(name), server, port, quoteYAML(ob.Password)))
		writeSingBoxTLSAndTransport(&sb, ob, "sni")
	case "socks5":
		sb.WriteString(fmt.Sprintf("name: %s\ntype: socks5\nserver: %s\nport: %d\nudp: true\n",
			quoteYAML(name), server, port))
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
		Server:   fmt.Sprintf("%s:%d", server, port),
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

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("name: %s\ntype: ss\nserver: %s\nport: %d\ncipher: %s\npassword: %s\nudp: true\n",
		quoteYAML(name), host, port, method, quoteYAML(password)))
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
		Server:   fmt.Sprintf("%s:%d", host, port),
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

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("name: %s\ntype: vmess\nserver: %s\nport: %d\nuuid: %s\nalterId: %d\ncipher: %s\nnetwork: %s\nudp: true\n",
		quoteYAML(name), server, port, uuid, alterID, cipher, netType))
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
		Server:   fmt.Sprintf("%s:%d", server, port),
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

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("name: %s\ntype: trojan\nserver: %s\nport: %d\npassword: %s\nudp: true\n",
		quoteYAML(name), server, port, quoteYAML(password)))
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
		Server:   fmt.Sprintf("%s:%d", server, port),
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

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("name: %s\ntype: vless\nserver: %s\nport: %d\nuuid: %s\nnetwork: %s\nudp: true\n",
		quoteYAML(name), server, port, uuid, netType))
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
		Server:   fmt.Sprintf("%s:%d", server, port),
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

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("name: %s\ntype: hysteria2\nserver: %s\nport: %d\npassword: %s\nudp: true\n",
		quoteYAML(name), server, port, quoteYAML(password)))
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
		Server:   fmt.Sprintf("%s:%d", server, port),
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

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("name: %s\ntype: tuic\nserver: %s\nport: %d\nuuid: %s\npassword: %s\nudp: true\n",
		quoteYAML(name), server, port, quoteYAML(uuid), quoteYAML(password)))
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
		Server:   fmt.Sprintf("%s:%d", server, port),
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

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("name: %s\ntype: ssr\nserver: %s\nport: %d\ncipher: %s\npassword: %s\nprotocol: %s\nobfs: %s\nudp: true\n",
		quoteYAML(name), host, port, method, quoteYAML(password), protocol, obfs))
	if obfsParam != "" {
		sb.WriteString(fmt.Sprintf("obfs-param: %s\n", quoteYAML(obfsParam)))
	}
	if protoParam != "" {
		sb.WriteString(fmt.Sprintf("protocol-param: %s\n", quoteYAML(protoParam)))
	}

	return &MiaospeedNode{
		Name:     name,
		Protocol: "ssr",
		Server:   fmt.Sprintf("%s:%d", host, port),
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

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("name: %s\ntype: hysteria\nserver: %s\nport: %d\nprotocol: %s\n",
		quoteYAML(name), server, port, protocol))
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
		Server:   fmt.Sprintf("%s:%d", server, port),
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

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("name: %s\ntype: socks5\nserver: %s\nport: %d\nudp: true\n",
		quoteYAML(name), server, port))
	if username != "" {
		sb.WriteString(fmt.Sprintf("username: %s\n", quoteYAML(username)))
	}
	if password != "" {
		sb.WriteString(fmt.Sprintf("password: %s\n", quoteYAML(password)))
	}

	return &MiaospeedNode{
		Name:     name,
		Protocol: "socks5",
		Server:   fmt.Sprintf("%s:%d", server, port),
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

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("name: %s\ntype: snell\nserver: %s\nport: %d\npsk: %s\nversion: %s\nudp: true\n",
		quoteYAML(name), server, port, quoteYAML(psk), version))
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
		Server:   fmt.Sprintf("%s:%d", server, port),
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

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("name: %s\ntype: anytls\nserver: %s\nport: %d\npassword: %s\nudp: true\n",
		quoteYAML(name), server, port, quoteYAML(password)))
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

	srvAddr := net.JoinHostPort(server, strconv.Itoa(port))

	return &MiaospeedNode{
		Name:     name,
		Protocol: "anytls",
		Server:   srvAddr,
		Port:     port,
		Payload:  sb.String(),
	}, nil
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

// --- MiaoSpeed 临时进程与单次任务执行引擎 ---

// CalcMiaospeedTimeout 根据测速节点数量动态计算任务超时：
// 基础准备时间 60s + 每个节点 12s 预算，单节点保底 90s。
func CalcMiaospeedTimeout(nodeCount int) time.Duration {
	if nodeCount <= 0 {
		nodeCount = 1
	}
	timeout := 60*time.Second + time.Duration(nodeCount)*12*time.Second
	if timeout < 90*time.Second {
		timeout = 90 * time.Second
	}
	return timeout
}

// selectJobNodes 根据任务请求选取测速节点，默认无上限全量测速；仅在明确指定 Count 时截取前 Count 个节点。
func selectJobNodes(allNodes []MiaospeedNode, count int) []MiaospeedNode {
	if count > 0 && count < len(allNodes) {
		return allNodes[:count]
	}
	return allNodes
}

// runMiaospeedJob 执行一次 MiaoSpeed 测速任务：按需拉起进程 -> WebSocket 交互 -> 收集结果 -> 退出清理。
func runMiaospeedJob(ctx context.Context, binary, ghProxy string, job Job, log logger, onProgress func(Progress)) (string, json.RawMessage, error) {
	if binary == "" {
		binary = "miaospeed"
	}

	binPath := binary
	if p, err := exec.LookPath(binary); err == nil {
		binPath = p
	} else if _, err := os.Stat(binary); err != nil {
		// 未找到可执行文件，若配置为 miaospeed 标准文件名则尝试从 AirportR/miaospeed 自动下载安装
		baseName := strings.ToLower(filepath.Base(binary))
		if baseName == "miaospeed" || baseName == "miaospeed.exe" {
			if installed, err := autoInstallMiaospeed(ctx, binary, ghProxy, log); err == nil && installed != "" {
				binPath = installed
			}
		}
	}

	// 1. 解析目标节点
	allNodes, err := parseProxyTarget(ctx, job.Target)
	if err != nil {
		return "", nil, fmt.Errorf("解析测速目标失败: %w", err)
	}

	totalNodes := len(allNodes)
	nodes := selectJobNodes(allNodes, job.Count)

	// 根据节点数量动态计算本次测速的超时时间限制
	dynamicTimeout := CalcMiaospeedTimeout(len(nodes))
	if reqTimeout := time.Duration(job.TimeoutMS) * time.Millisecond; reqTimeout > dynamicTimeout {
		dynamicTimeout = reqTimeout
	}
	if dynamicTimeout > jobMiaospeedMaxTimeout {
		dynamicTimeout = jobMiaospeedMaxTimeout
	}

	taskCtx, cancelTask := context.WithTimeout(ctx, dynamicTimeout)
	defer cancelTask()

	// 立即发送首包进度，告知上游总节点数与准备状态
	if onProgress != nil {
		onProgress(Progress{
			ID:      job.ID,
			Current: 0,
			Total:   len(nodes),
			Stage:   "准备测速",
		})
	}

	// 2. 分配随机本地端口与 Token
	port, err := getFreeLocalPort()
	if err != nil {
		return "", nil, fmt.Errorf("申请本地端口失败: %w", err)
	}
	token := generateRandomHex(16)

	// 3. 启动临时 miaospeed server 进程
	cmd := exec.CommandContext(taskCtx, binPath, "server",
		"-bind", fmt.Sprintf("127.0.0.1:%d", port),
		"-token", token,
	)
	cmd.WaitDelay = 3 * time.Second
	serverOut := &cappedBuffer{max: maxOutputBytes}
	cmd.Stdout = serverOut
	cmd.Stderr = serverOut

	if log != nil {
		log.Debug("启动 miaospeed 服务", "binary", binPath, "port", port, "timeout", dynamicTimeout, "nodes", len(nodes))
	}

	if err := cmd.Start(); err != nil {
		return "", nil, fmt.Errorf("启动 miaospeed 失败: %w", err)
	}

	// 确保退出时终止进程
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}()

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	if err := waitForPortReady(taskCtx, addr, 4*time.Second); err != nil {
		return "", nil, fmt.Errorf("等待 miaospeed 就绪超时: %w\n%s", err, serverOut.String())
	}

	// 4. 发起 WebSocket 请求并执行测速
	wsURL := fmt.Sprintf("ws://%s/", addr)
	origin := fmt.Sprintf("http://%s/", addr)

	report, err := executeMiaospeedTask(taskCtx, wsURL, origin, token, nodes, totalNodes, job, log, onProgress)
	if err != nil {
		return "", nil, err
	}

	data, err := json.Marshal(report)
	if err != nil {
		return "", nil, fmt.Errorf("序列化结果数据失败: %w", err)
	}

	// 数据直接返回 JSON 供机器人端解析与排版展示
	return string(data), data, nil
}

// autoInstallMiaospeed 在运行时自动下载并解压 AirportR/miaospeed Release，严格继承使用 ghProxy。
func autoInstallMiaospeed(ctx context.Context, targetPath, ghProxy string, log logger) (string, error) {
	dm := newDependencyManager(ghProxy)
	return dm.UpdateMiaospeed(ctx, targetPath, "latest", log)
}

func mapMiaospeedArch(arch string) string {
	switch arch {
	case "amd64":
		return "amd64"
	case "arm64":
		return "arm64"
	case "arm":
		return "armv7"
	case "386":
		return "386"
	case "mips":
		return "mips-softfloat"
	case "mipsle":
		return "mipsle-softfloat"
	case "riscv64":
		return "riscv64"
	default:
		return arch
	}
}

func applyGHProxy(rawURL, ghProxy string) string {
	ghProxy = strings.TrimSpace(ghProxy)
	if ghProxy == "" {
		return rawURL
	}
	prefix := strings.TrimRight(ghProxy, "/") + "/"
	if strings.HasPrefix(rawURL, prefix) {
		return rawURL
	}
	return prefix + rawURL
}

type miaospeedTestPlan struct {
	ModeDescription   string
	Matrices          []slaveRequestMatrixEntry
	Scripts           []slaveScript
	DownloadThreading uint
	DownloadDuration  int64
	UploadThreading   uint
	UploadDuration    int64
	STUNURL           string
}

// buildMiaospeedTestPlan 根据任务参数解析期望执行的测速矩阵。
// 支持 8 种测试类型：连通性、拓扑、多线程测速、单线程测速、上行速度、延迟、UDP类型、全量测试。
func buildMiaospeedTestPlan(job Job, nodeCount ...int) miaospeedTestPlan {
	raw := strings.ToLower(strings.TrimSpace(job.Query))
	if raw == "" {
		raw = strings.ToLower(strings.TrimSpace(job.Protocol))
	}
	if raw == "" {
		kind := strings.ToLower(strings.TrimSpace(job.Kind))
		if strings.HasPrefix(kind, "miaospeed_") {
			raw = strings.TrimPrefix(kind, "miaospeed_")
		} else if strings.HasPrefix(kind, "speed_") {
			raw = strings.TrimPrefix(kind, "speed_")
		}
	}

	tokens := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '|' || r == '/'
	})

	modes := make(map[string]bool)
	for _, tok := range tokens {
		switch tok {
		case "conn", "connectivity", "connect", "http", "连通", "连通性", "代理连通性", "连通性测试", "代理连通性测试":
			modes[ModeConnectivity] = true
		case "topo", "topology", "geo", "geoip", "hijack", "拓扑", "拓扑测试":
			modes[ModeTopology] = true
		case "multi", "multithread", "multispeed", "多线程", "多线程测速", "下载", "下行":
			modes[ModeMultiSpeed] = true
		case "single", "singlethread", "singlespeed", "单线程", "单线程测速":
			modes[ModeSingleSpeed] = true
		case "latency", "ping", "rtt", "delay", "延迟", "延迟测试":
			modes[ModeLatency] = true
		case "udp", "nat", "stun", "udp类型", "udp类型测试":
			modes[ModeUDP] = true
		case "full", "all", "total", "全量", "全量测试":
			modes[ModeFull] = true
		}
	}

	count := 1
	if len(nodeCount) > 0 && nodeCount[0] > 0 {
		count = nodeCount[0]
	}
	// 多节点测试时将单节点下行测速时长收敛为 3s，兼顾精准度与整批耗时
	downloadDuration := int64(5)
	if count > 1 {
		downloadDuration = 3
	}

	// 默认或明确指定为全量测试
	if len(modes) == 0 || modes[ModeFull] {
		matrices := []slaveRequestMatrixEntry{
			{Type: matrixRTTPing},
			{Type: matrixHTTPPing},
			{Type: matrixPacketLoss},
			{Type: matrixHTTPCode},
			{Type: matrixInboundGeoIP},
			{Type: matrixOutboundGeoIP},
		}
		// 单节点测速包含防劫持检测；多节点批量测速跳过 matrixHijack
		//（miaospeed 内部 checkHijack 硬编码 2×3×7s=42s 超时且无视 TaskTimeout，会导致死节点卡住 42s，而多节点表格不展示该项）
		if count <= 1 {
			matrices = append(matrices, slaveRequestMatrixEntry{Type: matrixHijack})
		}
		matrices = append(matrices,
			slaveRequestMatrixEntry{Type: matrixUDPType},
			slaveRequestMatrixEntry{Type: matrixAverageSpeed},
			slaveRequestMatrixEntry{Type: matrixMaxSpeed},
			slaveRequestMatrixEntry{Type: "TEST_SCRIPT", Params: "youtube"},
			slaveRequestMatrixEntry{Type: "TEST_SCRIPT", Params: "netflix"},
			slaveRequestMatrixEntry{Type: "TEST_SCRIPT", Params: "disney"},
			slaveRequestMatrixEntry{Type: "TEST_SCRIPT", Params: "openai"},
			slaveRequestMatrixEntry{Type: "TEST_SCRIPT", Params: "claude"},
			slaveRequestMatrixEntry{Type: "TEST_SCRIPT", Params: "spotify"},
			slaveRequestMatrixEntry{Type: "TEST_SCRIPT", Params: "tiktok"},
			slaveRequestMatrixEntry{Type: "TEST_SCRIPT", Params: "bilibili"},
			slaveRequestMatrixEntry{Type: "TEST_SCRIPT", Params: "wikipedia"},
		)
		return miaospeedTestPlan{
			ModeDescription:   "全量测试",
			Matrices:          matrices,
			Scripts:           buildDefaultMediaScripts(),
			DownloadThreading: 4,
			DownloadDuration:  downloadDuration,
			STUNURL:           defaultSTUNServer,
		}
	}

	matrixSet := make(map[string]bool)
	var descriptions []string
	plan := miaospeedTestPlan{
		DownloadDuration: downloadDuration,
	}

	if modes[ModeConnectivity] {
		descriptions = append(descriptions, "连通性测试")
		matrixSet[matrixHTTPPing] = true
		matrixSet[matrixRTTPing] = true
		matrixSet[matrixMaxRTTPing] = true
		matrixSet[matrixPacketLoss] = true
		matrixSet[matrixHTTPCode] = true
		matrixSet[matrixOutboundGeoIP] = true
	}
	if modes[ModeTopology] {
		descriptions = append(descriptions, "拓扑测试")
		matrixSet[matrixInboundGeoIP] = true
		matrixSet[matrixOutboundGeoIP] = true
		matrixSet[matrixHijack] = true
		matrixSet[matrixRTTPing] = true
		matrixSet[matrixHTTPPing] = true
		matrixSet[matrixUDPType] = true
		plan.STUNURL = defaultSTUNServer
	}
	if modes[ModeLatency] {
		descriptions = append(descriptions, "延迟测试")
		matrixSet[matrixRTTPing] = true
		matrixSet[matrixHTTPPing] = true
		matrixSet[matrixPacketLoss] = true
		matrixSet[matrixMaxRTTPing] = true
		matrixSet[matrixHTTPCode] = true
		matrixSet[matrixOutboundGeoIP] = true
	}
	if modes[ModeUDP] {
		descriptions = append(descriptions, "UDP类型测试")
		matrixSet[matrixUDPType] = true
		matrixSet[matrixRTTPing] = true
		matrixSet[matrixHTTPPing] = true
		matrixSet[matrixPacketLoss] = true
		matrixSet[matrixHTTPCode] = true
		matrixSet[matrixOutboundGeoIP] = true
		plan.STUNURL = defaultSTUNServer
	}
	if modes[ModeSingleSpeed] {
		descriptions = append(descriptions, "单线程测速")
		matrixSet[matrixAverageSpeed] = true
		matrixSet[matrixMaxSpeed] = true
		matrixSet[matrixRTTPing] = true
		matrixSet[matrixHTTPPing] = true
		matrixSet[matrixPacketLoss] = true
		matrixSet[matrixHTTPCode] = true
		matrixSet[matrixOutboundGeoIP] = true
		plan.DownloadThreading = 1
	}
	if modes[ModeMultiSpeed] {
		descriptions = append(descriptions, "多线程测速")
		matrixSet[matrixAverageSpeed] = true
		matrixSet[matrixMaxSpeed] = true
		matrixSet[matrixRTTPing] = true
		matrixSet[matrixHTTPPing] = true
		matrixSet[matrixPacketLoss] = true
		matrixSet[matrixHTTPCode] = true
		matrixSet[matrixOutboundGeoIP] = true
		th := uint(4)
		if job.Count > 1 && job.Count <= 16 {
			th = uint(job.Count)
		}
		plan.DownloadThreading = th
	}
	orderedMatrixKeys := []string{
		matrixRTTPing, matrixHTTPPing, matrixPacketLoss, matrixMaxRTTPing, matrixHTTPCode,
		matrixInboundGeoIP, matrixOutboundGeoIP, matrixHijack,
		matrixUDPType,
		matrixAverageSpeed, matrixMaxSpeed,
	}
	for _, key := range orderedMatrixKeys {
		if matrixSet[key] {
			plan.Matrices = append(plan.Matrices, slaveRequestMatrixEntry{Type: key})
		}
	}
	plan.ModeDescription = strings.Join(descriptions, " + ")
	return plan
}

// executeMiaospeedTask 连接 WebSocket、发送任务并读取结果。
func executeMiaospeedTask(ctx context.Context, wsURL, origin, token string, nodes []MiaospeedNode, totalNodes int, job Job, log logger, onProgress func(Progress)) (*MiaospeedReport, error) {
	wsCfg, err := websocket.NewConfig(wsURL, origin)
	if err != nil {
		return nil, fmt.Errorf("配置 websocket 失败: %w", err)
	}

	type dialResult struct {
		conn *websocket.Conn
		err  error
	}
	dialCh := make(chan dialResult, 1)
	go func() {
		conn, err := websocket.DialConfig(wsCfg)
		dialCh <- dialResult{conn: conn, err: err}
	}()

	var ws *websocket.Conn
	select {
	case <-ctx.Done():
		go func() {
			if res := <-dialCh; res.conn != nil {
				_ = res.conn.Close()
			}
		}()
		return nil, ctx.Err()
	case res := <-dialCh:
		if res.err != nil {
			return nil, fmt.Errorf("连接 miaospeed 服务失败: %w", res.err)
		}
		ws = res.conn
	}
	defer ws.Close()

	plan := buildMiaospeedTestPlan(job, len(nodes))

	// 构造节点
	reqNodes := make([]slaveRequestNode, 0, len(nodes))
	for _, n := range nodes {
		reqNodes = append(reqNodes, slaveRequestNode{
			Name:    n.Name,
			Payload: n.Payload,
		})
	}

	stunURL := plan.STUNURL
	if stunURL == "" {
		stunURL = defaultSTUNServer
	}

	scripts := plan.Scripts
	if scripts == nil {
		scripts = make([]slaveScript, 0)
	}

	// 批量测速时若节点超时或阻断，不重试（TaskRetry=0）并将单次超时收紧为 3500ms，避免死节点阻塞整批进度
	taskRetry := uint(2)
	taskTimeout := uint(5000)
	if len(nodes) > 1 {
		taskRetry = 0
		taskTimeout = 3500
	}

	req := slaveRequest{
		Basics: slaveRequestBasics{
			ID:        job.ID,
			Slave:     "mnagent",
			SlaveName: "mnagent-local",
			Invoker:   "mnagent",
			Version:   "1.0",
		},
		Options: slaveRequestOptions{
			Matrices: plan.Matrices,
		},
		Configs: slaveRequestConfigs{
			STUNURL:           stunURL,
			DownloadURL:       defaultSpeedFile,
			DownloadDuration:  plan.DownloadDuration,
			DownloadThreading: plan.DownloadThreading,
			PingAddress:       defaultPingURL,
			PingAverageOver:   2,
			TaskRetry:         taskRetry,
			TaskTimeout:       taskTimeout,
			DNSServers:        make([]string, 0),
			Scripts:           scripts,
		},
		Vendor:         "Clash",
		Nodes:          reqNodes,
		RandomSequence: generateRandomHex(8),
	}

	// 签名
	sig, err := signMiaoSpeedRequest(token, defaultBuildToken, req)
	if err != nil {
		return nil, fmt.Errorf("签名任务请求失败: %w", err)
	}
	req.Challenge = sig

	// 发送任务
	if err := websocket.JSON.Send(ws, req); err != nil {
		return nil, fmt.Errorf("向 miaospeed 发送任务失败: %w", err)
	}

	// 接收结果
	startTime := time.Now()
	var lastProgressTime time.Time
	var progressSlots []slaveEntrySlot
	for {
		select {
		case <-ctx.Done():
			if len(progressSlots) > 0 {
				resTask := &slaveTask{Results: progressSlots}
				return parseSlaveTaskResult(resTask, nodes, totalNodes, plan, time.Since(startTime)), nil
			}
			return nil, ctx.Err()
		default:
		}

		var resp slaveResponse
		if err := readNextSlaveJSON(ctx, ws, &resp); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
				break
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			if len(progressSlots) > 0 {
				break
			}
			return nil, fmt.Errorf("读取 miaospeed 响应失败: %w", err)
		}
		if log != nil {
			log.Debug("收到 miaospeed 响应", "has_result", resp.Result != nil, "has_progress", resp.Progress != nil, "error", resp.Error)
		}

		if resp.Error != "" {
			return nil, fmt.Errorf("miaospeed 任务执行报错: %s", resp.Error)
		}

		if resp.Progress != nil && resp.Progress.Record != nil {
			progressSlots = append(progressSlots, *resp.Progress.Record)
			if onProgress != nil {
				curIdx := resp.Progress.Index + 1
				curName := ""
				if resp.Progress.Index >= 0 && resp.Progress.Index < len(nodes) {
					curName = nodes[resp.Progress.Index].Name
				}
				now := time.Now()
				if curIdx == 1 || curIdx >= len(nodes) || now.Sub(lastProgressTime) >= 600*time.Millisecond {
					lastProgressTime = now
					onProgress(Progress{
						ID:       job.ID,
						Current:  curIdx,
						Total:    len(nodes),
						NodeName: curName,
						Stage:    "全量测速中",
					})
				}
			}
		}

		if resp.Result != nil {
			report := parseSlaveTaskResult(resp.Result, nodes, totalNodes, plan, time.Since(startTime))
			return report, nil
		}
	}

	if len(progressSlots) > 0 {
		resTask := &slaveTask{Results: progressSlots}
		report := parseSlaveTaskResult(resTask, nodes, totalNodes, plan, time.Since(startTime))
		return report, nil
	}

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return nil, errors.New("miaospeed 连接已关闭，但未收到结果数据")
}

// parseSingleSlot 提取单个节点的 slot 数据为 MiaospeedReport。
func parseSingleSlot(slot slaveEntrySlot, node *MiaospeedNode, plan miaospeedTestPlan) MiaospeedReport {
	rep := MiaospeedReport{
		TestMode:        plan.ModeDescription,
		DownloadThreads: int(plan.DownloadThreading),
		MediaUnlock:     make(map[string]string),
	}
	if node != nil {
		rep.NodeName = node.Name
		rep.Protocol = node.Protocol
		rep.Server = node.Server
	}
	for _, m := range slot.Matrices {
		switch m.Type {
		case matrixRTTPing:
			rep.PingRTTMs = parseMatrixFloat(m.Payload)
		case matrixHTTPPing:
			rep.PingConnMs = parseMatrixFloat(m.Payload)
		case matrixPacketLoss:
			rep.PacketLoss = parseMatrixFloat(m.Payload)
		case matrixMaxRTTPing:
			rep.MaxRTTMs = parseMatrixFloat(m.Payload)
		case matrixHTTPCode:
			rep.HTTPCode = parseMatrixHTTPCode(m.Payload)
		case matrixUDPType:
			rep.UDPType = parseMatrixString(m.Payload)
		case matrixInboundGeoIP:
			_, rep.InboundGeo = parseMatrixGeo(m.Payload)
			if rep.InboundGeo == rep.NodeName || rep.InboundGeo == rep.Server {
				rep.InboundGeo = ""
			}
		case matrixOutboundGeoIP:
			rep.OutboundIP, rep.OutboundGeo = parseMatrixGeo(m.Payload)
			if rep.OutboundGeo == rep.NodeName || rep.OutboundGeo == rep.Server {
				rep.OutboundGeo = ""
			}
		case matrixHijack:
			rep.Hijack = parseMatrixHijack(m.Payload)
		case matrixAverageSpeed:
			rep.AvgSpeedBps = parseMatrixFloat(m.Payload)
		case matrixMaxSpeed:
			rep.MaxSpeedBps = parseMatrixFloat(m.Payload)
		case "TEST_SCRIPT":
			mediaName, status := parseMatrixScript(m.Payload)
			if mediaName != "" && status != "" {
				rep.MediaUnlock[mediaName] = status
			}
		}
	}
	return rep
}

// parseSlaveTaskResult 将 miaospeed 任务返回结果整理为 MiaospeedReport。
func parseSlaveTaskResult(task *slaveTask, nodes []MiaospeedNode, totalNodes int, plan miaospeedTestPlan, duration time.Duration) *MiaospeedReport {
	if totalNodes <= 0 {
		totalNodes = len(nodes)
	}
	if len(task.Results) == 0 {
		var n *MiaospeedNode
		if len(nodes) > 0 {
			n = &nodes[0]
		}
		rep := parseSingleSlot(slaveEntrySlot{}, n, plan)
		rep.TotalNodes = totalNodes
		rep.DurationMs = duration.Milliseconds()
		rep.RawResults = task.Results
		return &rep
	}

	var firstNode *MiaospeedNode
	if len(nodes) > 0 {
		firstNode = &nodes[0]
	}
	mainRep := parseSingleSlot(task.Results[0], firstNode, plan)
	mainRep.TotalNodes = totalNodes
	mainRep.DurationMs = duration.Milliseconds()
	mainRep.RawResults = task.Results

	// 多节点结果同步封装为 SubReports
	if len(task.Results) > 1 {
		mainRep.SubReports = make([]MiaospeedReport, 0, len(task.Results))
		for i, slot := range task.Results {
			var nodePtr *MiaospeedNode
			if i < len(nodes) {
				nodePtr = &nodes[i]
			}
			sub := parseSingleSlot(slot, nodePtr, plan)
			sub.DurationMs = duration.Milliseconds()
			sub.TotalNodes = totalNodes
			mainRep.SubReports = append(mainRep.SubReports, sub)
		}
	}

	return &mainRep
}

// parseMatrixFloat 提取形如 `{"Value":12.3}` 或裸数值 `12.3` 的浮点数。
func parseMatrixFloat(payload string) float64 {
	payload = strings.TrimSpace(payload)
	if payload == "" {
		return 0
	}
	if strings.HasPrefix(payload, "{") {
		var obj struct {
			Value float64 `json:"Value"`
		}
		if err := json.Unmarshal([]byte(payload), &obj); err == nil {
			return obj.Value
		}
	}
	val, _ := strconv.ParseFloat(payload, 64)
	return val
}

// parseMatrixHTTPCode 提取形如 `{"Values":[204,204]}` 或 `{"Value":200}` 或裸数值的状态码。
func parseMatrixHTTPCode(payload string) int {
	payload = strings.TrimSpace(payload)
	if payload == "" {
		return 0
	}
	if strings.HasPrefix(payload, "{") {
		var obj struct {
			Values []int `json:"Values"`
			Value  int   `json:"Value"`
		}
		if err := json.Unmarshal([]byte(payload), &obj); err == nil {
			if len(obj.Values) > 0 && obj.Values[0] > 0 {
				return obj.Values[0]
			}
			if obj.Value > 0 {
				return obj.Value
			}
		}
	}
	val, _ := strconv.Atoi(payload)
	return val
}

// parseMatrixString 提取形如 `{"Value":"FullCone"}` 或裸文本的字符串。
func parseMatrixString(payload string) string {
	payload = strings.TrimSpace(payload)
	if payload == "" {
		return ""
	}
	if strings.HasPrefix(payload, "{") {
		var obj struct {
			Value string `json:"Value"`
		}
		if err := json.Unmarshal([]byte(payload), &obj); err == nil && obj.Value != "" {
			return obj.Value
		}
	}
	return payload
}

// parseMatrixGeo 解析 MultiStacks JSON 提取地理位置与 IP。
func parseMatrixGeo(payload string) (ip, geo string) {
	payload = strings.TrimSpace(payload)
	if payload == "" {
		return "", ""
	}
	if strings.HasPrefix(payload, "{") {
		var stacks struct {
			Domain    string `json:"Domain"`
			MainStack *struct {
				Country string `json:"country"`
				ISP     string `json:"isp"`
				IP      string `json:"ip"`
			} `json:"MainStack"`
			IPv4Stack []*struct {
				Country string `json:"country"`
				ISP     string `json:"isp"`
				IP      string `json:"ip"`
			} `json:"IPv4Stack"`
			IPv6Stack []*struct {
				Country string `json:"country"`
				ISP     string `json:"isp"`
				IP      string `json:"ip"`
			} `json:"IPv6Stack"`
		}
		if err := json.Unmarshal([]byte(payload), &stacks); err == nil {
			var targetGeo *struct {
				Country string `json:"country"`
				ISP     string `json:"isp"`
				IP      string `json:"ip"`
			}
			if len(stacks.IPv4Stack) > 0 && stacks.IPv4Stack[0] != nil {
				targetGeo = stacks.IPv4Stack[0]
			} else if len(stacks.IPv6Stack) > 0 && stacks.IPv6Stack[0] != nil {
				targetGeo = stacks.IPv6Stack[0]
			} else if stacks.MainStack != nil {
				targetGeo = stacks.MainStack
			}

			if targetGeo != nil {
				ip = targetGeo.IP
				parts := make([]string, 0, 2)
				if targetGeo.Country != "" {
					parts = append(parts, targetGeo.Country)
				}
				if targetGeo.ISP != "" && targetGeo.ISP != targetGeo.Country {
					parts = append(parts, targetGeo.ISP)
				}
				if len(parts) > 0 {
					geo = strings.Join(parts, " ")
				}
			}
			return ip, geo
		}
		return "", ""
	}
	return "", payload
}

// parseMatrixHijack 解析防劫持 JSON
func parseMatrixHijack(payload string) string {
	payload = strings.TrimSpace(payload)
	if payload == "" {
		return "未检测"
	}
	var obj struct {
		SpeedIP string `json:"SpeedIP"`
		RealIP  string `json:"RealIP"`
		Hijack  bool   `json:"Hijack"`
	}
	if err := json.Unmarshal([]byte(payload), &obj); err == nil {
		if obj.Hijack || (obj.SpeedIP != "" && obj.RealIP != "" && obj.SpeedIP != obj.RealIP) {
			return fmt.Sprintf("⚠️ 疑似劫持 (%s != %s)", obj.SpeedIP, obj.RealIP)
		}
		return "正常 (未劫持)"
	}
	return payload
}

func getFreeLocalPort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func waitForPortReady(ctx context.Context, addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errors.New("端口未就绪")
}

func generateRandomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// buildDefaultMediaScripts 返回主流流媒体检测与快速 GeoIP 探测的轻量 JavaScript 脚本集。
func buildDefaultMediaScripts() []slaveScript {
	return []slaveScript{
		{
			// 覆盖 miaospeed 默认的 default_ip.js 与 default_geoip.js：
			// 默认脚本对每个节点顺序请求 IPv4 + IPv6 (2606:4700:4700::1111) 且单次 3000ms，
			// 导致无 IPv6 的正常节点每次白等 3s、死节点重试 3 次阻塞 18s。
			// 此处收敛为轻量 IPv4 1500ms 快速探测，大幅加速大订阅多节点测速。
			ID:   "ip_fast",
			Type: "ip",
			Content: `function ip_resolve() {
    var content = (get(fetch("https://1.1.1.1/cdn-cgi/trace", {
        headers: {'User-Agent': 'Mozilla/5.0'},
        retry: 1,
        timeout: 1500
    }), "body") || "").trim();
    var m = content.match(/ip=(\S+)/);
    if (m && m[1]) return [m[1].trim()];
    return [];
}
function handler(ip) {
    var content = fetch("https://ipv4.ipleak.net/json/" + ip, {
        headers: {'User-Agent': 'Mozilla/5.0'},
        retry: 1,
        timeout: 2000
    });
    var ret = safeParse(get(content, "body"));
    return {
        "ip": get(ret, "ip", ""),
        "isp": get(ret, "isp_name", ""),
        "organization": get(ret, "isp_name", ""),
        "latitude": get(ret, "latitude", 0),
        "longitude": get(ret, "longitude", 0),
        "asn": parseInt(get(ret, "as_number", 0), 10) || 0,
        "asn_organization": get(ret, "isp_name", ""),
        "timezone": get(ret, "time_zone", ""),
        "region": get(ret, "region_name", ""),
        "city": get(ret, "city_name", ""),
        "country": get(ret, "country_name", ""),
        "country_code": get(ret, "country_code", "")
    };
}`,
			TimeoutMillis: 2500,
		},
		{
			ID:   "youtube",
			Type: "media",
			Content: `function handler() {
    var res = fetch("https://www.youtube.com/premium", { headers: {'User-Agent':'Mozilla/5.0'}, timeout: 2500 });
    if (!res || !res.body) return { text: "超时", color: "#f87171" };
    if (res.body.indexOf("Premium is not available in your country") > 0) return { text: "不支持", color: "#f87171" };
    var m = res.body.match(/"countryCode":"([A-Z]{2})"/);
    if (m && m[1]) return { text: "支持 (" + m[1] + ")", color: "#34d399" };
    return { text: "支持", color: "#34d399" };
}`,
			TimeoutMillis: 3000,
		},
		{
			ID:   "netflix",
			Type: "media",
			Content: `function handler() {
    var res1 = fetch("https://www.netflix.com/title/80018499", { headers: {'User-Agent':'Mozilla/5.0'}, noRedir: true, timeout: 2500 });
    if (!res1) return { text: "超时", color: "#f87171" };
    if (res1.statusCode === 200) return { text: "原生解锁", color: "#34d399" };
    var res2 = fetch("https://www.netflix.com/title/70143836", { headers: {'User-Agent':'Mozilla/5.0'}, noRedir: true, timeout: 2500 });
    if (res2 && res2.statusCode === 200) return { text: "仅自制剧", color: "#fbbf24" };
    return { text: "不可用", color: "#f87171" };
}`,
			TimeoutMillis: 3000,
		},
		{
			ID:   "disney",
			Type: "media",
			Content: `function handler() {
    var res = fetch("https://www.disneyplus.com/", { headers: {'User-Agent':'Mozilla/5.0'}, noRedir: true, timeout: 2500 });
    if (!res) return { text: "超时", color: "#f87171" };
    var loc = get(res, "headers.Location", "");
    if (loc.indexOf("preview") > 0 || loc.indexOf("unavailable") > 0) return { text: "不可用", color: "#f87171" };
    if (res.statusCode === 200 || res.statusCode === 301 || res.statusCode === 302) return { text: "解锁", color: "#34d399" };
    return { text: "不可用", color: "#f87171" };
}`,
			TimeoutMillis: 3000,
		},
		{
			ID:   "openai",
			Type: "media",
			Content: `function handler() {
    var res = fetch("https://ios.chat.openai.com/public-api/mobile/server_status/v1", { timeout: 2500 });
    if (!res) return { text: "超时", color: "#f87171" };
    if (res.statusCode === 200) return { text: "支持", color: "#34d399" };
    if (res.statusCode === 403) return { text: "封锁", color: "#f87171" };
    if (res.body && res.body.indexOf("unsupported_country") > 0) return { text: "地区受限", color: "#f87171" };
    return { text: "支持", color: "#34d399" };
}`,
			TimeoutMillis: 3000,
		},
		{
			ID:   "spotify",
			Type: "media",
			Content: `function handler() {
    var res = fetch("https://spclient.wg.spotify.com/signup/public/v1/account", { headers: {'User-Agent':'Mozilla/5.0'}, timeout: 2500 });
    if (!res) return { text: "超时", color: "#f87171" };
    if (res.statusCode === 200 || res.statusCode === 400) return { text: "支持", color: "#34d399" };
    return { text: "不可用", color: "#f87171" };
}`,
			TimeoutMillis: 3000,
		},
		{
			ID:   "claude",
			Type: "media",
			Content: `function handler() {
    var res = fetch("https://claude.ai/login", { headers: {'User-Agent':'Mozilla/5.0'}, noRedir: true, timeout: 2500 });
    if (!res) return { text: "超时", color: "#f87171" };
    var loc = get(res, "headers.Location", "");
    if (loc.indexOf("unavailable") > 0) return { text: "不可用", color: "#f87171" };
    if (res.statusCode === 200) return { text: "支持", color: "#34d399" };
    return { text: "不可用", color: "#f87171" };
}`,
			TimeoutMillis: 3000,
		},
		{
			ID:   "tiktok",
			Type: "media",
			Content: `function handler() {
    var res = fetch("https://www.tiktok.com", { headers: {'User-Agent':'Mozilla/5.0'}, timeout: 2500 });
    if (!res || !res.body) return { text: "超时", color: "#f87171" };
    if (res.statusCode === 200) {
        var idx = res.body.indexOf('"region":');
        if (idx > 0) {
            var r = res.body.substring(idx).split('"')[3];
            if (r) return { text: "解锁 (" + r + ")", color: "#34d399" };
        }
        return { text: "解锁", color: "#34d399" };
    }
    return { text: "失败", color: "#f87171" };
}`,
			TimeoutMillis: 3000,
		},
		{
			ID:   "bilibili",
			Type: "media",
			Content: `function handler() {
    var res = fetch("https://api.bilibili.com/pgc/player/web/playurl?avid=50762638&cid=100279344&qn=0&type=&otype=json&ep_id=268176", { headers: {'User-Agent':'Mozilla/5.0'}, timeout: 2500 });
    if (!res || !res.body) return { text: "超时", color: "#f87171" };
    var d = safeParse(res.body);
    if (d.code === 0 || d.message === "success") return { text: "解锁 (台湾)", color: "#34d399" };
    var res2 = fetch("https://api.bilibili.com/pgc/player/web/playurl?avid=18281381&cid=29892777&qn=0&type=&otype=json&ep_id=183799", { headers: {'User-Agent':'Mozilla/5.0'}, timeout: 2500 });
    if (res2 && res2.body) {
        var d2 = safeParse(res2.body);
        if (d2.code === 0 || d2.message === "success") return { text: "解锁 (港澳台)", color: "#34d399" };
    }
    return { text: "大陆受限", color: "#fbbf24" };
}`,
			TimeoutMillis: 3000,
		},
		{
			ID:   "wikipedia",
			Type: "media",
			Content: `function handler() {
    var res = fetch("https://en.wikipedia.org/w/index.php?title=Wikipedia:WikiProject_on_open_proxies&action=edit", { headers: {'User-Agent':'Mozilla/5.0'}, timeout: 2500 });
    if (!res || !res.body) return { text: "超时", color: "#f87171" };
    if (res.body.indexOf("This IP address has been") > 0) return { text: "禁止编辑", color: "#f87171" };
    if (res.statusCode === 200) return { text: "允许编辑", color: "#34d399" };
    return { text: "不可用", color: "#f87171" };
}`,
			TimeoutMillis: 3000,
		},
	}
}

func parseMatrixScript(payload string) (name, status string) {
	payload = strings.TrimSpace(payload)
	if payload == "" {
		return "", ""
	}
	var obj struct {
		Key  string `json:"Key"`
		Text string `json:"Text"`
	}
	if err := json.Unmarshal([]byte(payload), &obj); err == nil {
		display := mapScriptKey(obj.Key)
		return display, obj.Text
	}
	return "", ""
}

func mapScriptKey(key string) string {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "youtube":
		return "YouTube"
	case "netflix":
		return "Netflix"
	case "disney":
		return "Disney+"
	case "openai":
		return "OpenAI"
	case "claude":
		return "Claude"
	case "spotify":
		return "Spotify"
	case "tiktok":
		return "TikTok"
	case "bilibili":
		return "Bilibili"
	case "wikipedia":
		return "维基百科"
	default:
		return key
	}
}

// readNextSlaveJSON 从 ws 连接中读取下一条完整的 JSON 响应并反序列化。
// 内部处理 5s ReadDeadline 超时并在 ctx 未结束时继续累积读取，防止跨读取周期拆帧丢失半包数据。
func readNextSlaveJSON(ctx context.Context, ws *websocket.Conn, dest any) error {
	var buf bytes.Buffer
	chunk := make([]byte, 32*1024)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		_ = ws.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := ws.Read(chunk)
		if n > 0 {
			buf.Write(chunk[:n])
			b := bytes.TrimSpace(buf.Bytes())
			if len(b) > 0 && b[0] == '{' && b[len(b)-1] == '}' {
				if json.Valid(b) {
					if jsonErr := json.Unmarshal(b, dest); jsonErr == nil {
						return nil
					}
				}
			}
		}
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				continue
			}
			if buf.Len() > 0 {
				b := bytes.TrimSpace(buf.Bytes())
				if len(b) > 0 && json.Valid(b) {
					if jsonErr := json.Unmarshal(b, dest); jsonErr == nil {
						return nil
					}
				}
			}
			return err
		}
	}
}
