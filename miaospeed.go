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
	"strconv"
	"strings"
	"time"

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
	TestMode        string           `json:"test_mode,omitempty"`
	NodeName        string           `json:"node_name"`
	Protocol        string           `json:"protocol,omitempty"`
	Server          string           `json:"server,omitempty"`
	HTTPCode        int              `json:"http_code,omitempty"`
	PingRTTMs       float64          `json:"ping_rtt_ms,omitempty"`
	PingConnMs      float64          `json:"ping_conn_ms,omitempty"`
	MaxRTTMs        float64          `json:"max_rtt_ms,omitempty"`
	PacketLoss      float64          `json:"packet_loss_pct,omitempty"`
	UDPType         string           `json:"udp_type,omitempty"`
	DownloadThreads int              `json:"download_threads,omitempty"`
	AvgSpeedBps     float64          `json:"avg_speed_bps,omitempty"` // 字节/秒
	MaxSpeedBps     float64          `json:"max_speed_bps,omitempty"` // 字节/秒
	InboundGeo      string           `json:"inbound_geo,omitempty"`
	OutboundIP      string           `json:"outbound_ip,omitempty"`
	OutboundGeo     string           `json:"outbound_geo,omitempty"`
	Hijack          string           `json:"hijack,omitempty"`
	DurationMs      int64            `json:"duration_ms"`
	RawResults      []slaveEntrySlot `json:"raw_results,omitempty"`
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

	if r.PingRTTMs > 0 || r.PingConnMs > 0 || r.PacketLoss > 0 {
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
	} else if r.PacketLoss >= 100 {
		b.WriteString("延迟: 节点不可达 (100% 丢包)\n")
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
	ScriptType string
	ScriptName string
	ScriptData string
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
	Index int `json:"Index"`
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

// parseProxyTarget 将任务 Target（单节点链接、订阅 URL 或原生 YAML）解析为节点列表。
func parseProxyTarget(ctx context.Context, target string) ([]MiaospeedNode, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, errors.New("目标地址不能为空")
	}

	// 1. 如果是以 http:// 或 https:// 开头的订阅地址，拉取并解析。
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return fetchAndParseSubscription(ctx, target)
	}

	// 2. 如果包含换行且含有 YAML 关键字（如 type: ），直接作为原生配置。
	if strings.Contains(target, "type:") && (strings.Contains(target, "server:") || strings.Contains(target, "port:")) {
		return []MiaospeedNode{{
			Name:    "Custom-Node",
			Payload: target,
		}}, nil
	}

	// 3. 解析单节点 URI（ss://, vmess://, trojan://, vless://, hysteria2://）。
	node, err := parseProxyURI(target)
	if err != nil {
		return nil, err
	}
	return []MiaospeedNode{*node}, nil
}

// fetchAndParseSubscription 拉取订阅并提取节点。
func fetchAndParseSubscription(ctx context.Context, subURL string) ([]MiaospeedNode, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, subURL, nil)
	if err != nil {
		return nil, fmt.Errorf("构建订阅请求失败: %w", err)
	}
	req.Header.Set("User-Agent", "ClashMeta/v1.19.23 mnagent")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("拉取订阅失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("拉取订阅返回 HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20)) // 限制 4MB
	if err != nil {
		return nil, fmt.Errorf("读取订阅失败: %w", err)
	}

	content := strings.TrimSpace(string(body))
	// 尝试 Base64 解码
	decoded, err := base64.StdEncoding.DecodeString(content)
	if err == nil && len(decoded) > 0 {
		content = string(decoded)
	} else if rawDecoded, err2 := base64.RawStdEncoding.DecodeString(content); err2 == nil && len(rawDecoded) > 0 {
		content = string(rawDecoded)
	}

	lines := strings.Split(content, "\n")
	var nodes []MiaospeedNode
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if n, err := parseProxyURI(line); err == nil && n != nil {
			nodes = append(nodes, *n)
		}
	}

	if len(nodes) == 0 {
		return nil, errors.New("订阅中未找到有效代理节点")
	}
	return nodes, nil
}

// parseProxyURI 解析主流代理协议 URI 为 MiaospeedNode。
func parseProxyURI(rawURI string) (*MiaospeedNode, error) {
	rawURI = strings.TrimSpace(rawURI)
	u, err := url.Parse(rawURI)
	if err != nil {
		return nil, fmt.Errorf("无法解析节点链接: %w", err)
	}

	switch strings.ToLower(u.Scheme) {
	case "ss":
		return parseShadowsocksURI(rawURI, u)
	case "vmess":
		return parseVmessURI(rawURI)
	case "trojan":
		return parseTrojanURI(u)
	case "vless":
		return parseVlessURI(u)
	case "hysteria2", "hy2":
		return parseHysteria2URI(u)
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

	payload := fmt.Sprintf("name: %s\ntype: ss\nserver: %s\nport: %d\ncipher: %s\npassword: %s\n",
		quoteYAML(name), host, port, method, quoteYAML(password))

	return &MiaospeedNode{
		Name:     name,
		Protocol: "ss",
		Server:   fmt.Sprintf("%s:%d", host, port),
		Port:     port,
		Payload:  payload,
	}, nil
}

func decodeBase64Safe(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
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
	netType := getString(v, "net")
	if netType == "" {
		netType = "tcp"
	}
	tls := getString(v, "tls") == "tls"
	host := getString(v, "host")
	path := getString(v, "path")
	sni := getString(v, "sni")

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("name: %s\ntype: vmess\nserver: %s\nport: %d\nuuid: %s\nalterId: %d\ncipher: %s\nnetwork: %s\n",
		quoteYAML(name), server, port, uuid, alterID, cipher, netType))
	if tls {
		sb.WriteString("tls: true\n")
		if sni != "" {
			sb.WriteString(fmt.Sprintf("servername: %s\n", quoteYAML(sni)))
		}
	}
	if netType == "ws" {
		sb.WriteString("ws-opts:\n")
		if path != "" {
			sb.WriteString(fmt.Sprintf("  path: %s\n", quoteYAML(path)))
		}
		if host != "" {
			sb.WriteString(fmt.Sprintf("  headers:\n    Host: %s\n", quoteYAML(host)))
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
	sni := u.Query().Get("sni")
	if sni == "" {
		sni = u.Query().Get("peer")
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("name: %s\ntype: trojan\nserver: %s\nport: %d\npassword: %s\n",
		quoteYAML(name), server, port, quoteYAML(password)))
	if sni != "" {
		sb.WriteString(fmt.Sprintf("sni: %s\n", quoteYAML(sni)))
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
	uuid := u.User.Username()
	server := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	if port == 0 {
		port = 443
	}
	security := u.Query().Get("security")
	sni := u.Query().Get("sni")
	netType := u.Query().Get("type")
	if netType == "" {
		netType = "tcp"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("name: %s\ntype: vless\nserver: %s\nport: %d\nuuid: %s\nnetwork: %s\n",
		quoteYAML(name), server, port, uuid, netType))
	if security == "tls" || security == "reality" {
		sb.WriteString("tls: true\n")
		if sni != "" {
			sb.WriteString(fmt.Sprintf("servername: %s\n", quoteYAML(sni)))
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
	password := u.User.Username()
	server := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	if port == 0 {
		port = 443
	}
	sni := u.Query().Get("sni")

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("name: %s\ntype: hysteria2\nserver: %s\nport: %d\npassword: %s\n",
		quoteYAML(name), server, port, quoteYAML(password)))
	if sni != "" {
		sb.WriteString(fmt.Sprintf("sni: %s\n", quoteYAML(sni)))
	}

	return &MiaospeedNode{
		Name:     name,
		Protocol: "hysteria2",
		Server:   fmt.Sprintf("%s:%d", server, port),
		Port:     port,
		Payload:  sb.String(),
	}, nil
}

func quoteYAML(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

func getString(m map[string]any, k string) string {
	if v, ok := m[k]; ok {
		if s, ok := v.(string); ok {
			return s
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

// runMiaospeedJob 执行一次 MiaoSpeed 测速任务：按需拉起进程 -> WebSocket 交互 -> 收集结果 -> 退出清理。
func runMiaospeedJob(ctx context.Context, binary, ghProxy string, job Job, log logger) (string, json.RawMessage, error) {
	if binary == "" {
		binary = "miaospeed"
	}

	binPath := binary
	if p, err := exec.LookPath(binary); err == nil {
		binPath = p
	} else if _, err := os.Stat(binary); err != nil {
		// 未找到可执行文件，尝试从 AirportR/miaospeed 自动下载安装（继承使用 ghProxy）
		if installed, err := autoInstallMiaospeed(ctx, binary, ghProxy, log); err == nil && installed != "" {
			binPath = installed
		}
	}

	// 1. 解析目标节点
	nodes, err := parseProxyTarget(ctx, job.Target)
	if err != nil {
		return "", nil, fmt.Errorf("解析测速目标失败: %w", err)
	}

	// 2. 分配随机本地端口与 Token
	port, err := getFreeLocalPort()
	if err != nil {
		return "", nil, fmt.Errorf("申请本地端口失败: %w", err)
	}
	token := generateRandomHex(16)

	// 3. 启动临时 miaospeed server 进程
	cmdCtx, cancelCmd := context.WithCancel(ctx)
	defer cancelCmd()

	cmd := exec.CommandContext(cmdCtx, binPath, "server",
		"-bind", fmt.Sprintf("127.0.0.1:%d", port),
		"-token", token,
	)
	cmd.WaitDelay = 3 * time.Second
	var serverOut strings.Builder
	cmd.Stdout = &serverOut
	cmd.Stderr = &serverOut

	if log != nil {
		log.Debug("启动 miaospeed 服务", "binary", binPath, "port", port)
	}

	if err := cmd.Start(); err != nil {
		return "", nil, fmt.Errorf("启动 miaospeed 失败: %w", err)
	}

	// 确保退出时终止进程
	defer func() {
		cancelCmd()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}()

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	if err := waitForPortReady(ctx, addr, 4*time.Second); err != nil {
		return "", nil, fmt.Errorf("等待 miaospeed 就绪超时: %w\n%s", err, serverOut.String())
	}

	// 4. 发起 WebSocket 请求并执行测速
	wsURL := fmt.Sprintf("ws://%s/", addr)
	origin := fmt.Sprintf("http://%s/", addr)

	report, err := executeMiaospeedTask(ctx, wsURL, origin, token, nodes, job, log)
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
	DownloadThreading uint
	DownloadDuration  int64
	UploadThreading   uint
	UploadDuration    int64
	STUNURL           string
}

// buildMiaospeedTestPlan 根据任务参数解析期望执行的测速矩阵。
// 支持 8 种测试类型：连通性、拓扑、多线程测速、单线程测速、上行速度、延迟、UDP类型、全量测试。
func buildMiaospeedTestPlan(job Job) miaospeedTestPlan {
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

	// 默认或明确指定为全量测试
	if len(modes) == 0 || modes[ModeFull] {
		return miaospeedTestPlan{
			ModeDescription: "全量测试",
			Matrices: []slaveRequestMatrixEntry{
				{Type: matrixRTTPing},
				{Type: matrixHTTPPing},
				{Type: matrixPacketLoss},
				{Type: matrixHTTPCode},
				{Type: matrixInboundGeoIP},
				{Type: matrixOutboundGeoIP},
				{Type: matrixHijack},
				{Type: matrixUDPType},
				{Type: matrixAverageSpeed},
				{Type: matrixMaxSpeed},
			},
			DownloadThreading: 4,
			DownloadDuration:  5,
			STUNURL:           defaultSTUNServer,
		}
	}

	matrixSet := make(map[string]bool)
	var descriptions []string
	plan := miaospeedTestPlan{
		DownloadDuration: 5,
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
func executeMiaospeedTask(ctx context.Context, wsURL, origin, token string, nodes []MiaospeedNode, job Job, log logger) (*MiaospeedReport, error) {
	wsCfg, err := websocket.NewConfig(wsURL, origin)
	if err != nil {
		return nil, fmt.Errorf("配置 websocket 失败: %w", err)
	}

	var ws *websocket.Conn
	dialErrChan := make(chan error, 1)
	go func() {
		conn, err := websocket.DialConfig(wsCfg)
		if err != nil {
			dialErrChan <- err
			return
		}
		ws = conn
		close(dialErrChan)
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case err := <-dialErrChan:
		if err != nil {
			return nil, fmt.Errorf("连接 miaospeed 服务失败: %w", err)
		}
	}
	defer ws.Close()

	plan := buildMiaospeedTestPlan(job)

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
			TaskRetry:         2,
			TaskTimeout:       5000,
			DNSServers:        make([]string, 0),
			Scripts:           make([]slaveScript, 0),
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
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		_ = ws.SetReadDeadline(time.Now().Add(5 * time.Second))
		var resp slaveResponse
		if err := readNextSlaveJSON(ws, &resp); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			return nil, fmt.Errorf("读取 miaospeed 响应失败: %w", err)
		}
		if log != nil {
			log.Debug("收到 miaospeed 响应", "has_result", resp.Result != nil, "error", resp.Error)
		}

		if resp.Error != "" {
			return nil, fmt.Errorf("miaospeed 任务执行报错: %s", resp.Error)
		}

		if resp.Result != nil {
			report := parseSlaveTaskResult(resp.Result, nodes, plan, time.Since(startTime))
			return report, nil
		}
	}

	return nil, errors.New("miaospeed 连接已关闭，但未收到结果数据")
}

// parseSlaveTaskResult 将 miaospeed 任务返回结果整理为 MiaospeedReport。
func parseSlaveTaskResult(task *slaveTask, nodes []MiaospeedNode, plan miaospeedTestPlan, duration time.Duration) *MiaospeedReport {
	report := &MiaospeedReport{
		TestMode:        plan.ModeDescription,
		DownloadThreads: int(plan.DownloadThreading),
		DurationMs:      duration.Milliseconds(),
		RawResults:      task.Results,
	}
	if len(nodes) > 0 {
		report.NodeName = nodes[0].Name
		report.Protocol = nodes[0].Protocol
		report.Server = nodes[0].Server
	}

	if len(task.Results) == 0 {
		return report
	}

	slot := task.Results[0]
	for _, m := range slot.Matrices {
		switch m.Type {
		case matrixRTTPing:
			report.PingRTTMs = parseMatrixFloat(m.Payload)
		case matrixHTTPPing:
			report.PingConnMs = parseMatrixFloat(m.Payload)
		case matrixPacketLoss:
			report.PacketLoss = parseMatrixFloat(m.Payload)
		case matrixMaxRTTPing:
			report.MaxRTTMs = parseMatrixFloat(m.Payload)
		case matrixHTTPCode:
			report.HTTPCode = parseMatrixHTTPCode(m.Payload)
		case matrixUDPType:
			report.UDPType = parseMatrixString(m.Payload)
		case matrixInboundGeoIP:
			_, report.InboundGeo = parseMatrixGeo(m.Payload)
		case matrixOutboundGeoIP:
			report.OutboundIP, report.OutboundGeo = parseMatrixGeo(m.Payload)
		case matrixHijack:
			report.Hijack = parseMatrixHijack(m.Payload)
		case matrixAverageSpeed:
			report.AvgSpeedBps = parseMatrixFloat(m.Payload)
		case matrixMaxSpeed:
			report.MaxSpeedBps = parseMatrixFloat(m.Payload)
		}
	}

	return report
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
		if geo == "" && stacks.Domain != "" {
			geo = stacks.Domain
		}
		if ip != "" || geo != "" {
			return ip, geo
		}
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

// readNextSlaveJSON 从 ws 连接中读取下一条完整的 JSON 响应并反序列化。
func readNextSlaveJSON(ws *websocket.Conn, dest any) error {
	var buf bytes.Buffer
	chunk := make([]byte, 4096)
	for {
		n, err := ws.Read(chunk)
		if n > 0 {
			buf.Write(chunk[:n])
			b := bytes.TrimSpace(buf.Bytes())
			if len(b) > 0 && b[0] == '{' && b[len(b)-1] == '}' {
				if jsonErr := json.Unmarshal(b, dest); jsonErr == nil {
					return nil
				}
			}
		}
		if err != nil {
			if buf.Len() > 0 {
				if jsonErr := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), dest); jsonErr == nil {
					return nil
				}
			}
			return err
		}
	}
}
