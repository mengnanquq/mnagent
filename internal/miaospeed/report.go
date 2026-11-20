package miaospeed

import (
	"container/list"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mengnanquq/mnagent/internal/probe"
)

// MiaospeedReport 包含测速任务的结构化结果。
type MiaospeedReport struct {
	TotalNodes       int               `json:"total_nodes,omitempty"`
	TestMode         string            `json:"test_mode,omitempty"`
	MiaospeedVersion string            `json:"miaospeed_version,omitempty"`
	NodeName         string            `json:"node_name"`
	Protocol         string            `json:"protocol,omitempty"`
	Server           string            `json:"server,omitempty"`
	URL              string            `json:"url,omitempty"`
	HTTPCode         int               `json:"http_code,omitempty"`
	PingRTTMs        float64           `json:"ping_rtt_ms,omitempty"`
	PingConnMs       float64           `json:"ping_conn_ms,omitempty"`
	MaxRTTMs         float64           `json:"max_rtt_ms,omitempty"`
	PacketLoss       float64           `json:"packet_loss_pct,omitempty"`
	UDPType          string            `json:"udp_type,omitempty"`
	DownloadThreads  int               `json:"download_threads,omitempty"`
	AvgSpeedBps      float64           `json:"avg_speed_bps,omitempty"` // 字节/秒
	MaxSpeedBps      float64           `json:"max_speed_bps,omitempty"` // 字节/秒
	InboundGeo       string            `json:"inbound_geo,omitempty"`
	OutboundIP       string            `json:"outbound_ip,omitempty"`
	OutboundGeo      string            `json:"outbound_geo,omitempty"`
	Hijack           string            `json:"hijack,omitempty"`
	MediaUnlock      map[string]string `json:"media_unlock,omitempty"`
	SubReports       []MiaospeedReport `json:"sub_reports,omitempty"`
	DurationMs       int64             `json:"duration_ms"`
}

// Format 格式化排版文本，供 Telegram 机器人展示。
func (r MiaospeedReport) Format() string {
	var b strings.Builder
	title := "⚡ MiaoSpeed 测速报告"
	if r.MiaospeedVersion != "" {
		v := r.MiaospeedVersion
		if !strings.HasPrefix(strings.ToLower(v), "v") {
			v = "v" + v
		}
		title = fmt.Sprintf("⚡ MiaoSpeed %s 测速报告", v)
	}
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
		b.WriteString(fmt.Sprintf("目标: %s\n", maskIP(r.Server)))
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
			b.WriteString(fmt.Sprintf("  - 入站: %s\n", maskIP(r.InboundGeo)))
		}
		if r.OutboundGeo != "" {
			b.WriteString(fmt.Sprintf("  - 出站: %s\n", maskIP(r.OutboundGeo)))
		}
		if r.Hijack != "" {
			b.WriteString(fmt.Sprintf("  - 劫持检测: %s\n", r.Hijack))
		}
	}

	if len(r.MediaUnlock) > 0 {
		b.WriteString("流媒体解锁:\n")
		for _, name := range []string{"YouTube", "Netflix", "Disney+", "Prime Video", "Spotify", "OpenAI", "Claude", "Google Gemini", "动画疯", "Bilibili", "TikTok", "维基百科"} {
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

// parseSingleSlot 提取单个节点的 slot 数据为 MiaospeedReport。
// 保留无 ctx 包装供旧调用与测试使用；实际查询走 parseSingleSlotContext。
func parseSingleSlot(slot slaveEntrySlot, node *MiaospeedNode, plan miaospeedTestPlan) MiaospeedReport {
	return parseSingleSlotContext(context.Background(), slot, node, plan)
}

// reportNodeURL 返回报告里的节点代理 URL。
// Clash/Sing-box 解析阶段不再为每个候选节点生成 NodeURL（几千个节点时 URL 拼接
// 会额外复制大量字符串），只在实际产出报告时按需生成；原生 URI 节点已经带 URL。
func reportNodeURL(node *MiaospeedNode) string {
	if node == nil {
		return ""
	}
	if node.URL != "" {
		return node.URL
	}
	// node.Server 保留的是解析时的原始主机名（域名节点不会被 pinNodeServerIP 改写），
	// payload 里的 server 则已被钉死为校验过的 IP；生成链接必须优先用原始域名。
	server := extractHost(node.Server)
	port := extractField(node.Payload, "port")
	if port == "" {
		if _, p, err := net.SplitHostPort(node.Server); err == nil {
			port = p
		}
	}
	if server == "" || port == "" {
		if payloadServer := extractField(node.Payload, "server"); payloadServer != "" {
			server = payloadServer
		}
		if payloadPort := extractField(node.Payload, "port"); payloadPort != "" {
			port = payloadPort
		}
	}
	return formatClashPayloadToURI(node.Payload, node.Name, node.Protocol, server, port)
}

// parseSingleSlotContext 带 ctx 解析节点结果，GeoIP 查询可随任务取消立即返回。
func parseSingleSlotContext(ctx context.Context, slot slaveEntrySlot, node *MiaospeedNode, plan miaospeedTestPlan) MiaospeedReport {
	rep := MiaospeedReport{
		TestMode:        plan.ModeDescription,
		DownloadThreads: int(plan.DownloadThreading),
		MediaUnlock:     make(map[string]string),
	}
	if node != nil {
		rep.NodeName = node.Name
		rep.Protocol = node.Protocol
		rep.Server = node.Server
		rep.URL = reportNodeURL(node)
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
			inIP, inGeo := parseMatrixGeo(m.Payload)
			rep.InboundGeo = inGeo
			// 若 miaospeed 原生未能解析入站 Geo，或仅返回了裸国别简写（如 "TW"、"CN"）而缺少详细 ISP，从节点 server 主动提取并解析入站 Geo
			if rep.InboundGeo == rep.NodeName || rep.InboundGeo == rep.Server || rep.InboundGeo == "" || len(strings.TrimSpace(rep.InboundGeo)) <= 3 || !strings.Contains(rep.InboundGeo, " ") {
				if node != nil && node.Server != "" && !isLocalHost(node.Server) {
					sHost := extractHost(node.Server)
					if resolvedIP, resolvedGeo := queryIPGeo(ctx, sHost); resolvedGeo != "" && resolvedGeo != "本地直连" {
						rep.InboundGeo = resolvedGeo
						if resolvedIP != "" {
							inIP = resolvedIP
						}
					}
				}
				if rep.InboundGeo == rep.NodeName || rep.InboundGeo == rep.Server {
					rep.InboundGeo = ""
				}
			}
			if inIP != "" && rep.InboundGeo != "" && !strings.Contains(rep.InboundGeo, inIP) && !strings.Contains(rep.InboundGeo, "(") {
				rep.InboundGeo = fmt.Sprintf("%s (%s)", rep.InboundGeo, inIP)
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

	if rep.InboundGeo == "" && node != nil && node.Server != "" && !isLocalHost(node.Server) {
		sHost := extractHost(node.Server)
		if resolvedIP, resolvedGeo := queryIPGeo(ctx, sHost); resolvedGeo != "" && resolvedGeo != "本地直连" {
			rep.InboundGeo = resolvedGeo
			if resolvedIP != "" && !strings.Contains(rep.InboundGeo, resolvedIP) && !strings.Contains(rep.InboundGeo, "(") {
				rep.InboundGeo = fmt.Sprintf("%s (%s)", rep.InboundGeo, resolvedIP)
			}
		}
	}

	// 出站 GeoIP 兜底 1: 出站 IP 有值但 OutboundGeo 为空时，通过本地 IP 归属地库查询
	if rep.OutboundGeo == "" && rep.OutboundIP != "" && !isLocalHost(rep.OutboundIP) {
		if _, resolvedGeo := queryIPGeo(ctx, rep.OutboundIP); resolvedGeo != "" && resolvedGeo != "本地直连" {
			rep.OutboundGeo = resolvedGeo
		}
	}

	// 出站 GeoIP 兜底 2: 流媒体专测或普通测速中 OutboundGeo 仍为空时，从流媒体成功探测出的地区代码中智能推导
	if rep.OutboundGeo == "" && len(rep.MediaUnlock) > 0 {
		if inferred := inferOutboundGeoFromMedia(rep.MediaUnlock); inferred != "" {
			rep.OutboundGeo = inferred
		}
	}

	if rep.OutboundIP != "" && rep.OutboundGeo != "" && !strings.Contains(rep.OutboundGeo, rep.OutboundIP) && !strings.Contains(rep.OutboundGeo, "(") {
		rep.OutboundGeo = fmt.Sprintf("%s (%s)", rep.OutboundGeo, rep.OutboundIP)
	}

	return rep
}

// inferOutboundGeoFromMedia 从流媒体解锁测试状态文案中智能提取落地国家代码并转换为规范地域。
func inferOutboundGeoFromMedia(media map[string]string) string {
	if len(media) == 0 {
		return ""
	}

	regionNames := map[string]string{
		"HK":  "中国香港 (HK)",
		"HKG": "中国香港 (HK)",
		"TW":  "中国台湾 (TW)",
		"TWN": "中国台湾 (TW)",
		"JP":  "日本 (JP)",
		"JPN": "日本 (JP)",
		"SG":  "新加坡 (SG)",
		"SGP": "新加坡 (SG)",
		"US":  "美国 (US)",
		"USA": "美国 (US)",
		"KR":  "韩国 (KR)",
		"KOR": "韩国 (KR)",
		"GB":  "英国 (GB)",
		"UK":  "英国 (GB)",
		"DE":  "德国 (DE)",
		"DEU": "德国 (DE)",
		"NL":  "荷兰 (NL)",
		"NLD": "荷兰 (NL)",
		"FR":  "法国 (FR)",
		"FRA": "法国 (FR)",
		"CA":  "加拿大 (CA)",
		"CAN": "加拿大 (CA)",
		"AU":  "澳大利亚 (AU)",
		"AUS": "澳大利亚 (AU)",
		"MY":  "马来西亚 (MY)",
		"MYS": "马来西亚 (MY)",
		"TH":  "泰国 (TH)",
		"THA": "泰国 (TH)",
		"VN":  "越南 (VN)",
		"VNM": "越南 (VN)",
		"PH":  "菲律宾 (PH)",
		"PHL": "菲律宾 (PH)",
		"IN":  "印度 (IN)",
		"IND": "印度 (IN)",
		"CN":  "中国 (CN)",
		"CHN": "中国 (CN)",
	}

	// 按可信度顺序探测：优先参考 YouTube, Netflix, Prime Video, Gemini, TikTok, 动画疯
	priorityKeys := []string{"YouTube", "Netflix", "Prime Video", "Google Gemini", "TikTok", "动画疯"}
	for _, key := range priorityKeys {
		st, ok := media[key]
		if !ok || st == "" {
			continue
		}
		// 提取形如 (HK), (JP), (JPN), (United States) 的括号内容
		re := regexp.MustCompile(`\(([^)]+)\)`)
		matches := re.FindAllStringSubmatch(st, -1)
		for _, m := range matches {
			if len(m) > 1 {
				code := strings.ToUpper(strings.TrimSpace(m[1]))
				if name, exists := regionNames[code]; exists {
					return name
				}
				if strings.Contains(strings.ToLower(code), "united states") {
					return "美国 (US)"
				}
			}
		}
	}

	// 次优先检查其他所有流媒体平台
	for _, st := range media {
		re := regexp.MustCompile(`\(([A-Za-z]{2,4})\)`)
		if m := re.FindStringSubmatch(st); len(m) > 1 {
			code := strings.ToUpper(m[1])
			if name, exists := regionNames[code]; exists {
				return name
			}
		}
	}

	return ""
}

// parseSlaveTaskResult 将 miaospeed 任务返回结果整理为 MiaospeedReport。
func parseSlaveTaskResult(task *slaveTask, nodes []MiaospeedNode, totalNodes int, plan miaospeedTestPlan, duration time.Duration) *MiaospeedReport {
	return parseSlaveTaskResultContext(context.Background(), task, nodes, totalNodes, plan, duration)
}

// parseSlaveTaskResultContext 带 ctx 整理测速结果；逐节点 GeoIP 查询使用受限并发（4），
// 避免数百个节点串行查询导致报告长时间无法生成。
func parseSlaveTaskResultContext(ctx context.Context, task *slaveTask, nodes []MiaospeedNode, totalNodes int, plan miaospeedTestPlan, duration time.Duration) *MiaospeedReport {
	// TotalNodes 保持原始订阅总数，而不是本次实测结果数：机器人侧在
	// TotalNodes > len(SubReports) 时会显示“已测 M 个 / 订阅共 N 个”，
	// 能正确表达节点上限截断或部分节点未返回结果，不需要新增协议字段。
	if totalNodes <= 0 {
		totalNodes = len(nodes)
	}
	if len(task.Results) == 0 {
		var n *MiaospeedNode
		if len(nodes) > 0 {
			n = &nodes[0]
		}
		rep := parseSingleSlotContext(ctx, slaveEntrySlot{}, n, plan)
		rep.TotalNodes = totalNodes
		rep.DurationMs = duration.Milliseconds()
		return &rep
	}

	reports := parseSlotsConcurrently(ctx, task.Results, nodes, plan)
	mainRep := reports[0]
	mainRep.TotalNodes = totalNodes
	mainRep.DurationMs = duration.Milliseconds()

	// 多节点结果同步封装为 SubReports（保持与 task.Results 相同顺序）。
	if len(reports) > 1 {
		mainRep.SubReports = make([]MiaospeedReport, 0, len(reports))
		for _, sub := range reports {
			sub.DurationMs = duration.Milliseconds()
			sub.TotalNodes = totalNodes
			mainRep.SubReports = append(mainRep.SubReports, sub)
		}
	}

	return &mainRep
}

// parseSlotsConcurrently 以固定并发度解析节点结果，输出顺序与输入一致。
func parseSlotsConcurrently(ctx context.Context, slots []slaveEntrySlot, nodes []MiaospeedNode, plan miaospeedTestPlan) []MiaospeedReport {
	reports := make([]MiaospeedReport, len(slots))
	if len(slots) == 0 {
		return reports
	}
	sem := make(chan struct{}, geoLookupWorkers)
	var wg sync.WaitGroup
	for i := range slots {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				// 任务已取消：仍生成基础报告（ctx 已取消，远程 GeoIP 查询会立即跳过），
				// 保证已收到的进度不丢失。
				reports[i] = parseSingleSlotContext(ctx, slots[i], nodeAt(nodes, i), plan)
				return
			}
			reports[i] = parseSingleSlotContext(ctx, slots[i], nodeAt(nodes, i), plan)
		}(i)
	}
	wg.Wait()
	return reports
}

func nodeAt(nodes []MiaospeedNode, i int) *MiaospeedNode {
	if i < 0 || i >= len(nodes) {
		return nil
	}
	return &nodes[i]
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

// extractHost 从形如 "host:port" 或 "[ipv6]:port" 中提取纯主机名或 IP。
func extractHost(addr string) string {
	addr = strings.TrimSpace(addr)
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return strings.Trim(h, "[]")
	}
	return strings.Trim(addr, "[]")
}

// isLocalHost 判断地址是否为本地回环或未指定地址。
func isLocalHost(addr string) bool {
	h := extractHost(addr)
	if h == "" || h == "localhost" || h == "127.0.0.1" || h == "::1" || h == "0.0.0.0" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && (ip.IsLoopback() || ip.IsUnspecified())
}

const (
	// geoCacheMaxEntries 限制 GeoIP 缓存条目数，低内存设备上也不会无限增长。
	geoCacheMaxEntries = 512
	// geoCacheTTL 让缓存定期失效，避免 IP 归属地变化后长期展示旧数据。
	geoCacheTTL = 30 * time.Minute
	// geoLookupWorkers 限制报告生成时并发查询 GeoIP 的节点数。
	geoLookupWorkers = 4
	// geoRateLimitCooldown 是 GeoIP 数据源被限流（HTTP 429）后的冷却时长。
	// 一个批次里往往有很多节点指向同一出口，冷却期内直接跳过该数据源，
	// 避免每次都吃一个 429 白白拖慢整批报告。
	geoRateLimitCooldown = 10 * time.Minute
)

// geoHTTPClient 是 GeoIP 查询共享的包级客户端，复用连接并统一超时。
var geoHTTPClient = &http.Client{Timeout: 3 * time.Second}

type geoCacheEntry struct {
	ip      string
	geo     string
	expires time.Time
	elem    *list.Element
}

type geoIPCache struct {
	mu       sync.Mutex
	entries  map[string]*geoCacheEntry
	order    *list.List // 前端最新、后端最旧
	capacity int
	ttl      time.Duration
	now      func() time.Time
}

func newGeoIPCache(capacity int, ttl time.Duration) *geoIPCache {
	return &geoIPCache{
		entries:  make(map[string]*geoCacheEntry),
		order:    list.New(),
		capacity: capacity,
		ttl:      ttl,
		now:      time.Now,
	}
}

var defaultGeoCache = newGeoIPCache(geoCacheMaxEntries, geoCacheTTL)

// geoCooldown 记录某个 GeoIP 数据源被限流后的冷却截止时间。
type geoCooldown struct {
	mu    sync.Mutex
	until time.Time
	now   func() time.Time
}

// active 报告冷却期是否仍在进行。
func (c *geoCooldown) active() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now().Before(c.until)
}

// block 从现在起进入（或延长到）至少一个完整冷却期。
func (c *geoCooldown) block(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if until := c.now().Add(d); until.After(c.until) {
		c.until = until
	}
}

// geoIPAPICooldown 是 ipapi.co 的限流冷却状态。
var geoIPAPICooldown = &geoCooldown{now: time.Now}

// geoCall 是一次进行中的 GeoIP 查询；done 关闭后其字段对等待者可见。
type geoCall struct {
	done chan struct{}
	// waiters 是正在等待共享结果的调用方数量（受 geoInflight.mu 保护）。
	// 它不参与业务逻辑，仅用于观测合并效果，也让测试可以用条件同步代替 sleep。
	waiters int
	ip      string
	geo     string
}

// geoInflight 合并同一 IP 的并发 GeoIP 查询（手写 singleflight，避免引入新依赖）。
// 首个调用方执行查询，其余等待者共享同一结果，避免同一 IP 被并发打到外部接口。
type geoInflight struct {
	mu    sync.Mutex
	calls map[string]*geoCall
}

// do 在 key 上执行 fn；相同 key 的并发调用只执行一次 fn。
// 等待者尊重自己的 ctx：ctx 取消时立即返回，不再等共享结果。
func (g *geoInflight) do(ctx context.Context, key string, fn func(context.Context) (string, string)) (string, string) {
	g.mu.Lock()
	if call, ok := g.calls[key]; ok {
		call.waiters++
		g.mu.Unlock()
		defer func() {
			g.mu.Lock()
			call.waiters--
			g.mu.Unlock()
		}()
		select {
		case <-call.done:
			return call.ip, call.geo
		case <-ctx.Done():
			return "", ""
		}
	}
	call := &geoCall{done: make(chan struct{})}
	if g.calls == nil {
		g.calls = make(map[string]*geoCall)
	}
	g.calls[key] = call
	g.mu.Unlock()

	// 共享查询沿用发起者的 ctx：发起者取消时所有等待者一起结束，
	// 保证任务取消能立即生效，也不会遗留后台 goroutine。
	ip, geo := fn(ctx)
	call.ip, call.geo = ip, geo
	g.mu.Lock()
	delete(g.calls, key)
	g.mu.Unlock()
	close(call.done)
	return ip, geo
}

var defaultGeoInflight = &geoInflight{calls: make(map[string]*geoCall)}

func (c *geoIPCache) get(key string) (ip, geo string, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return "", "", false
	}
	if !entry.expires.After(c.now()) {
		c.removeLocked(key, entry)
		return "", "", false
	}
	c.order.MoveToFront(entry.elem)
	return entry.ip, entry.geo, true
}

func (c *geoIPCache) put(key, ip, geo string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry, ok := c.entries[key]; ok {
		entry.ip, entry.geo = ip, geo
		entry.expires = c.now().Add(c.ttl)
		c.order.MoveToFront(entry.elem)
		return
	}
	entry := &geoCacheEntry{ip: ip, geo: geo, expires: c.now().Add(c.ttl)}
	entry.elem = c.order.PushFront(key)
	c.entries[key] = entry
	for len(c.entries) > c.capacity {
		back := c.order.Back()
		if back == nil {
			break
		}
		oldKey := back.Value.(string)
		c.removeLocked(oldKey, c.entries[oldKey])
	}
}

func (c *geoIPCache) removeLocked(key string, entry *geoCacheEntry) {
	if entry == nil {
		return
	}
	if entry.elem != nil {
		c.order.Remove(entry.elem)
	}
	delete(c.entries, key)
}

// queryIPGeo 主动查询 IP 或域名的地理位置与运营商（带 LRU + TTL 内存缓存）。
// ctx 取消时立即返回，不再继续访问外部 GeoIP 服务。
func queryIPGeo(ctx context.Context, host string) (ip, geo string) {
	cleanHost := extractHost(host)
	if cleanHost == "" {
		return "", ""
	}
	if ctx == nil {
		ctx = context.Background()
	}
	parsedIP := net.ParseIP(cleanHost)
	if label := geoBlockedLabel(parsedIP); label != "" {
		return cleanHost, label
	}
	if cachedIP, cachedGeo, ok := defaultGeoCache.get(cleanHost); ok {
		return cachedIP, cachedGeo
	}

	targetIP := resolveGeoLookupIP(ctx, cleanHost, parsedIP)
	// 域名解析出的地址同样不能外发：私有/链路本地/云元数据地址既没有公开地理信息，
	// 把内网拓扑发给第三方 GeoIP 服务也没有任何好处。
	if label := geoBlockedLabel(net.ParseIP(targetIP)); label != "" {
		return targetIP, label
	}
	if ctx.Err() != nil {
		// 任务已取消：不再访问外部 GeoIP 服务，直接用解析结果兜底。
		return targetIP, targetIP
	}
	// 同一 IP 被多个节点并发引用时只查一次，结果共享给所有等待者。
	ip, geo = defaultGeoInflight.do(ctx, targetIP, func(lookupCtx context.Context) (string, string) {
		return lookupGeoText(lookupCtx, targetIP)
	})
	if ip == "" {
		// 等待共享结果期间被取消：用解析结果兜底，且不写入缓存，
		// 避免把空结果缓存 30 分钟后影响后续任务。
		return targetIP, targetIP
	}
	if geo == "" {
		geo = ip
	}
	defaultGeoCache.put(cleanHost, ip, geo)
	return ip, geo
}

// geoBlockedLabel 判断 IP 是否属于不该发往外部 GeoIP 服务的地址：
// 回环/私网/未指定返回“本地直连”，其余私有/保留/链路本地/云元数据地址返回
// “内网/保留地址”，公网地址返回空串。判定复用探针的 IsBlockedProbeIP，保持一致。
func geoBlockedLabel(ip net.IP) string {
	if ip == nil || !probe.IsBlockedProbeIP(ip) {
		return ""
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() {
		return "本地直连"
	}
	return "内网/保留地址"
}

// resolveGeoLookupIP 把域名解析为 IP；已是 IP 时直接返回。
func resolveGeoLookupIP(ctx context.Context, host string, parsedIP net.IP) string {
	if parsedIP != nil {
		return host
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(lookupCtx, "ip", host)
	if err != nil || len(ips) == 0 {
		return host
	}
	return ips[0].String()
}

// lookupGeoText 依次尝试各 HTTPS GeoIP 数据源，返回最终 IP 与“国家 运营商”文案。
func lookupGeoText(ctx context.Context, targetIP string) (string, string) {
	for _, lookup := range geoLookupFuncs {
		if ctx.Err() != nil {
			break
		}
		resolvedIP, resolvedGeo, ok := lookup(ctx, targetIP)
		if !ok {
			continue
		}
		if resolvedIP != "" {
			targetIP = resolvedIP
		}
		if resolvedGeo != "" {
			return targetIP, resolvedGeo
		}
	}
	return targetIP, ""
}

// geoLookupFuncs 是依次尝试的 GeoIP 数据源，全部使用 HTTPS，避免明文查询泄露节点地址。
var geoLookupFuncs = []func(context.Context, string) (ip, geo string, ok bool){
	lookupGeoIPLeak,
	lookupGeoIPSB,
	lookupGeoIPAPI,
}

type geoAPIResponse struct {
	IP          string `json:"ip"`
	Query       string `json:"query"`
	Country     string `json:"country"`
	CountryName string `json:"country_name"`
	ISP         string `json:"isp"`
	Org         string `json:"org"`
	Error       bool   `json:"error"`
}

// fetchGeoAPI 请求一个 JSON GeoIP 接口，并拼接“国家 运营商”展示文案。
// status 返回 HTTP 状态码（未发出请求或网络错误时为 0），供调用方处理 429 限流。
func fetchGeoAPI(ctx context.Context, apiURL string) (ip, geo string, status int, ok bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return "", "", 0, false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := geoHTTPClient.Do(req)
	if err != nil {
		return "", "", 0, false
	}
	defer resp.Body.Close()
	status = resp.StatusCode
	if status != http.StatusOK {
		return "", "", status, false
	}
	var info geoAPIResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&info); err != nil || info.Error {
		return "", "", status, false
	}
	if info.IP != "" {
		ip = info.IP
	} else if info.Query != "" {
		ip = info.Query
	}
	country := info.CountryName
	if country == "" {
		country = info.Country
	}
	isp := info.ISP
	if isp == "" || isp == country {
		isp = info.Org
	}
	parts := make([]string, 0, 2)
	if country != "" {
		parts = append(parts, country)
	}
	if isp != "" && isp != country {
		parts = append(parts, isp)
	}
	if len(parts) > 0 {
		geo = strings.Join(parts, " ")
	}
	return ip, geo, status, true
}

func lookupGeoIPLeak(ctx context.Context, targetIP string) (string, string, bool) {
	host := "ipv4.ipleak.net"
	if strings.Contains(targetIP, ":") {
		host = "ipv6.ipleak.net"
	}
	ip, geo, _, ok := fetchGeoAPI(ctx, "https://"+host+"/json/"+targetIP)
	return ip, geo, ok
}

func lookupGeoIPSB(ctx context.Context, targetIP string) (string, string, bool) {
	ip, geo, _, ok := fetchGeoAPI(ctx, "https://api.ip.sb/geoip/"+targetIP)
	return ip, geo, ok
}

// lookupGeoIPAPI 查询 ipapi.co；遇到 429 后进入 10 分钟冷却期，冷却期内直接跳过。
func lookupGeoIPAPI(ctx context.Context, targetIP string) (string, string, bool) {
	if geoIPAPICooldown.active() {
		return "", "", false
	}
	ip, geo, status, ok := fetchGeoAPI(ctx, "https://ipapi.co/"+targetIP+"/json/")
	if status == http.StatusTooManyRequests {
		geoIPAPICooldown.block(geoRateLimitCooldown)
	}
	return ip, geo, ok
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

// maskIP 对 IP 或包含 "地域 (IP)" 格式的字符串进行脱敏处理。
func maskIP(ip string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" || ip == "---" {
		return ip
	}

	if start := strings.LastIndex(ip, "("); start != -1 {
		if end := strings.LastIndex(ip, ")"); end > start {
			prefix := ip[:start+1]
			innerIP := ip[start+1 : end]
			suffix := ip[end:]
			return prefix + maskIP(innerIP) + suffix
		}
	}

	if host, port, err := net.SplitHostPort(ip); err == nil {
		return net.JoinHostPort(maskIP(host), port)
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		if strings.Contains(ip, ".") {
			parts := strings.Split(ip, ".")
			if len(parts) == 4 {
				return parts[0] + "." + parts[1] + ".*.*"
			}
		}
		return ip
	}

	if v4 := parsed.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.*.*", v4[0], v4[1])
	}

	if v6 := parsed.To16(); v6 != nil {
		b0 := (uint16(v6[0]) << 8) | uint16(v6[1])
		b1 := (uint16(v6[2]) << 8) | uint16(v6[3])
		return fmt.Sprintf("%x:%x:*:*", b0, b1)
	}

	return ip
}
