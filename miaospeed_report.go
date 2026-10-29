package main

import (
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
)

// MiaospeedReport 包含测速任务的结构化结果。
type MiaospeedReport struct {
	TotalNodes       int               `json:"total_nodes,omitempty"`
	TestMode         string            `json:"test_mode,omitempty"`
	MiaospeedVersion string            `json:"miaospeed_version,omitempty"`
	NodeName         string            `json:"node_name"`
	Protocol         string            `json:"protocol,omitempty"`
	Server           string            `json:"server,omitempty"`
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
	RawResults       []slaveEntrySlot  `json:"raw_results,omitempty"`
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
			inIP, inGeo := parseMatrixGeo(m.Payload)
			rep.InboundGeo = inGeo
			if rep.InboundGeo == rep.NodeName || rep.InboundGeo == rep.Server || rep.InboundGeo == "" {
				// 若 miaospeed 原生未能解析入站 Geo（如 IPv6 节点因官方核心缺少端口剥离 bug 导致查询失败），从节点 server 主动提取并解析入站 Geo
				if node != nil && node.Server != "" && !isLocalHost(node.Server) {
					sHost := extractHost(node.Server)
					if resolvedIP, resolvedGeo := queryIPGeo(sHost); resolvedGeo != "" && resolvedGeo != "本地直连" {
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
		if resolvedIP, resolvedGeo := queryIPGeo(sHost); resolvedGeo != "" && resolvedGeo != "本地直连" {
			rep.InboundGeo = resolvedGeo
			if resolvedIP != "" && !strings.Contains(rep.InboundGeo, resolvedIP) && !strings.Contains(rep.InboundGeo, "(") {
				rep.InboundGeo = fmt.Sprintf("%s (%s)", rep.InboundGeo, resolvedIP)
			}
		}
	}

	// 出站 GeoIP 兜底 1: 出站 IP 有值但 OutboundGeo 为空时，通过本地 IP 归属地库查询
	if rep.OutboundGeo == "" && rep.OutboundIP != "" && !isLocalHost(rep.OutboundIP) {
		if _, resolvedGeo := queryIPGeo(rep.OutboundIP); resolvedGeo != "" && resolvedGeo != "本地直连" {
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

var (
	geoCacheMu  sync.RWMutex
	geoCacheMap = make(map[string]struct{ ip, geo string })
)

// queryIPGeo 主动查询 IP 或域名的地理位置与运营商（带线程安全内存缓存）。
func queryIPGeo(host string) (ip, geo string) {
	cleanHost := extractHost(host)
	if cleanHost == "" {
		return "", ""
	}
	parsedIP := net.ParseIP(cleanHost)
	if parsedIP != nil && (parsedIP.IsLoopback() || parsedIP.IsPrivate() || parsedIP.IsUnspecified()) {
		return cleanHost, "本地直连"
	}

	geoCacheMu.RLock()
	if cached, ok := geoCacheMap[cleanHost]; ok {
		geoCacheMu.RUnlock()
		return cached.ip, cached.geo
	}
	geoCacheMu.RUnlock()

	targetIP := cleanHost
	if parsedIP == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", cleanHost)
		cancel()
		if err == nil && len(ips) > 0 {
			targetIP = ips[0].String()
		}
	}

	isV6 := strings.Contains(targetIP, ":")
	apiURL := "https://ipv4.ipleak.net/json/" + targetIP
	if isV6 {
		apiURL = "https://ipv6.ipleak.net/json/" + targetIP
	}

	client := &http.Client{Timeout: 3 * time.Second}
	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err == nil {
		req.Header.Set("User-Agent", "Mozilla/5.0")
		resp, err := client.Do(req)
		if err == nil {
			if resp.StatusCode == http.StatusOK {
				var info struct {
					CountryName string `json:"country_name"`
					ISPName     string `json:"isp_name"`
					IP          string `json:"ip"`
				}
				if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&info); err == nil {
					if info.IP != "" {
						targetIP = info.IP
					}
					parts := make([]string, 0, 2)
					if info.CountryName != "" {
						parts = append(parts, info.CountryName)
					}
					if info.ISPName != "" && info.ISPName != info.CountryName {
						parts = append(parts, info.ISPName)
					}
					if len(parts) > 0 {
						geo = strings.Join(parts, " ")
					}
				}
			}
			_ = resp.Body.Close()
		}
	}

	if geo == "" {
		reqSB, err := http.NewRequest(http.MethodGet, "https://api.ip.sb/geoip/"+targetIP, nil)
		if err == nil {
			reqSB.Header.Set("User-Agent", "Mozilla/5.0")
			respSB, err := client.Do(reqSB)
			if err == nil {
				if respSB.StatusCode == http.StatusOK {
					var infoSB struct {
						Country string `json:"country"`
						ISP     string `json:"isp"`
						IP      string `json:"ip"`
					}
					if err := json.NewDecoder(io.LimitReader(respSB.Body, 64*1024)).Decode(&infoSB); err == nil {
						if infoSB.IP != "" {
							targetIP = infoSB.IP
						}
						parts := make([]string, 0, 2)
						if infoSB.Country != "" {
							parts = append(parts, infoSB.Country)
						}
						if infoSB.ISP != "" && infoSB.ISP != infoSB.Country {
							parts = append(parts, infoSB.ISP)
						}
						if len(parts) > 0 {
							geo = strings.Join(parts, " ")
						}
					}
				}
				_ = respSB.Body.Close()
			}
		}
	}

	ip = targetIP
	if geo == "" && ip != "" {
		geo = ip
	}

	geoCacheMu.Lock()
	geoCacheMap[cleanHost] = struct{ ip, geo string }{ip: ip, geo: geo}
	geoCacheMu.Unlock()

	return ip, geo
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
