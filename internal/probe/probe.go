package probe

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/mengnanquq/mnagent/internal/model"
)

var Version = "dev"

// 探针类型（与机器人侧 internal/agent 的常量保持一致）。
const (
	KindTrace  = "trace" // 默认：远程执行 nexttrace
	KindPing   = "ping"  // ICMP echo
	KindTCPing = "tcping"
	KindHTTP   = "http"
	KindDNS    = "dns"
)

// 探针默认参数与上限。
const (
	defaultPingCount   = 4
	defaultTCPingCount = 4
	maxProbeCount      = 20
	probeInterval      = time.Second
	pingPayloadSize    = 32
	httpMaxBodyBytes   = 8 << 10 // 默认诊断模式读取字节数
	httpMaxRedirects   = 5
)

// LatencyAttempt 是一次延迟探测的结果（ping 与 tcping 共用）。
type LatencyAttempt struct {
	Index int     `json:"index"`
	OK    bool    `json:"ok"`
	RTTms float64 `json:"rtt_ms"`
	Error string  `json:"error,omitempty"`
}

// LatencyReport 是 ping / tcping 的结构化结果。
type LatencyReport struct {
	Kind     string           `json:"kind"`
	Target   string           `json:"target"`
	Resolved string           `json:"resolved,omitempty"`
	Sent     int              `json:"sent"`
	Recv     int              `json:"recv"`
	Loss     float64          `json:"loss_pct"`
	MinMs    float64          `json:"min_ms"`
	AvgMs    float64          `json:"avg_ms"`
	MaxMs    float64          `json:"max_ms"`
	JitterMs float64          `json:"jitter_ms"`
	Attempts []LatencyAttempt `json:"attempts"`
}

// HTTPReport 是 HTTP 拨测的结构化结果（各阶段耗时便于定位瓶颈）。
type HTTPReport struct {
	URL         string            `json:"url"`
	Status      int               `json:"status"`
	StatusText  string            `json:"status_text,omitempty"`
	RemoteIP    string            `json:"remote_ip,omitempty"`
	TLS         bool              `json:"tls"`
	CertExpiry  string            `json:"cert_expiry,omitempty"`
	Redirects   int               `json:"redirects"`
	DNSMs       float64           `json:"dns_ms"`
	ConnectMs   float64           `json:"connect_ms"`
	TLSHandMs   float64           `json:"tls_ms"`
	TTFBMs      float64           `json:"ttfb_ms"`
	TotalMs     float64           `json:"total_ms"`
	BodySnippet string            `json:"body_snippet,omitempty"`
	Proto       string            `json:"proto,omitempty"`
	TLSVersion  string            `json:"tls_version,omitempty"`
	CertIssuer  string            `json:"cert_issuer,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
}

// DNSReport 是 DNS 查询的结构化结果。
type DNSReport struct {
	Host      string   `json:"host"`
	Type      string   `json:"type"`
	Records   []string `json:"records"`
	ElapsedMs float64  `json:"elapsed_ms"`
}

// Outcome 是探针执行的统一产物：结构化结果 + 简短文本（供日志/兜底展示）。
type Outcome struct {
	Data   json.RawMessage
	Output string
}

// probeKind 归一化任务类型；空值按 trace 处理（兼容旧版机器人）。
func ProbeKind(job model.Job) string {
	return job.NormalizedKind()
}

// isProbeKind 判断是否为进程内探针（非 nexttrace）。
func IsProbeKind(kind string) bool {
	switch kind {
	case KindPing, KindTCPing, KindHTTP, KindDNS:
		return true
	default:
		return false
	}
}

// normalizeCount 把次数夹到合理区间。
func normalizeCount(count int) int {
	if count <= 0 {
		return defaultPingCount
	}
	if count > maxProbeCount {
		return maxProbeCount
	}
	return count
}

// isBlockedProbeIP 判断 IP 是否属于回环、私有网段、链路本地、运营商级 NAT 或云实例元数据地址，防范 SSRF。
func IsBlockedProbeIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		return isBlockedIPv4(ip4)
	}
	ip16 := ip.To16()
	if ip16 == nil {
		// fail-closed：不是合法 IPv4/IPv6 的地址（异常长度/畸形 IP）无法判定，
		// 一律按拦截处理，绝不因为“判断不了”就放行。
		return true
	}
	// IPv4 兼容地址 ::/96（::a.b.c.d）：Go 的 To4 不识别，但内核/部分库会把它当作 IPv4 使用。
	// 只按内嵌 IPv4 判定，不能整段拦截：公网 IPv4 的兼容地址本身并不指向内网。
	if isZeroIPBytes(ip16[:12]) {
		return isBlockedIPv4(ip16[12:16])
	}
	// NAT64 知名前缀 64:ff9b::/96：解出低 32 位内嵌 IPv4 后递归判定。
	// IPv6-only + NAT64 网络里所有公网 IPv4 都会表现为该前缀，整段拦截会误伤全部探测。
	if ip16[0] == 0x00 && ip16[1] == 0x64 && ip16[2] == 0xff && ip16[3] == 0x9b {
		if ip16[4] == 0x00 && ip16[5] == 0x01 { // 64:ff9b:1::/48 为本地使用前缀，保持整段拦截
			return true
		}
		if isZeroIPBytes(ip16[4:12]) { // 64:ff9b::/96
			return isBlockedIPv4(ip16[12:16])
		}
	}
	// 6to4 2002::/16：第 2-5 字节是内嵌 IPv4，按内嵌地址判定（2002::/16 本身不是内网）。
	if ip16[0] == 0x20 && ip16[1] == 0x02 {
		return isBlockedIPv4(ip16[2:6])
	}
	// Teredo 2001:0000::/32 的地址里是对端/客户端 IPv4 与端口，无法安全映射为单一目标，保持整段拦截。
	// 注意只匹配 2001:0000::/32，普通的 2001:db8:: 等公网 IPv6 不受影响。
	if ip16[0] == 0x20 && ip16[1] == 0x01 && ip16[2] == 0x00 && ip16[3] == 0x00 {
		return true
	}
	return false
}

// isBlockedIPv4 判断 4 字节 IPv4 地址是否属于保留/内网/元数据网段。
// IPv4 兼容地址、NAT64、6to4 的内嵌地址统一走这里，保证各入口判定一致。
func isBlockedIPv4(ip4 net.IP) bool {
	if len(ip4) < 4 {
		return true
	}
	switch {
	case ip4[0] == 0: // 0.0.0.0/8（“本网络”，常被解析成 0.x 绕过回环判断）
		return true
	case ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127: // 100.64.0.0/10 (CGNAT)
		return true
	case ip4[0] == 169 && ip4[1] == 254: // 169.254.0.0/16 (Link-local / Cloud Metadata)
		return true
	case ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 0: // 192.0.0.0/24（IETF 协议分配）
		return true
	case ip4[0] == 198 && (ip4[1] == 18 || ip4[1] == 19): // 198.18.0.0/15（基准测试保留）
		return true
	case ip4[0] >= 240: // 240.0.0.0/4（含 255.255.255.255 广播）
		return true
	}
	// 复用标准库判定回环/私有/链路本地（内嵌地址同样适用）。
	return net.IP(ip4).IsLoopback() || net.IP(ip4).IsPrivate() || net.IP(ip4).IsLinkLocalUnicast()
}

// isZeroIPBytes 判断字节切片是否全为 0。
func isZeroIPBytes(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// runProbe 执行一次进程内探针。这些探针不依赖任何外部二进制，
// 因此 OpenWrt 等精简系统上也能直接用。
func RunProbe(ctx context.Context, job model.Job, allowPrivate bool) (Outcome, error) {
	switch ProbeKind(job) {
	case KindPing:
		report, err := PingProbe(ctx, job, allowPrivate)
		return marshalProbe(report, err)
	case KindTCPing:
		report, err := TCPingProbe(ctx, job, allowPrivate)
		return marshalProbe(report, err)
	case KindHTTP:
		report, err := HTTPProbe(ctx, job, allowPrivate)
		return marshalProbe(report, err)
	case KindDNS:
		report, err := DNSProbe(ctx, job, allowPrivate)
		return marshalProbe(report, err)
	default:
		return Outcome{}, fmt.Errorf("未知探针类型：%s", job.Kind)
	}
}

// marshalProbe 把报告序列化为 Data，并生成一行简短文本。
// 探测过程中的正常数据（如 ping 丢包）err 为 nil，只有无法执行/连接失败等致命错误 err 非空。
func marshalProbe(report any, err error) (Outcome, error) {
	if err != nil {
		return Outcome{Output: err.Error()}, err
	}
	raw, marshalErr := json.Marshal(report)
	if marshalErr != nil {
		return Outcome{}, marshalErr
	}
	out := Outcome{Data: raw, Output: summarizeProbe(report)}
	return out, nil
}

// summarizeProbe 生成一句话摘要（写日志与兜底展示用）。
func summarizeProbe(report any) string {
	switch r := report.(type) {
	case LatencyReport:
		return fmt.Sprintf("%s %s：%d/%d 成功，平均 %.1f ms，丢包 %.0f%%",
			r.Kind, r.Target, r.Recv, r.Sent, r.AvgMs, r.Loss)
	case HTTPReport:
		return fmt.Sprintf("http %s：%d，总耗时 %.0f ms", r.URL, r.Status, r.TotalMs)
	case DNSReport:
		return fmt.Sprintf("dns %s %s：%d 条记录", r.Host, r.Type, len(r.Records))
	default:
		return ""
	}
}

// ---------- ping ----------

// pingProbe 发送 ICMP echo 并统计延迟。优先使用非特权 ICMP（SOCK_DGRAM），
// 不可用时回退到需要 CAP_NET_RAW 的原始套接字。
func PingProbe(ctx context.Context, job model.Job, allowPrivate bool) (LatencyReport, error) {
	count := normalizeCount(job.Count)
	target := strings.TrimSpace(job.Target)
	timeout := probeTimeout(ctx, job.TimeoutMS)

	resolved, ip, ipv6, err := resolveEchoTarget(ctx, target)
	if err != nil {
		return LatencyReport{}, err
	}
	if !allowPrivate && IsBlockedProbeIP(ip) {
		return LatencyReport{}, fmt.Errorf("安全策略拦截：禁止探测私有或云元数据地址 (%s)", ip.String())
	}
	report := LatencyReport{Kind: KindPing, Target: target, Resolved: resolved, Sent: count}

	// 每次探测使用独立随机载荷（前 8 字节为 cookie），原始套接字可能收到
	// 同机其它 ping 进程的回包，只校验序号/ID 不足以防误判。
	payload := make([]byte, pingPayloadSize)
	if _, err := rand.Read(payload[:8]); err != nil {
		return report, fmt.Errorf("生成 ping 随机载荷失败：%w", err)
	}

	conn, udpSocket, listenErr := ListenICMP(ipv6)
	if listenErr != nil {
		return report, fmt.Errorf("无法创建 ICMP 套接字：%w", listenErr)
	}
	defer conn.Close()

	stopWatch := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-stopWatch:
		}
	}()
	defer close(stopWatch)

	buf := make([]byte, 1500)
	for i := 0; i < count; i++ {
		if ctx.Err() != nil {
			break
		}
		start := time.Now()
		if err := writeEcho(conn, ip, ipv6, udpSocket, i, payload); err != nil {
			report.Attempts = append(report.Attempts, LatencyAttempt{Index: i + 1, Error: err.Error()})
			continue
		}
		deadline := start.Add(timeout)
		_ = conn.SetReadDeadline(deadline)
		attempt := LatencyAttempt{Index: i + 1}
		for {
			n, _, readErr := conn.ReadFrom(buf)
			if readErr != nil {
				attempt.Error = echoErrorText(readErr)
				break
			}
			if !parseEchoReply(buf[:n], ipv6, udpSocket, i, payload) {
				continue // 其它序号/其它报文，继续等待本次回包
			}
			attempt.OK = true
			attempt.RTTms = sinceMs(start)
			break
		}
		report.Attempts = append(report.Attempts, attempt)
		if i < count-1 {
			sleepCtx(ctx, time.Until(start.Add(probeInterval)))
		}
	}
	// 取消或提前退出时，实际尝试次数可能少于计划次数：Sent 必须与明细一致，
	// 否则丢包率会被算成 100%。
	report.Sent = len(report.Attempts)
	fillLatencyStats(&report)
	return report, nil
}

// resolveEchoTarget 解析目标为单个 IP，并返回展示用的解析结果。
func resolveEchoTarget(ctx context.Context, target string) (resolved string, ip net.IP, ipv6 bool, err error) {
	if parsed := net.ParseIP(target); parsed != nil {
		return parsed.String(), parsed, parsed.To4() == nil, nil
	}
	addrs, lookupErr := net.DefaultResolver.LookupIPAddr(ctx, target)
	if lookupErr != nil || len(addrs) == 0 {
		return "", nil, false, fmt.Errorf("解析 %s 失败", target)
	}
	// 优先 IPv4：多数拨测目标是 IPv4，且部分主机没有 IPv6 出口。
	for _, addr := range addrs {
		if addr.IP.To4() != nil {
			return addr.IP.String(), addr.IP, false, nil
		}
	}
	return addrs[0].IP.String(), addrs[0].IP, addrs[0].IP.To4() == nil, nil
}

// listenICMP 依次尝试非特权 ICMP（ping socket）与需要 CAP_NET_RAW 的原始套接字。
// 返回的 bool 表示是否走非特权套接字：两者的目标地址类型不同（UDPAddr / IPAddr）。
func ListenICMP(isV6 bool) (*icmp.PacketConn, bool, error) {
	var errs []string
	for _, network := range icmpNetworks(isV6) {
		conn, err := icmp.ListenPacket(network, "")
		if err == nil {
			return conn, strings.HasPrefix(network, "udp"), nil
		}
		errs = append(errs, fmt.Sprintf("%s: %v", network, err))
	}
	return nil, false, errors.New(strings.Join(errs, "；"))
}

// icmpNetworks 返回可用的监听方式：先非特权（udp），再原始套接字。
func icmpNetworks(isV6 bool) []string {
	if isV6 {
		return []string{"udp6", "ip6:ipv6-icmp"}
	}
	return []string{"udp4", "ip4:icmp"}
}

// writeEcho 发送一个 echo 请求；序号与随机载荷用于匹配回包。
// 非特权（udp）套接字必须用 *net.UDPAddr，原始套接字用 *net.IPAddr。
func writeEcho(conn *icmp.PacketConn, ip net.IP, isV6, udpSocket bool, seq int, payload []byte) error {
	var typ icmp.Type = ipv4.ICMPTypeEcho
	if isV6 {
		typ = ipv6.ICMPTypeEchoRequest
	}
	message := icmp.Message{
		Type: typ,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  seq,
			Data: payload,
		},
	}
	data, err := message.Marshal(nil)
	if err != nil {
		return err
	}
	if udpSocket {
		_, err = conn.WriteTo(data, &net.UDPAddr{IP: ip})
	} else {
		_, err = conn.WriteTo(data, &net.IPAddr{IP: ip})
	}
	return err
}

// parseEchoReply 判断回包是否为本次请求的 echo reply。
// 往返时间由调用方在本地计时（不依赖回包内容，避免时钟/ID 差异）。
func parseEchoReply(data []byte, isV6, udpSocket bool, seq int, payload []byte) bool {
	proto := 1
	var want icmp.Type = ipv4.ICMPTypeEchoReply
	if isV6 {
		proto = 58
		want = ipv6.ICMPTypeEchoReply
	}
	message, err := icmp.ParseMessage(proto, data)
	if err != nil || message.Type != want {
		return false
	}
	echo, ok := message.Body.(*icmp.Echo)
	if !ok || echo.Seq != seq {
		return false
	}
	// 非特权 ICMP 由内核分配 ID；原始套接字会收到全机 ICMP 报文，需校验进程 ID。
	if !udpSocket && echo.ID != (os.Getpid()&0xffff) {
		return false
	}
	// 校验载荷中的随机 cookie，避免把同机其它 ping 进程的回包算成本次结果。
	if len(payload) > 0 {
		if len(echo.Data) != len(payload) || !bytes.Equal(echo.Data, payload) {
			return false
		}
	}
	return true
}

// echoErrorText 把读超时与其它错误区分开，便于展示。
func echoErrorText(err error) string {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "超时"
	}
	return err.Error()
}

// ---------- tcping ----------

// tcpingProbe 反复建立 TCP 连接，统计握手延迟。
func TCPingProbe(ctx context.Context, job model.Job, allowPrivate bool) (LatencyReport, error) {
	count := normalizeCount(job.Count)
	timeout := probeTimeout(ctx, job.TimeoutMS)
	host := strings.TrimSpace(job.Target)
	port := job.Port
	if strings.Contains(host, ":") {
		if h, p, err := net.SplitHostPort(host); err == nil {
			host = h
			if portNum, pErr := strconv.Atoi(p); pErr == nil && portNum > 0 {
				port = portNum
			}
		}
	}
	// 只剩方括号没有端口的目标（如 [::1]）：先去掉方括号，否则 JoinHostPort
	// 会把 "[::1]" 再包一层拼成 "[[::1]]:443"，连接必然失败。
	host = strings.Trim(host, "[]")
	if port == 0 {
		port = 443
	}
	if port < 1 || port > 65535 {
		return LatencyReport{}, fmt.Errorf("端口非法：%d", port)
	}
	address := net.JoinHostPort(host, strconv.Itoa(port))

	resolved := ""
	if net.ParseIP(host) == nil {
		if ips, err := net.DefaultResolver.LookupIPAddr(ctx, host); err == nil && len(ips) > 0 {
			resolved = ips[0].IP.String()
			for _, addr := range ips {
				if addr.IP.To4() != nil {
					resolved = addr.IP.String()
					break
				}
			}
		}
	}
	if !allowPrivate {
		if ip := net.ParseIP(host); ip != nil {
			if IsBlockedProbeIP(ip) {
				return LatencyReport{}, fmt.Errorf("安全策略拦截：禁止探测私有或云元数据地址 (%s)", ip.String())
			}
		} else if resolved == "" {
			// 解析失败时不能按域名拨号：拨号时的再次解析未经校验，可能指向内网（DNS 重绑定）
			return LatencyReport{}, fmt.Errorf("无法解析目标主机 (%s)", host)
		} else if ip := net.ParseIP(resolved); ip != nil && IsBlockedProbeIP(ip) {
			return LatencyReport{}, fmt.Errorf("安全策略拦截：禁止探测私有或云元数据地址 (%s)", ip.String())
		}
	}
	report := LatencyReport{Kind: KindTCPing, Target: address, Resolved: resolved, Sent: count}

	dialAddress := address
	if resolved != "" {
		dialAddress = net.JoinHostPort(resolved, strconv.Itoa(port))
	}

	dialer := &net.Dialer{Timeout: timeout}
	for i := 0; i < count; i++ {
		if ctx.Err() != nil {
			break
		}
		start := time.Now()
		conn, err := dialer.DialContext(ctx, "tcp", dialAddress)
		rtt := time.Since(start)
		attempt := LatencyAttempt{Index: i + 1}
		if err != nil {
			attempt.Error = shortDialError(err)
		} else {
			attempt.OK = true
			attempt.RTTms = float64(rtt.Microseconds()) / 1000
			conn.Close()
		}
		report.Attempts = append(report.Attempts, attempt)
		if i < count-1 {
			wait := probeInterval - rtt
			if wait < 50*time.Millisecond {
				wait = 50 * time.Millisecond
			}
			sleepCtx(ctx, wait)
		}
	}
	report.Sent = len(report.Attempts)
	fillLatencyStats(&report)
	return report, nil
}

// fillLatencyStats 汇总成功探测的延迟统计。
func fillLatencyStats(report *LatencyReport) {
	var sum float64
	minMs, maxMs := 0.0, 0.0
	for _, attempt := range report.Attempts {
		if !attempt.OK {
			continue
		}
		report.Recv++
		sum += attempt.RTTms
		if minMs == 0 || attempt.RTTms < minMs {
			minMs = attempt.RTTms
		}
		if attempt.RTTms > maxMs {
			maxMs = attempt.RTTms
		}
	}
	if report.Sent > 0 {
		report.Loss = float64(report.Sent-report.Recv) * 100 / float64(report.Sent)
	}
	if report.Recv > 0 {
		report.MinMs, report.MaxMs = minMs, maxMs
		report.AvgMs = sum / float64(report.Recv)
		report.JitterMs = maxMs - minMs
	}
}

// shortDialError 把拨号错误精简为可读原因。
func shortDialError(err error) string {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "DNS 解析失败"
	}
	msg := err.Error()
	if idx := strings.LastIndex(msg, ": "); idx >= 0 {
		msg = strings.TrimPrefix(msg[idx+2:], "connect: ")
	}
	switch msg {
	case "connection refused":
		return "连接被拒绝"
	case "i/o timeout":
		return "连接超时"
	case "network is unreachable":
		return "网络不可达"
	case "no route to host":
		return "无到主机的路由"
	case "context deadline exceeded":
		return "连接超时"
	}
	return msg
}

// ---------- http ----------

// httpPhaseTimings 收集 HTTP 分阶段耗时。httptrace 回调与自定义 DialContext
// 可能在不同 goroutine 上并发执行，所有字段都必须加锁，且只记录首次观测值
// （重定向时会出现多次拨号，报告只展示第一次）。
type httpPhaseTimings struct {
	mu sync.Mutex

	dnsStart, connStart, tlsStart, writeStart time.Time
	dnsMs, connMs, tlsMs, ttfbMs              float64
	dnsSet, connSet, tlsSet, ttfbSet          bool
	remoteAddr                                string
}

func durationMs(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

func (t *httpPhaseTimings) startDNS() {
	t.mu.Lock()
	t.dnsStart = time.Now()
	t.mu.Unlock()
}

func (t *httpPhaseTimings) doneDNS() {
	t.mu.Lock()
	if !t.dnsSet {
		t.dnsSet = true
		t.dnsMs = sinceMs(t.dnsStart)
	}
	t.mu.Unlock()
}

func (t *httpPhaseTimings) observeDNS(d time.Duration) {
	t.mu.Lock()
	if !t.dnsSet {
		t.dnsSet = true
		t.dnsMs = durationMs(d)
	}
	t.mu.Unlock()
}

func (t *httpPhaseTimings) startConnect() {
	t.mu.Lock()
	t.connStart = time.Now()
	t.mu.Unlock()
}

func (t *httpPhaseTimings) doneConnect() {
	t.mu.Lock()
	if !t.connSet {
		t.connSet = true
		t.connMs = sinceMs(t.connStart)
	}
	t.mu.Unlock()
}

func (t *httpPhaseTimings) observeConnect(d time.Duration) {
	t.mu.Lock()
	if !t.connSet {
		t.connSet = true
		t.connMs = durationMs(d)
	}
	t.mu.Unlock()
}

func (t *httpPhaseTimings) startTLS() {
	t.mu.Lock()
	t.tlsStart = time.Now()
	t.mu.Unlock()
}

func (t *httpPhaseTimings) doneTLS() {
	t.mu.Lock()
	if !t.tlsSet {
		t.tlsSet = true
		t.tlsMs = sinceMs(t.tlsStart)
	}
	t.mu.Unlock()
}

func (t *httpPhaseTimings) gotConn(info httptrace.GotConnInfo) {
	t.mu.Lock()
	t.writeStart = time.Now()
	if info.Conn != nil && info.Conn.RemoteAddr() != nil {
		addr := info.Conn.RemoteAddr().String()
		if host, _, err := net.SplitHostPort(addr); err == nil {
			addr = host
		}
		t.remoteAddr = addr
	}
	t.mu.Unlock()
}

func (t *httpPhaseTimings) gotFirstByte() {
	t.mu.Lock()
	if !t.ttfbSet {
		t.ttfbSet = true
		t.ttfbMs = sinceMs(t.writeStart)
	}
	t.mu.Unlock()
}

func (t *httpPhaseTimings) snapshot() (dnsMs, connMs, tlsMs, ttfbMs float64, remoteAddr string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.dnsMs, t.connMs, t.tlsMs, t.ttfbMs, t.remoteAddr
}

// httpProbe 发起一次 HTTP(S) 请求并分阶段计时。
func HTTPProbe(ctx context.Context, job model.Job, allowPrivate bool) (HTTPReport, error) {
	parsed, err := parseHTTPProbeURL(job.Target)
	if err != nil {
		return HTTPReport{}, err
	}
	timeout := probeTimeout(ctx, job.TimeoutMS)
	report := HTTPReport{URL: parsed.String(), TLS: parsed.Scheme == "https"}

	timings := &httpPhaseTimings{}
	start := time.Now()
	reqCtx, cancel := context.WithTimeout(httptrace.WithClientTrace(ctx, newHTTPProbeTrace(timings)), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return report, err
	}
	req.Header.Set("User-Agent", "mnagent/"+Version)

	dialer := &net.Dialer{Timeout: timeout}
	transport := newHTTPProbeTransport(dialer, allowPrivate, timings)
	defer transport.CloseIdleConnections()

	var redirects int
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			redirects = len(via)
			if len(via) >= httpMaxRedirects {
				return errors.New("重定向次数过多")
			}
			return nil
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return HTTPReport{}, errors.New(shortHTTPError(err))
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, httpMaxBodyBytes))
	return buildHTTPReport(report, resp, body, timings, redirects, start), nil
}

// parseHTTPProbeURL 校验并解析 http(s) 目标。
func parseHTTPProbeURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, fmt.Errorf("无效的 URL：%s（需要 http:// 或 https:// 开头）", raw)
	}
	return parsed, nil
}

// newHTTPProbeTrace 绑定分阶段计时回调；所有写入均由 httpPhaseTimings 内的锁保护。
func newHTTPProbeTrace(timings *httpPhaseTimings) *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		DNSStart:             func(httptrace.DNSStartInfo) { timings.startDNS() },
		DNSDone:              func(httptrace.DNSDoneInfo) { timings.doneDNS() },
		ConnectStart:         func(_, _ string) { timings.startConnect() },
		ConnectDone:          func(_, _ string, _ error) { timings.doneConnect() },
		TLSHandshakeStart:    func() { timings.startTLS() },
		TLSHandshakeDone:     func(tls.ConnectionState, error) { timings.doneTLS() },
		GotConn:              func(info httptrace.GotConnInfo) { timings.gotConn(info) },
		GotFirstResponseByte: func() { timings.gotFirstByte() },
	}
}

// newHTTPProbeTransport 构造禁用环境代理的传输层，并在拨号前完成 SSRF 校验。
func newHTTPProbeTransport(dialer *net.Dialer, allowPrivate bool, timings *httpPhaseTimings) *http.Transport {
	return &http.Transport{
		// 明确禁用环境代理：HTTP_PROXY/HTTPS_PROXY 会把请求交给代理，
		// 代理自行解析目标并建立连接，从而完全绕过下面按解析 IP 做的 SSRF 校验。
		Proxy: nil,
		// 自定义 DialContext 会让 net/http 默认关闭 HTTP/2；这里显式打开，
		// 避免探针结果里的协议/耗时与真实客户端（默认 h2）不一致。
		// SNI 仍取自 URL 主机名，握手后按已校验的 IP 连接，SSRF 防护不受影响。
		ForceAttemptHTTP2: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialHTTPProbeTarget(ctx, network, addr, dialer, allowPrivate, timings)
		},
	}
}

// dialHTTPProbeTarget 先解析并校验目标 IP，再按 IP 拨号，避免 DNS 重绑定绕过检查。
func dialHTTPProbeTarget(ctx context.Context, network, addr string, dialer *net.Dialer, allowPrivate bool, timings *httpPhaseTimings) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else {
		dnsT0 := time.Now()
		resolved, lookupErr := net.DefaultResolver.LookupIP(ctx, "ip", host)
		if lookupErr != nil {
			return nil, lookupErr
		}
		timings.observeDNS(time.Since(dnsT0))
		ips = resolved
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("无法解析目标主机: %s", host)
	}
	if !allowPrivate {
		for _, ip := range ips {
			if IsBlockedProbeIP(ip) {
				return nil, fmt.Errorf("安全策略拦截：禁止探测私有或云元数据地址 (%s)", ip.String())
			}
		}
	}

	targetIP := ips[0]
	for _, ip := range ips {
		if ip.To4() != nil {
			targetIP = ip
			break
		}
	}
	connT0 := time.Now()
	c, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(targetIP.String(), port))
	timings.observeConnect(time.Since(connT0))
	return c, dialErr
}

// buildHTTPReport 汇总状态、TLS、耗时、响应头与正文摘要。
func buildHTTPReport(report HTTPReport, resp *http.Response, body []byte, timings *httpPhaseTimings, redirects int, start time.Time) HTTPReport {
	report.Status = resp.StatusCode
	report.StatusText = resp.Status
	report.Redirects = redirects
	report.DNSMs, report.ConnectMs, report.TLSHandMs, report.TTFBMs, report.RemoteIP = timings.snapshot()
	report.Proto = resp.Proto
	report.TotalMs = sinceMs(start)

	if resp.TLS != nil {
		switch resp.TLS.Version {
		case tls.VersionTLS13:
			report.TLSVersion = "TLS 1.3"
		case tls.VersionTLS12:
			report.TLSVersion = "TLS 1.2"
		case tls.VersionTLS11:
			report.TLSVersion = "TLS 1.1"
		default:
			report.TLSVersion = "TLS"
		}
		if len(resp.TLS.PeerCertificates) > 0 {
			cert := resp.TLS.PeerCertificates[0]
			report.CertExpiry = cert.NotAfter.Format("2006-01-02")
			if cert.Issuer.CommonName != "" {
				report.CertIssuer = cert.Issuer.CommonName
			} else if len(cert.Issuer.Organization) > 0 {
				report.CertIssuer = cert.Issuer.Organization[0]
			}
		}
	}
	headers := make(map[string]string)
	for _, k := range []string{"server", "cf-ray", "content-type", "cache-control", "content-encoding", "date", "strict-transport-security"} {
		if val := resp.Header.Get(k); val != "" {
			headers[k] = val
		}
	}
	if len(headers) > 0 {
		report.Headers = headers
	}
	if snippet := strings.TrimSpace(string(body)); snippet != "" {
		report.BodySnippet = strings.TrimSpace(collapseWhitespace(snippet, 120))
	}
	return report
}

// sinceMs 返回自 t 起的毫秒数；t 为零值时返回 0。
func sinceMs(t time.Time) float64 {
	if t.IsZero() {
		return 0
	}
	return float64(time.Since(t).Microseconds()) / 1000
}

// collapseWhitespace 把连续空白折叠为单个空格，并限制长度。
func collapseWhitespace(s string, limit int) string {
	fields := strings.Fields(s)
	joined := strings.Join(fields, " ")
	runes := []rune(joined)
	if len(runes) > limit {
		return string(runes[:limit]) + "…"
	}
	return joined
}

// ---------- dns ----------

// privateDNSNameSuffixes 是不应通过 DNS 探针查询的内网保留后缀。
var privateDNSNameSuffixes = []string{
	".local", ".localhost", ".internal", ".intranet", ".lan",
	".home", ".home.arpa", ".corp", ".localdomain",
}

// parseReverseDNSName 把 in-addr.arpa / ip6.arpa 反向域名还原为 IP。
// 返回 false 表示不是合法的反向域名（标签数量或取值不合法）。
func parseReverseDNSName(name string) (net.IP, bool) {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	switch {
	case strings.HasSuffix(name, ".in-addr.arpa"):
		labels := strings.Split(strings.TrimSuffix(name, ".in-addr.arpa"), ".")
		if len(labels) != 4 {
			return nil, false
		}
		octets := make(net.IP, 4)
		for i, label := range labels {
			n, err := strconv.Atoi(label)
			if err != nil || n < 0 || n > 255 {
				return nil, false
			}
			octets[3-i] = byte(n)
		}
		return octets, true
	case strings.HasSuffix(name, ".ip6.arpa"):
		labels := strings.Split(strings.TrimSuffix(name, ".ip6.arpa"), ".")
		if len(labels) != 32 {
			return nil, false
		}
		ip := make(net.IP, 16)
		for i := range ip {
			hi, okHi := parseHexNibble(labels[31-2*i])
			lo, okLo := parseHexNibble(labels[30-2*i])
			if !okHi || !okLo {
				return nil, false
			}
			ip[i] = hi<<4 | lo
		}
		return ip, true
	}
	return nil, false
}

// parseHexNibble 解析单个十六进制字符。
func parseHexNibble(s string) (byte, bool) {
	if len(s) != 1 {
		return 0, false
	}
	switch c := s[0]; {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	default:
		return 0, false
	}
}

// validateDNSQueryName 在 allowPrivate=false 时做名称级 SSRF 校验：
// 拒绝单标签名、内网保留后缀，以及指向私网/元数据地址的反向解析域名。
// 对 CNAME/MX/NS/TXT 只检查名称本身，不要求能解析出 A 记录。
func validateDNSQueryName(host string) error {
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if net.ParseIP(name) != nil {
		// 字面 IP 的私网判定由调用方完成；公网 IPv6 字面量没有点，不能按单标签拒绝。
		return nil
	}
	if strings.HasSuffix(name, ".in-addr.arpa") || strings.HasSuffix(name, ".ip6.arpa") {
		ip, ok := parseReverseDNSName(name)
		if !ok {
			return fmt.Errorf("安全策略拦截：无法识别的反向解析域名 (%s)", host)
		}
		if IsBlockedProbeIP(ip) {
			return fmt.Errorf("安全策略拦截：禁止查询私有或云元数据地址的反向解析 (%s)", ip.String())
		}
		return nil
	}
	if !strings.Contains(name, ".") {
		return fmt.Errorf("安全策略拦截：禁止查询单标签域名 (%s)", host)
	}
	for _, suffix := range privateDNSNameSuffixes {
		if name == strings.TrimPrefix(suffix, ".") || strings.HasSuffix(name, suffix) {
			return fmt.Errorf("安全策略拦截：禁止查询内网保留域名 (%s)", host)
		}
	}
	return nil
}

// dnsProbe 用主机自身的解析器查询记录，便于对比不同地域/线路的解析结果。
// allowPrivate=false 时与其他探针保持一致的 fail-closed 策略：查询目标本身是私网/元数据
// 地址、或 A/AAAA/ALL 结果中出现这类地址时直接拒绝，不返回任何记录。
// （Job 目前没有单独的“DNS 服务器”字段，解析始终走主机系统解析器；若以后增加该字段，
// 也应在此按 IsBlockedProbeIP 拒绝私网 DNS 服务器。）
func DNSProbe(ctx context.Context, job model.Job, allowPrivate bool) (DNSReport, error) {
	host := strings.TrimSpace(job.Target)
	if host == "" {
		return DNSReport{}, errors.New("缺少查询域名")
	}
	if !allowPrivate {
		if ip := net.ParseIP(host); ip != nil && IsBlockedProbeIP(ip) {
			return DNSReport{}, fmt.Errorf("安全策略拦截：禁止查询私有或云元数据地址 (%s)", ip.String())
		}
		if err := validateDNSQueryName(host); err != nil {
			return DNSReport{}, err
		}
	}
	recordType := strings.ToUpper(strings.TrimSpace(job.Query))
	if recordType == "" {
		recordType = "ALL"
	}
	report := DNSReport{Host: host, Type: recordType}
	start := time.Now()
	queryCtx, cancel := context.WithTimeout(ctx, probeTimeout(ctx, job.TimeoutMS))
	defer cancel()
	resolver := net.DefaultResolver

	add := func(values []string) { report.Records = append(report.Records, values...) }

	switch recordType {
	case "A", "AAAA", "ALL":
		network := "ip"
		if recordType == "A" {
			network = "ip4"
		} else if recordType == "AAAA" {
			network = "ip6"
		}
		ips, err := resolver.LookupIP(queryCtx, network, host)
		if err != nil {
			return report, err
		}
		for _, ip := range ips {
			if !allowPrivate && IsBlockedProbeIP(ip) {
				return report, fmt.Errorf("安全策略拦截：DNS 查询结果包含私有或云元数据地址 (%s)", ip.String())
			}
			add([]string{ip.String()})
		}
	// CNAME / MX / NS 只返回域名，不会去连接或解析这些名字（Go 的 LookupMX/LookupNS
	// 不做二次解析），因此不存在借此探测内网的问题，不需要按 IsBlockedProbeIP 过滤；
	// 真正会拿到 IP 的 A/AAAA/ALL 已在上面的分支逐条校验。
	case "CNAME":
		cname, err := resolver.LookupCNAME(queryCtx, host)
		if err != nil {
			return report, err
		}
		add([]string{cname})
	case "MX":
		records, err := resolver.LookupMX(queryCtx, host)
		if err != nil {
			return report, err
		}
		for _, r := range records {
			add([]string{fmt.Sprintf("%s（优先级 %d）", r.Host, r.Pref)})
		}
	case "NS":
		records, err := resolver.LookupNS(queryCtx, host)
		if err != nil {
			return report, err
		}
		for _, r := range records {
			add([]string{r.Host})
		}
	case "TXT":
		records, err := resolver.LookupTXT(queryCtx, host)
		if err != nil {
			return report, err
		}
		add(records)
	case "PTR":
		// PTR 是对地址的反向解析：输入必须是 IP（可带 IPv6 方括号）或 in-addr.arpa /
		// ip6.arpa 反向域名。其它输入在不同平台上行为不一致（空结果或晦涩的 DNS 错误），
		// 这里提前给出清晰的中文提示。
		ptrHost := strings.Trim(host, "[]")
		if net.ParseIP(ptrHost) == nil {
			ip, ok := parseReverseDNSName(ptrHost)
			if !ok {
				return report, fmt.Errorf("PTR 反向解析需要 IP 地址（如 8.8.8.8、2001:4860:4860::8888）或 in-addr.arpa / ip6.arpa 反向域名，收到：%s", host)
			}
			// LookupAddr 只接受字面 IP；输入是反向域名时先还原成 IP。
			ptrHost = ip.String()
		}
		records, err := resolver.LookupAddr(queryCtx, ptrHost)
		if err != nil {
			return report, err
		}
		add(records)
	default:
		return report, fmt.Errorf("不支持的记录类型：%s", recordType)
	}
	report.ElapsedMs = sinceMs(start)
	return report, nil
}

// probeTimeout 返回单次探测的超时：由任务的 timeout_ms 决定，缺省 15 秒。
func probeTimeout(ctx context.Context, timeoutMS int64) time.Duration {
	timeout := time.Duration(timeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	// 单次探测（一次回包/一次握手）不超过 15 秒，整体由任务超时兜底。
	if timeout > 15*time.Second {
		timeout = 15 * time.Second
	}
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining < timeout {
			timeout = remaining
		}
	}
	if timeout <= 0 {
		timeout = time.Second
	}
	return timeout
}

// sleepCtx 等待指定时长；ctx 结束时提前返回。
func sleepCtx(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

// shortHTTPError 把 HTTP 请求失败的底层错误精简为易读原因。
func shortHTTPError(err error) string {
	if err == nil {
		return ""
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "连接超时"
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "context deadline exceeded") || strings.Contains(msg, "i/o timeout"):
		return "连接超时"
	case strings.Contains(msg, "connection refused"):
		return "连接被拒绝"
	case strings.Contains(msg, "connection reset by peer"):
		return "连接被重置"
	case strings.Contains(msg, "no such host"):
		return "DNS 解析失败"
	case strings.Contains(msg, "certificate"):
		return "证书验证失败"
	case strings.Contains(msg, "network is unreachable"):
		return "网络不可达"
	default:
		if len(msg) > 100 {
			msg = msg[:100] + "…"
		}
		return msg
	}
}
