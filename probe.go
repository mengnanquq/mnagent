package main

import (
	"context"
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
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// 探针类型（与机器人侧 internal/agent 的常量保持一致）。
const (
	kindTrace  = "trace" // 默认：远程执行 nexttrace
	kindPing   = "ping"  // ICMP echo
	kindTCPing = "tcping"
	kindHTTP   = "http"
	kindDNS    = "dns"
)

// 探针默认参数与上限。
const (
	defaultPingCount   = 4
	defaultTCPingCount = 4
	maxProbeCount      = 20
	probeInterval      = time.Second
	pingPayloadSize    = 32
	httpMaxBodyBytes   = 8 << 10 // 只需要响应头与少量正文用于诊断
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
	URL         string  `json:"url"`
	Status      int     `json:"status"`
	StatusText  string  `json:"status_text,omitempty"`
	RemoteIP    string  `json:"remote_ip,omitempty"`
	TLS         bool    `json:"tls"`
	CertExpiry  string  `json:"cert_expiry,omitempty"`
	Redirects   int     `json:"redirects"`
	DNSMs       float64 `json:"dns_ms"`
	ConnectMs   float64 `json:"connect_ms"`
	TLSHandMs   float64 `json:"tls_ms"`
	TTFBMs      float64 `json:"ttfb_ms"`
	TotalMs     float64 `json:"total_ms"`
	BodySnippet string  `json:"body_snippet,omitempty"`
}

// DNSReport 是 DNS 查询的结构化结果。
type DNSReport struct {
	Host      string   `json:"host"`
	Type      string   `json:"type"`
	Records   []string `json:"records"`
	ElapsedMs float64  `json:"elapsed_ms"`
}

// probeOutcome 是探针执行的统一产物：结构化结果 + 简短文本（供日志/兜底展示）。
type probeOutcome struct {
	Data   json.RawMessage
	Output string
}

// probeKind 归一化任务类型；空值按 trace 处理（兼容旧版机器人）。
func probeKind(job Job) string {
	kind := strings.ToLower(strings.TrimSpace(job.Kind))
	if kind == "" {
		return kindTrace
	}
	return kind
}

// isProbeKind 判断是否为进程内探针（非 nexttrace）。
func isProbeKind(kind string) bool {
	switch kind {
	case kindPing, kindTCPing, kindHTTP, kindDNS:
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

// runProbe 执行一次进程内探针。这些探针不依赖任何外部二进制，
// 因此 OpenWrt 等精简系统上也能直接用。
func runProbe(ctx context.Context, job Job) (probeOutcome, error) {
	switch probeKind(job) {
	case kindPing:
		report, err := pingProbe(ctx, job)
		return marshalProbe(report, err)
	case kindTCPing:
		report, err := tcpingProbe(ctx, job)
		return marshalProbe(report, err)
	case kindHTTP:
		report, err := httpProbe(ctx, job)
		return marshalProbe(report, err)
	case kindDNS:
		report, err := dnsProbe(ctx, job)
		return marshalProbe(report, err)
	default:
		return probeOutcome{}, fmt.Errorf("未知探针类型：%s", job.Kind)
	}
}

// marshalProbe 把报告序列化为 Data，并生成一行简短文本。
// 部分失败（如丢包）不算错误：报告本身已包含明细。
func marshalProbe(report any, err error) (probeOutcome, error) {
	raw, marshalErr := json.Marshal(report)
	if marshalErr != nil {
		return probeOutcome{}, marshalErr
	}
	out := probeOutcome{Data: raw, Output: summarizeProbe(report)}
	return out, err
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
func pingProbe(ctx context.Context, job Job) (LatencyReport, error) {
	count := normalizeCount(job.Count)
	target := strings.TrimSpace(job.Target)
	timeout := probeTimeout(ctx, job.TimeoutMS)

	resolved, ip, ipv6, err := resolveEchoTarget(ctx, target)
	if err != nil {
		return LatencyReport{}, err
	}
	report := LatencyReport{Kind: kindPing, Target: target, Resolved: resolved, Sent: count}

	conn, udpSocket, listenErr := listenICMP(ipv6)
	if listenErr != nil {
		return report, fmt.Errorf("无法创建 ICMP 套接字：%w", listenErr)
	}
	defer conn.Close()

	buf := make([]byte, 1500)
	for i := 0; i < count; i++ {
		if ctx.Err() != nil {
			break
		}
		start := time.Now()
		if err := writeEcho(conn, ip, ipv6, udpSocket, i); err != nil {
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
			if !parseEchoReply(buf[:n], ipv6, i) {
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
func listenICMP(isV6 bool) (*icmp.PacketConn, bool, error) {
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

// writeEcho 发送一个 echo 请求；序号用于匹配回包。
// 非特权（udp）套接字必须用 *net.UDPAddr，原始套接字用 *net.IPAddr。
func writeEcho(conn *icmp.PacketConn, ip net.IP, isV6, udpSocket bool, seq int) error {
	var typ icmp.Type = ipv4.ICMPTypeEcho
	if isV6 {
		typ = ipv6.ICMPTypeEchoRequest
	}
	message := icmp.Message{
		Type: typ,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  seq,
			Data: make([]byte, pingPayloadSize),
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
func parseEchoReply(data []byte, isV6 bool, seq int) bool {
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
	// 非特权 ICMP 由内核分配 ID，因此只按序号匹配。
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
func tcpingProbe(ctx context.Context, job Job) (LatencyReport, error) {
	count := normalizeCount(job.Count)
	timeout := probeTimeout(ctx, job.TimeoutMS)
	host := strings.TrimSpace(job.Target)
	port := job.Port
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
		}
	}
	report := LatencyReport{Kind: kindTCPing, Target: address, Resolved: resolved, Sent: count}

	dialer := &net.Dialer{Timeout: timeout}
	for i := 0; i < count; i++ {
		if ctx.Err() != nil {
			break
		}
		start := time.Now()
		conn, err := dialer.DialContext(ctx, "tcp", address)
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
			sleepCtx(ctx, probeInterval-rtt)
		}
	}
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

// httpProbe 发起一次 HTTP(S) 请求并分阶段计时。
func httpProbe(ctx context.Context, job Job) (HTTPReport, error) {
	raw := strings.TrimSpace(job.Target)
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return HTTPReport{}, fmt.Errorf("无效的 URL：%s（需要 http:// 或 https:// 开头）", raw)
	}
	timeout := probeTimeout(ctx, job.TimeoutMS)
	report := HTTPReport{URL: parsed.String(), TLS: parsed.Scheme == "https"}

	var (
		dnsStart, connStart, tlsStart, writeStart time.Time
		dnsMs, connMs, tlsMs, ttfbMs              float64
		remoteAddr                                string
		redirects                                 int
	)
	start := time.Now()
	trace := &httptrace.ClientTrace{
		DNSStart:          func(httptrace.DNSStartInfo) { dnsStart = time.Now() },
		DNSDone:           func(httptrace.DNSDoneInfo) { dnsMs = sinceMs(dnsStart) },
		ConnectStart:      func(_, _ string) { connStart = time.Now() },
		ConnectDone:       func(_, _ string, _ error) { connMs = sinceMs(connStart) },
		TLSHandshakeStart: func() { tlsStart = time.Now() },
		TLSHandshakeDone:  func(tls.ConnectionState, error) { tlsMs = sinceMs(tlsStart) },
		GotConn: func(info httptrace.GotConnInfo) {
			writeStart = time.Now()
			if info.Conn != nil && info.Conn.RemoteAddr() != nil {
				remoteAddr = info.Conn.RemoteAddr().String()
				if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
					remoteAddr = host
				}
			}
		},
		GotFirstResponseByte: func() { ttfbMs = sinceMs(writeStart) },
	}
	reqCtx, cancel := context.WithTimeout(httptrace.WithClientTrace(ctx, trace), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return report, err
	}
	req.Header.Set("User-Agent", "mnagent/"+version)

	client := &http.Client{
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
		return report, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, httpMaxBodyBytes))
	report.Status = resp.StatusCode
	report.StatusText = resp.Status
	report.Redirects = redirects
	report.RemoteIP = remoteAddr
	report.DNSMs, report.ConnectMs, report.TLSHandMs, report.TTFBMs = dnsMs, connMs, tlsMs, ttfbMs
	report.TotalMs = sinceMs(start)
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		report.CertExpiry = resp.TLS.PeerCertificates[0].NotAfter.Format("2006-01-02")
	}
	if snippet := strings.TrimSpace(string(body)); snippet != "" {
		report.BodySnippet = strings.TrimSpace(collapseWhitespace(snippet, 120))
	}
	return report, nil
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

// dnsProbe 用主机自身的解析器查询记录，便于对比不同地域/线路的解析结果。
func dnsProbe(ctx context.Context, job Job) (DNSReport, error) {
	host := strings.TrimSpace(job.Target)
	if host == "" {
		return DNSReport{}, errors.New("缺少查询域名")
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
			add([]string{ip.String()})
		}
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
		records, err := resolver.LookupAddr(queryCtx, host)
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
	// 单次探测（一次回包/一次握手）不超过 10 秒，整体由任务超时兜底。
	if timeout > 10*time.Second {
		timeout = 10 * time.Second
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
