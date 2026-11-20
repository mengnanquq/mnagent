package probe

import (
	"github.com/mengnanquq/mnagent/internal/model"
)

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// TestProbeKindRouting 覆盖任务类型归一化与分类。
func TestProbeKindRouting(t *testing.T) {
	if got := ProbeKind(model.Job{}); got != KindTrace {
		t.Fatalf("空 kind 应视为 trace，实际 %q", got)
	}
	for _, kind := range []string{KindPing, KindTCPing, KindHTTP, KindDNS} {
		if !IsProbeKind(kind) {
			t.Fatalf("%q 应被识别为进程内探针", kind)
		}
	}
	if IsProbeKind(KindTrace) || IsProbeKind("") {
		t.Fatal("trace 不应走进程内探针")
	}
	if _, err := RunProbe(context.Background(), model.Job{Kind: "nope", Target: "1.1.1.1"}, false); err == nil {
		t.Fatal("未知探针类型应报错")
	}

}

// TestNormalizeCount 覆盖次数夹取。
func TestNormalizeCount(t *testing.T) {
	if got := normalizeCount(0); got != defaultPingCount {
		t.Fatalf("缺省次数 = %d", got)
	}
	if got := normalizeCount(3); got != 3 {
		t.Fatalf("正常次数 = %d", got)
	}
	if got := normalizeCount(999); got != maxProbeCount {
		t.Fatalf("超限次数应夹到 %d，实际 %d", maxProbeCount, got)
	}
}

// TestTCPingProbeLocalListener 对本地监听端口做 tcping：应当全部成功且延迟很小。
func TestTCPingProbeLocalListener(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port

	report, err := TCPingProbe(context.Background(), model.Job{Target: "127.0.0.1", Port: port, Count: 2, TimeoutMS: 2000}, true)
	if err != nil {
		t.Fatalf("tcping 失败: %v", err)
	}
	if report.Sent != 2 || report.Recv != 2 || report.Loss != 0 {
		t.Fatalf("结果异常: %+v", report)
	}
	if report.AvgMs <= 0 || report.MinMs > report.MaxMs {
		t.Fatalf("延迟统计异常: %+v", report)
	}
	if report.Kind != KindTCPing || len(report.Attempts) != 2 {
		t.Fatalf("明细异常: %+v", report)
	}
}

// TestTCPingProbeRefusedPort 连接被拒绝时应当记录错误且丢包率 100%。
func TestTCPingProbeRefusedPort(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close() // 关闭后该端口无人监听

	report, err := TCPingProbe(context.Background(), model.Job{Target: "127.0.0.1", Port: port, Count: 1, TimeoutMS: 2000}, true)
	if err != nil {
		t.Fatalf("tcping 不应因连接失败而报错: %v", err)
	}
	if report.Recv != 0 || report.Loss != 100 {
		t.Fatalf("应全部失败: %+v", report)
	}
	if report.Attempts[0].Error == "" {
		t.Fatal("应记录失败原因")
	}
}

// TestTCPingProbeRejectsBadPort 端口越界应直接报错。
// TestTCPingProbeRejectsUnresolvedOrPrivateHost 验证域名无法解析时直接失败（不再按域名拨号），
// 解析到回环/内网地址时被拦截。
func TestTCPingProbeRejectsUnresolvedOrPrivateHost(t *testing.T) {
	if _, err := TCPingProbe(context.Background(), model.Job{Target: "no-such-host.invalid", Port: 443, Count: 1}, false); err == nil || !strings.Contains(err.Error(), "无法解析") {
		t.Fatalf("无法解析的域名应直接报错，实际: %v", err)
	}
	if _, err := TCPingProbe(context.Background(), model.Job{Target: "localhost", Port: 443, Count: 1}, false); err == nil || !strings.Contains(err.Error(), "安全策略拦截") {
		t.Fatalf("解析到回环地址的域名应被拦截，实际: %v", err)
	}
}

func TestTCPingProbeRejectsBadPort(t *testing.T) {
	if _, err := TCPingProbe(context.Background(), model.Job{Target: "127.0.0.1", Port: 70000}, true); err == nil {
		t.Fatal("非法端口应报错")
	}
}

// TestPingProbeLocalhost 对回环地址做 ICMP 探测：需要能创建 ICMP 套接字
// （非特权 ICMP 或 CAP_NET_RAW），两者都没有时跳过。
func TestPingProbeLocalhost(t *testing.T) {
	conn, _, err := ListenICMP(false)
	if err != nil {
		t.Skipf("本机无法创建 ICMP 套接字，跳过：%v", err)
	}
	conn.Close()

	report, err := PingProbe(context.Background(), model.Job{Target: "127.0.0.1", Count: 2, TimeoutMS: 3000}, true)
	if err != nil {
		t.Fatalf("ping 失败: %v", err)
	}
	if report.Sent != 2 || report.Recv != 2 || report.Loss != 0 {
		t.Fatalf("回环应全部成功: %+v", report)
	}
	if report.Resolved != "127.0.0.1" {
		t.Fatalf("解析结果异常: %q", report.Resolved)
	}
}

// TestHTTPProbeIgnoresEnvironmentProxy 验证 HTTP 探针不会使用 HTTP_PROXY/HTTPS_PROXY：
// 环境代理会让请求由代理自行解析并连接目标，从而绕过按解析 IP 做的 SSRF 校验。
func TestHTTPProbeIgnoresEnvironmentProxy(t *testing.T) {
	var proxyHits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHits.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "")

	// 监听 0.0.0.0 并以 http://0.0.0.0:<port> 访问：该主机名不会被 Go 的
	// ProxyFromEnvironment 当作回环地址跳过，能真实暴露“走环境代理”的行为。
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Skipf("无法监听 0.0.0.0: %v", err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	defer srv.Close()

	report, err := HTTPProbe(context.Background(), model.Job{Target: srv.URL, TimeoutMS: 5000}, true)
	if err != nil {
		t.Fatalf("应直连目标而不走环境代理，实际失败: %v", err)
	}
	if report.Status != http.StatusOK {
		t.Fatalf("应直连目标得到 200，实际状态 %d（可能被环境代理转发）", report.Status)
	}
	if hits := proxyHits.Load(); hits != 0 {
		t.Fatalf("HTTP 探针不应使用环境代理，代理却收到 %d 次请求", hits)
	}

	// 即使设置了代理，内网/元数据地址仍必须被 SSRF 守卫拦截。
	if _, err := HTTPProbe(context.Background(), model.Job{Target: "http://169.254.169.254/latest/meta-data/", TimeoutMS: 1000}, false); err == nil || !strings.Contains(err.Error(), "安全策略拦截") {
		t.Fatalf("设置代理后仍应拦截元数据地址，实际: %v", err)
	}
	if hits := proxyHits.Load(); hits != 0 {
		t.Fatalf("被拦截的目标不应经过环境代理，代理收到 %d 次请求", hits)
	}
}

// TestHTTPProbeOK 覆盖正常响应、状态码与耗时字段。
func TestHTTPProbeOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") == "" {
			t.Error("应带上 User-Agent")
		}
		w.Header().Set("Server", "test-server")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("hello\nworld"))
	}))
	defer srv.Close()

	report, err := HTTPProbe(context.Background(), model.Job{Target: srv.URL, TimeoutMS: 5000}, true)
	if err != nil {
		t.Fatalf("http 探针失败: %v", err)
	}
	if report.Status != http.StatusTeapot {
		t.Fatalf("状态码 = %d", report.Status)
	}
	if report.TotalMs <= 0 || report.TTFBMs < 0 {
		t.Fatalf("耗时字段异常: %+v", report)
	}
	if report.DNSMs != 0 {
		t.Fatalf("纯 IP 目标 DNS 耗时应为 0: %f", report.DNSMs)
	}
	if report.RemoteIP == "" {
		t.Fatalf("应记录远端 IP: %+v", report)
	}
	if report.Proto == "" {
		t.Fatalf("应记录协议版本: %+v", report)
	}
	if report.Headers["server"] != "test-server" || report.Headers["content-type"] != "text/plain; charset=utf-8" {
		t.Fatalf("响应标头采集异常: %+v", report.Headers)
	}
	if report.BodySnippet != "hello world" {
		t.Fatalf("正文摘要 = %q", report.BodySnippet)
	}

	// 验证域名目标的 DNS 阶段分离与耗时采集
	domainURL := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	domainReport, err := HTTPProbe(context.Background(), model.Job{Target: domainURL, TimeoutMS: 5000}, true)
	if err != nil {
		t.Fatalf("域名 http 探针失败: %v", err)
	}
	if domainReport.Status != http.StatusTeapot {
		t.Fatalf("域名请求状态码异常: %d", domainReport.Status)
	}
	if domainReport.ConnectMs < 0 || domainReport.TotalMs <= 0 {
		t.Fatalf("域名请求耗时异常: %+v", domainReport)
	}
}

// TestHTTPProbeCountsRedirects 覆盖重定向计数。
func TestHTTPProbeCountsRedirects(t *testing.T) {
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer final.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL, http.StatusFound)
	}))
	defer redirect.Close()

	report, err := HTTPProbe(context.Background(), model.Job{Target: redirect.URL, TimeoutMS: 5000}, true)
	if err != nil {
		t.Fatalf("http 探针失败: %v", err)
	}
	if report.Status != http.StatusOK || report.Redirects != 1 {
		t.Fatalf("重定向处理异常: %+v", report)
	}
}

// TestHTTPProbeRejectsBadURL 非 http(s) 目标应被拒绝。
func TestHTTPProbeRejectsBadURL(t *testing.T) {
	for _, target := range []string{"", "example.com", "ftp://example.com", "file:///etc/passwd"} {
		if _, err := HTTPProbe(context.Background(), model.Job{Target: target}, true); err == nil {
			t.Fatalf("%q 应被拒绝", target)
		}
	}
}

// TestBlockedProbeIPReservedRanges 表驱动覆盖新增的保留/过渡机制地址段，
// 并确认普通公网 IPv4/IPv6 不会被误伤。
func TestBlockedProbeIPReservedRanges(t *testing.T) {
	tests := []struct {
		ip      string
		blocked bool
	}{
		{"0.1.2.3", true},               // 0.0.0.0/8
		{"198.18.0.1", true},            // 198.18.0.0/15
		{"198.19.255.255", true},        // 198.18.0.0/15 上边界
		{"240.0.0.1", true},             // 240.0.0.0/4
		{"255.255.255.255", true},       // 广播地址
		{"100.64.0.1", true},            // CGNAT
		{"::a9fe:a9fe", true},           // IPv4 兼容 ::/96，内嵌 169.254.169.254
		{"64:ff9b:1::1", true},          // NAT64 本地使用前缀
		{"2001:0:4136:e378::1", true},   // Teredo 2001::/32
		{"1.1.1.1", false},              // 普通公网 IPv4
		{"11.0.0.1", false},             // 公网 IPv4（DoD 段，不在拦截列表）
		{"198.17.255.255", false},       // 198.18/15 之外
		{"198.20.0.1", false},           // 198.18/15 之外
		{"2606:4700:4700::1111", false}, // 普通公网 IPv6
		{"2001:4860:4860::8888", false}, // 普通公网 IPv6（2001::/32 之外）
		{"64:ff9b:2::1", false},         // 不属于 NAT64 前缀
		{"::8.8.8.8", false},            // IPv4 兼容地址内嵌公网地址，不应整段拦截
		{"64:ff9b::8.8.8.8", false},     // NAT64 内嵌公网地址，不应整段拦截
		{"2002:808:808::1", false},      // 6to4 内嵌公网地址，不应整段拦截
	}
	for _, tc := range tests {
		ip := net.ParseIP(tc.ip)
		if ip == nil {
			t.Fatalf("测试用例 IP 非法: %q", tc.ip)
		}
		if got := IsBlockedProbeIP(ip); got != tc.blocked {
			t.Errorf("IsBlockedProbeIP(%q) = %v, want %v", tc.ip, got, tc.blocked)
		}
	}
}

func TestBlockedProbeIPEmbeddedIPv4(t *testing.T) {
	// 过渡机制地址（NAT64 / 6to4 / IPv4-compatible）只按内嵌 IPv4 判定：
	// 内嵌公网地址必须放行，否则 IPv6-only + NAT64 网络下所有公网 IPv4 都会被拦截。
	tests := []struct {
		ip      string
		blocked bool
	}{
		{"64:ff9b::8.8.8.8", false},
		{"64:ff9b::a9fe:a9fe", true}, // 169.254.169.254 云元数据
		{"64:ff9b::7f00:1", true},    // 127.0.0.1
		{"2002:808:808::", false},    // 内嵌 8.8.8.8
		{"2002:a9fe:a9fe::", true},   // 内嵌 169.254.169.254
		{"2002:a00:1::", true},       // 内嵌 10.0.0.1
		{"::808:808", false},         // ::/96 内嵌 8.8.8.8
		{"::7f00:1", true},           // ::/96 内嵌 127.0.0.1
	}
	for _, tc := range tests {
		ip := net.ParseIP(tc.ip)
		if ip == nil {
			t.Fatalf("测试用例 IP 非法: %q", tc.ip)
		}
		if got := IsBlockedProbeIP(ip); got != tc.blocked {
			t.Errorf("IsBlockedProbeIP(%q) = %v, want %v", tc.ip, got, tc.blocked)
		}
	}
}

func TestBlockedProbeIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1",
		"::1",
		"10.0.0.1",
		"192.168.1.1",
		"172.16.0.1",
		"169.254.169.254", // AWS/GCP/Alibaba Cloud metadata
		"100.64.0.1",      // CGNAT
		"192.0.0.1",       // IETF 协议分配 192.0.0.0/24
		"198.18.0.1",      // 基准测试保留 198.18.0.0/15
		"240.0.0.1",       // 保留 240.0.0.0/4
	}
	for _, ipStr := range blocked {
		ip := net.ParseIP(ipStr)
		if !IsBlockedProbeIP(ip) {
			t.Errorf("IsBlockedProbeIP(%q) 期望返回 true，实际 false", ipStr)
		}
	}

	public := []string{
		"1.1.1.1",
		"8.8.8.8",
		"100.128.0.1", // 紧邻 CGNAT 之外，必须保持放行
		"192.0.2.1",   // 文档示例段，不能被 192.0.0.0/24 误伤
		"2606:4700:4700::1111",
	}
	for _, ipStr := range public {
		ip := net.ParseIP(ipStr)
		if IsBlockedProbeIP(ip) {
			t.Errorf("IsBlockedProbeIP(%q) 期望返回 false，实际 true", ipStr)
		}
	}

	// 默认未开启 allowPrivate 时，拦截云元数据
	if _, err := HTTPProbe(context.Background(), model.Job{Target: "http://169.254.169.254/latest/meta-data/"}, false); err == nil {
		t.Fatal("未开启 allowPrivate 时探测云元数据必须被拦截")
	}
	if _, err := TCPingProbe(context.Background(), model.Job{Target: "169.254.169.254", Port: 80}, false); err == nil {
		t.Fatal("未开启 allowPrivate 时 tcping 云元数据必须被拦截")
	}
}

// TestDNSProbeLocalhost 用主机自身解析器查询回环地址（显式允许私网）。
func TestDNSProbeLocalhost(t *testing.T) {
	report, err := DNSProbe(context.Background(), model.Job{Target: "localhost", Query: "A", TimeoutMS: 3000}, true)
	if err != nil {
		t.Fatalf("dns 探针失败: %v", err)
	}
	if len(report.Records) == 0 || !strings.Contains(strings.Join(report.Records, ","), "127.0.0.1") {
		t.Fatalf("A 记录异常: %+v", report)
	}
	if report.ElapsedMs < 0 {
		t.Fatalf("耗时异常: %+v", report)
	}
	if _, err := DNSProbe(context.Background(), model.Job{Target: "localhost", Query: "NOPE"}, true); err == nil {
		t.Fatal("不支持的记录类型应报错")
	}
	if _, err := DNSProbe(context.Background(), model.Job{Target: "", Query: "A"}, true); err == nil {
		t.Fatal("缺少域名应报错")
	}
}

// TestDNSProbeBlocksPrivate 验证 allowPrivate=false 时 DNS 探针与其他探针一致：
// 目标是私网/元数据地址或查询结果包含这类 IP 时直接拒绝，不返回记录。
func TestDNSProbeBlocksPrivate(t *testing.T) {
	// 目标是私网 IP（PTR/直查）应被拒绝。
	for _, target := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "192.168.1.1", "::1"} {
		if _, err := DNSProbe(context.Background(), model.Job{Target: target, Query: "PTR", TimeoutMS: 1000}, false); err == nil ||
			!strings.Contains(err.Error(), "安全策略拦截") {
			t.Fatalf("目标 %s 应被拦截，实际 err=%v", target, err)
		}
	}

	// 单标签 localhost 现在会在名称级校验直接拒绝，不再进入解析器。
	for _, recordType := range []string{"A", "AAAA", "ALL"} {
		if _, err := DNSProbe(context.Background(), model.Job{Target: "localhost", Query: recordType, TimeoutMS: 3000}, false); err == nil ||
			!strings.Contains(err.Error(), "安全策略拦截") {
			t.Fatalf("%s 查询 localhost 应被名称级校验拒绝，实际 err=%v", recordType, err)
		}
	}
}

// TestDNSProbeBlocksReservedNamesAndPrivateReverse 验证名称级 SSRF 校验：
// 单标签、内网保留后缀与私网反向域名在查询前被拒绝。
func TestDNSProbeBlocksReservedNamesAndPrivateReverse(t *testing.T) {
	cases := []struct {
		target string
		query  string
	}{
		{"localhost", "A"},
		{"printer.local", "A"},
		{"router.home.arpa", "A"},
		{"foo.internal", "TXT"},
		{"service.lan", "CNAME"},
		{"1.0.0.10.in-addr.arpa", "PTR"},
		{"1.0.0.127.in-addr.arpa", "PTR"},
		{"0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa", "PTR"},
	}
	for _, tc := range cases {
		if _, err := DNSProbe(context.Background(), model.Job{Target: tc.target, Query: tc.query, TimeoutMS: 1000}, false); err == nil ||
			!strings.Contains(err.Error(), "安全策略拦截") {
			t.Fatalf("目标 %s 应被拦截，实际 err=%v", tc.target, err)
		}
	}
}

// TestDNSQueryNameAllowsPublicDomains 验证公网域名、TXT 下划线前缀与公网反向域名
// 不会被名称级校验误伤（CNAME/MX/NS/TXT 不要求能解析出 A 记录）。
func TestDNSQueryNameAllowsPublicDomains(t *testing.T) {
	for _, host := range []string{
		"example.com",
		"_dmarc.example.com",
		"mail.example.com",
		"8.8.8.8",
		"8.8.8.8.in-addr.arpa",
		"2606:4700:4700::1111",
	} {
		if err := validateDNSQueryName(host); err != nil {
			t.Fatalf("公网名称 %s 不应被拦截: %v", host, err)
		}
	}
}

// TestParseReverseDNSName 验证反向域名还原为 IP，供私网判定复用。
func TestParseReverseDNSName(t *testing.T) {
	ip, ok := parseReverseDNSName("8.8.8.8.in-addr.arpa")
	if !ok || !ip.Equal(net.ParseIP("8.8.8.8")) {
		t.Fatalf("IPv4 反解异常: ip=%v ok=%v", ip, ok)
	}
	ip, ok = parseReverseDNSName("1.0.0.10.in-addr.arpa")
	if !ok || !ip.Equal(net.ParseIP("10.0.0.1")) {
		t.Fatalf("私网 IPv4 反解异常: ip=%v ok=%v", ip, ok)
	}

	want := net.ParseIP("2001:db8::1")
	hex := fmt.Sprintf("%032x", []byte(want.To16()))
	var b strings.Builder
	for i := len(hex) - 1; i >= 0; i-- {
		b.WriteByte(hex[i])
		if i > 0 {
			b.WriteByte('.')
		}
	}
	ip, ok = parseReverseDNSName(b.String() + ".ip6.arpa")
	if !ok || !ip.Equal(want) {
		t.Fatalf("IPv6 反解异常: ip=%v ok=%v", ip, ok)
	}

	if _, ok := parseReverseDNSName("not-a-reverse.example.com"); ok {
		t.Fatal("普通域名不应被识别为反向域名")
	}
	if _, ok := parseReverseDNSName("999.0.0.10.in-addr.arpa"); ok {
		t.Fatal("非法 IPv4 标签不应反解成功")
	}
}

// TestRunProbeJobProducesData 验证探针结果会带结构化 Data（机器人据此排版）。
func TestRunProbeJobProducesData(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port

	outcome, err := RunProbe(context.Background(), model.Job{Kind: KindTCPing, Target: "127.0.0.1", Port: port, Count: 1, TimeoutMS: 2000}, true)
	if err != nil {
		t.Fatalf("不应报错: %v", err)
	}
	if len(outcome.Data) == 0 {
		t.Fatal("应带结构化 Data")
	}
	var report LatencyReport
	if err := json.Unmarshal(outcome.Data, &report); err != nil {
		t.Fatalf("Data 不是合法 JSON: %v", err)
	}
	if report.Kind != KindTCPing || report.Recv != 1 {
		t.Fatalf("Data 内容异常: %+v", report)
	}
	if outcome.Output == "" || !strings.Contains(outcome.Output, fmt.Sprintf("%d", report.Sent)) {
		t.Fatalf("摘要文本异常: %q", outcome.Output)
	}
}

// TestHTTPProbeConnectionFailureClearsData 验证连接失败时不回传零值 Data，且错误信息精简易读。
func TestHTTPProbeConnectionFailureClearsData(t *testing.T) {
	outcome, err := RunProbe(context.Background(), model.Job{Kind: KindHTTP, Target: "http://192.0.2.1:1", TimeoutMS: 500}, true)
	if err == nil {
		t.Fatal("不可达目标应返回错误")
	}
	if len(outcome.Data) != 0 {
		t.Fatalf("连接失败时不应返回零值 Data，实际：%s", string(outcome.Data))
	}
}

// TestHTTPPhaseTimingsConcurrentObservation 验证 httptrace 回调与 DialContext
// 并发写入 dns/conn 耗时不会产生数据竞争，并且只记录第一次观测值。
func TestHTTPPhaseTimingsConcurrentObservation(t *testing.T) {
	var timings httpPhaseTimings
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			timings.startDNS()
			timings.observeDNS(time.Duration(i+1) * time.Millisecond)
			timings.doneDNS()
			timings.startConnect()
			timings.observeConnect(time.Duration(i+10) * time.Millisecond)
			timings.doneConnect()
		}(i)
	}
	wg.Wait()
	dnsMs, connMs, _, _, _ := timings.snapshot()
	if dnsMs <= 0 || connMs <= 0 {
		t.Fatalf("并发记录后耗时异常: dns=%f conn=%f", dnsMs, connMs)
	}
	if dnsMs > 8 || connMs > 18 {
		t.Fatalf("应只记录首次拨号耗时，实际 dns=%f conn=%f", dnsMs, connMs)
	}
}

// TestParseEchoReplyValidatesPayloadCookie 验证 ping 回包必须携带本次请求的随机 cookie，
// 避免原始套接字把同机其它 ping 进程的回包误算为成功。
func TestParseEchoReplyValidatesPayloadCookie(t *testing.T) {
	payload := []byte("cookie12-rest-of-payload-padding")
	reply, err := (&icmp.Message{
		Type: ipv4.ICMPTypeEchoReply,
		Body: &icmp.Echo{Seq: 7, Data: payload},
	}).Marshal(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !parseEchoReply(reply, false, true, 7, payload) {
		t.Fatal("匹配序号与随机载荷的回包应被接受")
	}
	if parseEchoReply(reply, false, true, 8, payload) {
		t.Fatal("序号不匹配的回包应被拒绝")
	}
	wrong := append([]byte(nil), payload...)
	wrong[0] ^= 0xff
	if parseEchoReply(reply, false, true, 7, wrong) {
		t.Fatal("随机 cookie 不匹配的回包应被拒绝")
	}
	if parseEchoReply(reply, false, true, 7, payload[:4]) {
		t.Fatal("回包载荷长度与请求不一致时应被拒绝")
	}
}

// TestProbeCanceledSentMatchesAttempts 验证取消后 Sent 等于实际 Attempts 数量，
// 避免提前退出时把未尝试的次数全部算成丢包。
func TestProbeCanceledSentMatchesAttempts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	t.Run("tcping", func(t *testing.T) {
		report, err := TCPingProbe(ctx, model.Job{Target: "127.0.0.1", Port: 443, Count: 4, TimeoutMS: 2000}, true)
		if err != nil {
			t.Fatalf("取消时不应返回致命错误: %v", err)
		}
		if report.Sent != len(report.Attempts) {
			t.Fatalf("Sent=%d 与 Attempts=%d 不一致", report.Sent, len(report.Attempts))
		}
	})

	t.Run("ping", func(t *testing.T) {
		conn, _, err := ListenICMP(false)
		if err != nil {
			t.Skipf("本机无法创建 ICMP 套接字，跳过：%v", err)
		}
		conn.Close()
		report, err := PingProbe(ctx, model.Job{Target: "127.0.0.1", Count: 4, TimeoutMS: 2000}, true)
		if err != nil {
			t.Fatalf("取消时不应返回致命错误: %v", err)
		}
		if report.Sent != len(report.Attempts) {
			t.Fatalf("Sent=%d 与 Attempts=%d 不一致", report.Sent, len(report.Attempts))
		}
	})
}
