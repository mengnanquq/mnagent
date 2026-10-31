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
	"testing"
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

func TestBlockedProbeIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1",
		"::1",
		"10.0.0.1",
		"192.168.1.1",
		"172.16.0.1",
		"169.254.169.254", // AWS/GCP/Alibaba Cloud metadata
		"100.64.0.1",      // CGNAT
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

// TestDNSProbeLocalhost 用主机自身解析器查询回环地址。
func TestDNSProbeLocalhost(t *testing.T) {
	report, err := DNSProbe(context.Background(), model.Job{Target: "localhost", Query: "A", TimeoutMS: 3000})
	if err != nil {
		t.Fatalf("dns 探针失败: %v", err)
	}
	if len(report.Records) == 0 || !strings.Contains(strings.Join(report.Records, ","), "127.0.0.1") {
		t.Fatalf("A 记录异常: %+v", report)
	}
	if report.ElapsedMs < 0 {
		t.Fatalf("耗时异常: %+v", report)
	}
	if _, err := DNSProbe(context.Background(), model.Job{Target: "localhost", Query: "NOPE"}); err == nil {
		t.Fatal("不支持的记录类型应报错")
	}
	if _, err := DNSProbe(context.Background(), model.Job{Target: "", Query: "A"}); err == nil {
		t.Fatal("缺少域名应报错")
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
