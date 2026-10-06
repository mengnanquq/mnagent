package main

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
	if got := probeKind(Job{}); got != kindTrace {
		t.Fatalf("空 kind 应视为 trace，实际 %q", got)
	}
	for _, kind := range []string{kindPing, kindTCPing, kindHTTP, kindDNS} {
		if !isProbeKind(kind) {
			t.Fatalf("%q 应被识别为进程内探针", kind)
		}
	}
	if isProbeKind(kindTrace) || isProbeKind("") {
		t.Fatal("trace 不应走进程内探针")
	}
	if _, err := runProbe(context.Background(), Job{Kind: "nope", Target: "1.1.1.1"}); err == nil {
		t.Fatal("未知探针类型应报错")
	}
	// 未知类型不应走 nexttrace（避免把畸形任务当追踪执行）
	res := (&runner{binary: "/nonexistent"}).run(context.Background(), Job{Kind: "nope", Target: "1.1.1.1"})
	if !strings.Contains(res.ErrText, "未知探针类型") {
		t.Fatalf("未知类型应快速失败，实际 %q", res.ErrText)
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

	report, err := tcpingProbe(context.Background(), Job{Target: "127.0.0.1", Port: port, Count: 2, TimeoutMS: 2000})
	if err != nil {
		t.Fatalf("tcping 失败: %v", err)
	}
	if report.Sent != 2 || report.Recv != 2 || report.Loss != 0 {
		t.Fatalf("结果异常: %+v", report)
	}
	if report.AvgMs <= 0 || report.MinMs > report.MaxMs {
		t.Fatalf("延迟统计异常: %+v", report)
	}
	if report.Kind != kindTCPing || len(report.Attempts) != 2 {
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

	report, err := tcpingProbe(context.Background(), Job{Target: "127.0.0.1", Port: port, Count: 1, TimeoutMS: 2000})
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
	if _, err := tcpingProbe(context.Background(), Job{Target: "127.0.0.1", Port: 70000}); err == nil {
		t.Fatal("非法端口应报错")
	}
}

// TestPingProbeLocalhost 对回环地址做 ICMP 探测：需要能创建 ICMP 套接字
// （非特权 ICMP 或 CAP_NET_RAW），两者都没有时跳过。
func TestPingProbeLocalhost(t *testing.T) {
	conn, _, err := listenICMP(false)
	if err != nil {
		t.Skipf("本机无法创建 ICMP 套接字，跳过：%v", err)
	}
	conn.Close()

	report, err := pingProbe(context.Background(), Job{Target: "127.0.0.1", Count: 2, TimeoutMS: 3000})
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
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("hello\nworld"))
	}))
	defer srv.Close()

	report, err := httpProbe(context.Background(), Job{Target: srv.URL, TimeoutMS: 5000})
	if err != nil {
		t.Fatalf("http 探针失败: %v", err)
	}
	if report.Status != http.StatusTeapot {
		t.Fatalf("状态码 = %d", report.Status)
	}
	if report.TotalMs <= 0 || report.TTFBMs < 0 {
		t.Fatalf("耗时字段异常: %+v", report)
	}
	if report.RemoteIP == "" {
		t.Fatalf("应记录远端 IP: %+v", report)
	}
	if report.BodySnippet != "hello world" {
		t.Fatalf("正文摘要 = %q", report.BodySnippet)
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

	report, err := httpProbe(context.Background(), Job{Target: redirect.URL, TimeoutMS: 5000})
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
		if _, err := httpProbe(context.Background(), Job{Target: target}); err == nil {
			t.Fatalf("%q 应被拒绝", target)
		}
	}
}

// TestDNSProbeLocalhost 用主机自身解析器查询回环地址。
func TestDNSProbeLocalhost(t *testing.T) {
	report, err := dnsProbe(context.Background(), Job{Target: "localhost", Query: "A", TimeoutMS: 3000})
	if err != nil {
		t.Fatalf("dns 探针失败: %v", err)
	}
	if len(report.Records) == 0 || !strings.Contains(strings.Join(report.Records, ","), "127.0.0.1") {
		t.Fatalf("A 记录异常: %+v", report)
	}
	if report.ElapsedMs < 0 {
		t.Fatalf("耗时异常: %+v", report)
	}
	if _, err := dnsProbe(context.Background(), Job{Target: "localhost", Query: "NOPE"}); err == nil {
		t.Fatal("不支持的记录类型应报错")
	}
	if _, err := dnsProbe(context.Background(), Job{Target: "", Query: "A"}); err == nil {
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

	r := newRunner("nexttrace", nil)
	res := r.run(context.Background(), Job{Kind: kindTCPing, Target: "127.0.0.1", Port: port, Count: 1, TimeoutMS: 2000})
	if res.ErrText != "" {
		t.Fatalf("不应报错: %q", res.ErrText)
	}
	if len(res.Data) == 0 {
		t.Fatal("应带结构化 Data")
	}
	var report LatencyReport
	if err := json.Unmarshal(res.Data, &report); err != nil {
		t.Fatalf("Data 不是合法 JSON: %v", err)
	}
	if report.Kind != kindTCPing || report.Recv != 1 {
		t.Fatalf("Data 内容异常: %+v", report)
	}
	if res.Output == "" || !strings.Contains(res.Output, fmt.Sprintf("%d", report.Sent)) {
		t.Fatalf("摘要文本异常: %q", res.Output)
	}
}
