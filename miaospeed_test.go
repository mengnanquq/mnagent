package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/net/websocket"
	"time"
)

// TestSignMiaoSpeedRequest 验证 MiaoSpeed 的 SHA-512 Challenge 计算。
func TestSignMiaoSpeedRequest(t *testing.T) {
	req := slaveRequest{
		Basics: slaveRequestBasics{ID: "test1"},
	}
	token := "token123"
	buildToken := "MIAOKO4|580JxAo049R|GEnERAl|1X571R930|T0kEN"

	sig1, err1 := signMiaoSpeedRequest(token, buildToken, req)
	sig2, err2 := signMiaoSpeedRequest(token, buildToken, req)
	if err1 != nil || err2 != nil {
		t.Fatalf("签名计算报错: %v, %v", err1, err2)
	}
	if sig1 == "" || sig1 != sig2 {
		t.Fatalf("签名计算结果不应为空且必须确定: sig1=%q, sig2=%q", sig1, sig2)
	}

	// 改变输入时签名应改变
	req2 := slaveRequest{
		Basics: slaveRequestBasics{ID: "test2"},
	}
	sigDifferent, _ := signMiaoSpeedRequest(token, buildToken, req2)
	if sig1 == sigDifferent {
		t.Fatalf("不同请求内容不应生成相同签名")
	}
}

// TestParseProxyURIs 验证各种主流代理协议 URI 解析。
func TestParseProxyURIs(t *testing.T) {
	t.Run("Shadowsocks SIP002", func(t *testing.T) {
		// aes-128-gcm:pass123 -> YWVzLTEyOC1nY206cGFzczEyMw==
		uri := "ss://YWVzLTEyOC1nY206cGFzczEyMw==@1.2.3.4:8388#HK-SS"
		node, err := parseProxyURI(uri)
		if err != nil {
			t.Fatalf("解析失败: %v", err)
		}
		if node.Protocol != "ss" || node.Server != "1.2.3.4:8388" || node.Name != "HK-SS" {
			t.Fatalf("节点信息不符合预期: %+v", node)
		}
		if !strings.Contains(node.Payload, "type: ss") || !strings.Contains(node.Payload, "cipher: aes-128-gcm") {
			t.Fatalf("Payload YAML 错误: %s", node.Payload)
		}
	})

	t.Run("Shadowsocks Legacy", func(t *testing.T) {
		// aes-256-cfb:pass@192.168.1.1:8388 -> base64
		raw := "aes-256-cfb:pass@192.168.1.1:8388"
		encoded := base64.StdEncoding.EncodeToString([]byte(raw))
		uri := "ss://" + encoded + "#Legacy-SS"
		node, err := parseProxyURI(uri)
		if err != nil {
			t.Fatalf("解析失败: %v", err)
		}
		if node.Protocol != "ss" || node.Server != "192.168.1.1:8388" {
			t.Fatalf("节点信息不符合预期: %+v", node)
		}
	})

	t.Run("VMess JSON", func(t *testing.T) {
		v := map[string]any{
			"v":    "2",
			"ps":   "JP-VMess",
			"add":  "jp.node.example",
			"port": 443,
			"id":   "b831381d-6324-4d53-ad4f-8cda48b30811",
			"aid":  0,
			"scy":  "auto",
			"net":  "ws",
			"tls":  "tls",
			"path": "/ws",
			"host": "jp.node.example",
		}
		b, _ := json.Marshal(v)
		uri := "vmess://" + base64.StdEncoding.EncodeToString(b)
		node, err := parseProxyURI(uri)
		if err != nil {
			t.Fatalf("解析失败: %v", err)
		}
		if node.Protocol != "vmess" || node.Server != "jp.node.example:443" || node.Name != "JP-VMess" {
			t.Fatalf("节点信息不符合预期: %+v", node)
		}
		if !strings.Contains(node.Payload, "type: vmess") || !strings.Contains(node.Payload, "network: ws") {
			t.Fatalf("Payload YAML 错误: %s", node.Payload)
		}
	})

	t.Run("Trojan", func(t *testing.T) {
		uri := "trojan://password123@trojan.example:443?sni=trojan.example#US-Trojan"
		node, err := parseProxyURI(uri)
		if err != nil {
			t.Fatalf("解析失败: %v", err)
		}
		if node.Protocol != "trojan" || node.Server != "trojan.example:443" || node.Name != "US-Trojan" {
			t.Fatalf("节点信息不符合预期: %+v", node)
		}
		if !strings.Contains(node.Payload, "type: trojan") || !strings.Contains(node.Payload, "password: \"password123\"") {
			t.Fatalf("Payload YAML 错误: %s", node.Payload)
		}
	})

	t.Run("VLESS", func(t *testing.T) {
		uri := "vless://uuid-vless-123@vless.example:443?security=tls&type=ws&sni=vless.example#SG-VLESS"
		node, err := parseProxyURI(uri)
		if err != nil {
			t.Fatalf("解析失败: %v", err)
		}
		if node.Protocol != "vless" || node.Server != "vless.example:443" || node.Name != "SG-VLESS" {
			t.Fatalf("节点信息不符合预期: %+v", node)
		}
		if !strings.Contains(node.Payload, "type: vless") || !strings.Contains(node.Payload, "uuid: uuid-vless-123") {
			t.Fatalf("Payload YAML 错误: %s", node.Payload)
		}
	})

	t.Run("Hysteria2", func(t *testing.T) {
		uri := "hysteria2://my-hy2-pass@hy2.example:443?sni=hy2.example#HY2-Node"
		node, err := parseProxyURI(uri)
		if err != nil {
			t.Fatalf("解析失败: %v", err)
		}
		if node.Protocol != "hysteria2" || node.Server != "hy2.example:443" || node.Name != "HY2-Node" {
			t.Fatalf("节点信息不符合预期: %+v", node)
		}
		if !strings.Contains(node.Payload, "type: hysteria2") {
			t.Fatalf("Payload YAML 错误: %s", node.Payload)
		}
	})

	t.Run("AnyTLS", func(t *testing.T) {
		uri := "anytls://secret-pass@anytls.example:8443/?sni=tls.example&insecure=1&alpn=h2,http/1.1&client-fingerprint=chrome#HK-AnyTLS"
		node, err := parseProxyURI(uri)
		if err != nil {
			t.Fatalf("解析失败: %v", err)
		}
		if node.Protocol != "anytls" || node.Server != "anytls.example:8443" || node.Name != "HK-AnyTLS" {
			t.Fatalf("节点信息不符合预期: %+v", node)
		}
		if !strings.Contains(node.Payload, "type: anytls") ||
			!strings.Contains(node.Payload, "password: \"secret-pass\"") ||
			!strings.Contains(node.Payload, "sni: \"tls.example\"") ||
			!strings.Contains(node.Payload, "skip-cert-verify: true") ||
			!strings.Contains(node.Payload, "client-fingerprint: \"chrome\"") ||
			!strings.Contains(node.Payload, "udp: true") ||
			!strings.Contains(node.Payload, "- \"h2\"") {
			t.Fatalf("Payload YAML 错误:\n%s", node.Payload)
		}

		// 测试 IPv6 与缺省配置
		uri6 := "anytls://pwd@[2409:8a71:6a00:1953::615]:8964/?insecure=1#IPv6-Node"
		node6, err := parseProxyURI(uri6)
		if err != nil {
			t.Fatalf("IPv6 解析失败: %v", err)
		}
		if node6.Server != "[2409:8a71:6a00:1953::615]:8964" || node6.Name != "IPv6-Node" {
			t.Fatalf("IPv6 节点信息不符合预期: %+v", node6)
		}

		// 测试默认端口与默认名称
		uriDefault := "anytls://letmein@example.com"
		nodeDef, err := parseProxyURI(uriDefault)
		if err != nil {
			t.Fatalf("默认参数解析失败: %v", err)
		}
		if nodeDef.Server != "example.com:443" || nodeDef.Name != "AnyTLS-Node" {
			t.Fatalf("默认参数不符合预期: %+v", nodeDef)
		}
	})

	t.Run("不支持的协议", func(t *testing.T) {
		uri := "ftp://example.com"
		_, err := parseProxyURI(uri)
		if err == nil {
			t.Fatalf("应拒绝不支持的协议")
		}
	})
}

// TestParseProxyTargetSubscription 验证从 HTTP 订阅提取节点。
func TestParseProxyTargetSubscription(t *testing.T) {
	node1 := "trojan://pass@trojan.com:443#Node1\n"
	node2 := "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ=@1.1.1.1:8388#Node2\n"
	subBody := base64.StdEncoding.EncodeToString([]byte(node1 + node2))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(subBody))
	}))
	defer server.Close()

	nodes, err := parseProxyTarget(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("解析订阅失败: %v", err)
	}
	if len(nodes) != 2 {
		t.Fatalf("期望解析出 2 个节点，实际: %d", len(nodes))
	}
	if nodes[0].Name != "Node1" || nodes[1].Name != "Node2" {
		t.Fatalf("节点名称不符合预期: %+v", nodes)
	}
}

// TestExecuteMiaospeedTask 验证与 WebSocket 服务的完整交互与结果解析。
func TestExecuteMiaospeedTask(t *testing.T) {
	token := "secret-test-token"

	// 启动模拟 WebSocket 服务器
	var receivedReq slaveRequest
	handler := websocket.Handler(func(ws *websocket.Conn) {
		// 1. 接收任务
		if err := websocket.JSON.Receive(ws, &receivedReq); err != nil {
			t.Errorf("服务端接收任务失败: %v", err)
			return
		}

		// 2. 发送进度
		_ = websocket.JSON.Send(ws, slaveResponse{
			Progress: &slaveProgress{Index: 0},
		})

		// 3. 发送最终测速结果
		resp := slaveResponse{
			Result: &slaveTask{
				Results: []slaveEntrySlot{
					{
						Grouping:       "test",
						InvokeDuration: 3500,
						Matrices: []matrixResponse{
							{Type: "TEST_PING_RTT", Payload: "35.2"},
							{Type: "TEST_PING_CONN", Payload: "48.6"},
							{Type: "TEST_PING_PACKET_LOSS", Payload: "0.0"},
							{Type: "SPEED_AVERAGE", Payload: "52428800"}, // 50 MB/s
							{Type: "SPEED_MAX", Payload: "83886080"},     // 80 MB/s
							{Type: "TEST_HTTP_CODE", Payload: "204"},
							{Type: "UDP_TYPE", Payload: "FullCone"},
							{Type: "GEOIP_INBOUND", Payload: "中国 广州 (14.215.x.x)"},
							{Type: "GEOIP_OUTBOUND", Payload: "日本 东京 (153.120.x.x)"},
							{Type: "TEST_HIJACK_DETECTION", Payload: "正常"},
							{Type: "SPEED_AVERAGE", Payload: "52428800"},  // 50 MB/s
							{Type: "SPEED_MAX", Payload: "83886080"},      // 80 MB/s
							{Type: "USPEED_AVERAGE", Payload: "20971520"}, // 20 MB/s
							{Type: "USPEED_MAX", Payload: "31457280"},     // 30 MB/s
						},
					},
				},
			},
		}
		_ = websocket.JSON.Send(ws, resp)
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	wsURL := "ws://" + server.Listener.Addr().String() + "/"
	origin := "http://" + server.Listener.Addr().String() + "/"

	nodes := []MiaospeedNode{
		{Name: "Tokyo-Node", Protocol: "trojan", Server: "1.2.3.4:443", Payload: "test-payload"},
	}
	job := Job{ID: "task-001"}

	report, err := executeMiaospeedTask(context.Background(), wsURL, origin, token, nodes, len(nodes), job, nil, nil)
	if err != nil {
		t.Fatalf("任务执行失败: %v", err)
	}

	if report.NodeName != "Tokyo-Node" || report.PingRTTMs != 35.2 || report.PingConnMs != 48.6 {
		t.Fatalf("报告延迟不符合预期: %+v", report)
	}
	if report.HTTPCode != 204 || report.UDPType != "FullCone" {
		t.Fatalf("连通性或 UDP 类型不符合预期: %+v", report)
	}
	if report.AvgSpeedBps != 52428800 {
		t.Fatalf("报告下行速度不符合预期: %+v", report)
	}
	if report.InboundGeo != "中国 广州 (14.215.x.x)" || report.Hijack != "正常" {
		t.Fatalf("拓扑信息不符合预期: %+v", report)
	}

	formatted := report.Format()
	if !strings.Contains(formatted, "MiaoSpeed 测速报告 · 全量测试") ||
		!strings.Contains(formatted, "UDP NAT 类型: FullCone") ||
		!strings.Contains(formatted, "下行 (4 线程): 平均 50.00 MB/s") {
		t.Fatalf("格式化排版不符合预期:\n%s", formatted)
	}
}

// TestMiaospeedReportJSONSerialization 验证直接返回的 JSON 数据结构供机器人端处理。
func TestMiaospeedReportJSONSerialization(t *testing.T) {
	report := MiaospeedReport{
		TestMode:  "全量测试",
		NodeName:  "Tokyo-01",
		Protocol:  "vmess",
		Server:    "1.2.3.4:443",
		HTTPCode:  204,
		PingRTTMs: 28.5,
		UDPType:   "FullCone",
		RawResults: []slaveEntrySlot{
			{
				Grouping: "test",
				Matrices: []matrixResponse{
					{Type: "TEST_PING_RTT", Payload: "28.5"},
				},
			},
		},
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("序列化 JSON 失败: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("反序列化 JSON 失败: %v", err)
	}
	if parsed["node_name"] != "Tokyo-01" || parsed["udp_type"] != "FullCone" || parsed["http_code"] != float64(204) {
		t.Fatalf("JSON 字段不符合预期: %+v", parsed)
	}
	if _, ok := parsed["raw_results"]; !ok {
		t.Fatalf("未携带原始 raw_results 字段供 bot 高级处理: %+v", parsed)
	}
}

// TestBuildMiaospeedTestPlan 验证 8 种测试类型与全量模式矩阵规划。
func TestBuildMiaospeedTestPlan(t *testing.T) {
	tests := []struct {
		name              string
		job               Job
		wantDesc          string
		wantMatrices      []string
		wantDownThreading uint
		wantUpThreading   uint
	}{
		{
			name:              "默认全量测试",
			job:               Job{ID: "t0"},
			wantDesc:          "全量测试",
			wantMatrices:      []string{matrixRTTPing, matrixHTTPPing, matrixPacketLoss, matrixHTTPCode, matrixInboundGeoIP, matrixOutboundGeoIP, matrixHijack, matrixUDPType, matrixAverageSpeed, matrixMaxSpeed, "TEST_SCRIPT", "TEST_SCRIPT", "TEST_SCRIPT", "TEST_SCRIPT", "TEST_SCRIPT", "TEST_SCRIPT", "TEST_SCRIPT", "TEST_SCRIPT", "TEST_SCRIPT"},
			wantDownThreading: 4,
		},
		{
			name:         "连通性测试 (connectivity)",
			job:          Job{ID: "t1", Query: "connectivity"},
			wantDesc:     "连通性测试",
			wantMatrices: []string{matrixRTTPing, matrixHTTPPing, matrixPacketLoss, matrixMaxRTTPing, matrixHTTPCode, matrixOutboundGeoIP},
		},
		{
			name:         "拓扑测试 (topology)",
			job:          Job{ID: "t2", Query: "拓扑测试"},
			wantDesc:     "拓扑测试",
			wantMatrices: []string{matrixRTTPing, matrixHTTPPing, matrixInboundGeoIP, matrixOutboundGeoIP, matrixHijack, matrixUDPType},
		},
		{
			name:              "多线程测速 (multithread)",
			job:               Job{ID: "t3", Query: "多线程测速", Count: 8},
			wantDesc:          "多线程测速",
			wantMatrices:      []string{matrixRTTPing, matrixHTTPPing, matrixPacketLoss, matrixHTTPCode, matrixOutboundGeoIP, matrixAverageSpeed, matrixMaxSpeed},
			wantDownThreading: 8,
		},
		{
			name:              "单线程测速 (singlethread)",
			job:               Job{ID: "t4", Query: "单线程测速"},
			wantDesc:          "单线程测速",
			wantMatrices:      []string{matrixRTTPing, matrixHTTPPing, matrixPacketLoss, matrixHTTPCode, matrixOutboundGeoIP, matrixAverageSpeed, matrixMaxSpeed},
			wantDownThreading: 1,
		},
		{
			name:         "延迟测试 (latency)",
			job:          Job{ID: "t6", Query: "latency"},
			wantDesc:     "延迟测试",
			wantMatrices: []string{matrixRTTPing, matrixHTTPPing, matrixPacketLoss, matrixMaxRTTPing, matrixHTTPCode, matrixOutboundGeoIP},
		},
		{
			name:         "UDP类型测试 (udp)",
			job:          Job{ID: "t7", Query: "udp类型"},
			wantDesc:     "UDP类型测试",
			wantMatrices: []string{matrixRTTPing, matrixHTTPPing, matrixPacketLoss, matrixHTTPCode, matrixOutboundGeoIP, matrixUDPType},
		},
		{
			name:         "组合测试：延迟+UDP类型",
			job:          Job{ID: "t8", Query: "latency,udp"},
			wantDesc:     "延迟测试 + UDP类型测试",
			wantMatrices: []string{matrixRTTPing, matrixHTTPPing, matrixPacketLoss, matrixMaxRTTPing, matrixHTTPCode, matrixOutboundGeoIP, matrixUDPType},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			plan := buildMiaospeedTestPlan(tc.job)
			if plan.ModeDescription != tc.wantDesc {
				t.Errorf("ModeDescription=%q, 期望=%q", plan.ModeDescription, tc.wantDesc)
			}
			if tc.wantDownThreading > 0 && plan.DownloadThreading != tc.wantDownThreading {
				t.Errorf("DownloadThreading=%d, 期望=%d", plan.DownloadThreading, tc.wantDownThreading)
			}
			if tc.wantUpThreading > 0 && plan.UploadThreading != tc.wantUpThreading {
				t.Errorf("UploadThreading=%d, 期望=%d", plan.UploadThreading, tc.wantUpThreading)
			}
			gotKeys := make([]string, len(plan.Matrices))
			for i, m := range plan.Matrices {
				gotKeys[i] = m.Type
			}
			if len(gotKeys) != len(tc.wantMatrices) {
				t.Fatalf("Matrices 长度=%d (%v), 期望=%d (%v)", len(gotKeys), gotKeys, len(tc.wantMatrices), tc.wantMatrices)
			}
			for i := range gotKeys {
				if gotKeys[i] != tc.wantMatrices[i] {
					t.Errorf("Matrices[%d]=%s, 期望=%s", i, gotKeys[i], tc.wantMatrices[i])
				}
			}
		})
	}
}

// TestRunMiaospeedMissingBinary 验证当 miaospeed 不存在时的明确报错。
func TestRunMiaospeedMissingBinary(t *testing.T) {
	r := newRunnerWithMiaospeed("nexttrace", filepath.Join(t.TempDir(), "non-existent-miaospeed"), nil)
	job := Job{
		ID:     "test-job",
		Kind:   "miaospeed",
		Target: "trojan://pass@example.com:443#Test",
	}

	res := r.run(context.Background(), job)
	if res.ExitCode == 0 || !strings.Contains(res.ErrText, "miaospeed") {
		t.Fatalf("期望启动失败报错，实际: exitCode=%d errText=%q", res.ExitCode, res.ErrText)
	}
}

// TestApplyGHProxy 验证 GitHub 代理前缀规范化与防止重复叠加。
func TestApplyGHProxy(t *testing.T) {
	raw := "https://github.com/AirportR/miaospeed/releases/download/4.7.7/test.tar.gz"
	proxy := "https://gh-proxy.com"
	want := "https://gh-proxy.com/https://github.com/AirportR/miaospeed/releases/download/4.7.7/test.tar.gz"

	if got := applyGHProxy(raw, proxy); got != want {
		t.Fatalf("applyGHProxy 结果异常: got=%q, want=%q", got, want)
	}
	// 重复调用不应叠加
	if got := applyGHProxy(want, proxy); got != want {
		t.Fatalf("不应重复叠加代理前缀: got=%q, want=%q", got, want)
	}
	// 空代理应原样返回
	if got := applyGHProxy(raw, ""); got != raw {
		t.Fatalf("空代理应原样返回: got=%q, want=%q", got, raw)
	}
}

// TestAutoInstallMiaospeedWithProxy 验证自动下载解压与 ghProxy 代理前缀的继承与调用。
func TestAutoInstallMiaospeedWithProxy(t *testing.T) {
	// 构建内存中的 fake miaospeed tar.gz
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	content := []byte("#!/bin/sh\necho fake-miaospeed\n")
	hdr := &tar.Header{
		Name:     "miaospeed-linux-amd64",
		Mode:     0755,
		Size:     int64(len(content)),
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
	tw.Close()
	gw.Close()
	tarBytes := buf.Bytes()

	// 启动模拟代理服务器
	var requestedURLs []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedURLs = append(requestedURLs, r.URL.String())
		if strings.Contains(r.URL.Path, "releases/latest") {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"tag_name":"4.7.7"}`))
			return
		}
		if strings.Contains(r.URL.Path, ".tar.gz") {
			w.Header().Set("Content-Type", "application/gzip")
			w.Write(tarBytes)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "bin", "miaospeed")
	path, err := autoInstallMiaospeed(context.Background(), dest, srv.URL, nil)
	if err != nil {
		t.Fatalf("autoInstallMiaospeed 失败: %v", err)
	}

	if path != dest {
		t.Fatalf("安装路径异常: got=%q, want=%q", path, dest)
	}
	fi, err := os.Stat(path)
	if err != nil || (fi.Mode()&0111) == 0 {
		t.Fatalf("安装产物不存在或不可执行: %v", err)
	}

	if len(requestedURLs) < 1 {
		t.Fatalf("未通过代理服务器请求下载: %v", requestedURLs)
	}
	if !strings.Contains(requestedURLs[0], ".tar.gz") {
		t.Fatalf("代理请求的不是 release 资源包: %s", requestedURLs[0])
	}
}

// TestParseMatrixGeoWithoutGeoIP 验证当节点不可用且仅包含 Domain 时不应错误识别为 Geo。
func TestParseMatrixGeoWithoutGeoIP(t *testing.T) {
	dummyPayload := `{"Domain":"🚫 账号已被删除或不存在"}`
	ip, geo := parseMatrixGeo(dummyPayload)
	if ip != "" || geo != "" {
		t.Fatalf("无有效 GeoIP 栈时期望空值，实际 ip=%q geo=%q", ip, geo)
	}

	validPayload := `{"MainStack":{"country":"Japan","isp":"SoftBank","ip":"1.2.3.4"}}`
	ip, geo = parseMatrixGeo(validPayload)
	if ip != "1.2.3.4" || geo != "Japan SoftBank" {
		t.Fatalf("有效 GeoIP 解析异常，实际 ip=%q geo=%q", ip, geo)
	}
}

// TestParseSingleSlotFiltersDummyGeo 验证当出口与节点名称相同时自动清理。
func TestParseSingleSlotFiltersDummyGeo(t *testing.T) {
	node := &MiaospeedNode{
		Name:     "🚫 账号已被删除或不存在",
		Protocol: "vless",
		Server:   "jz.ov0.kdns.fr",
	}
	slot := slaveEntrySlot{
		Matrices: []matrixResponse{
			{Type: matrixOutboundGeoIP, Payload: `{"Domain":"🚫 账号已被删除或不存在"}`},
		},
	}
	rep := parseSingleSlot(slot, node, miaospeedTestPlan{})
	if rep.OutboundGeo != "" {
		t.Fatalf("同名出口信息期望被过滤为空，实际: %q", rep.OutboundGeo)
	}
}

// TestExtractFieldRobustness 验证加固后的 extractField 对各种复杂 YAML 边界格式的处理能力。
func TestExtractFieldRobustness(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		key  string
		want string
	}{
		{
			name: "单引号包裹且内含逗号与冒号",
			raw:  `{ name: '剩余流量：975.52 GB, 有效期：长期', server: 1.2.3.4, port: 443 }`,
			key:  "name",
			want: "剩余流量：975.52 GB, 有效期：长期",
		},
		{
			name: "双引号包裹且内含逗号",
			raw:  `{ name: "HK, 01 PCCW - VIP", server: hk.node.com, port: 443 }`,
			key:  "name",
			want: "HK, 01 PCCW - VIP",
		},
		{
			name: "防子串误匹配：存在 client-type 时精确匹配 type",
			raw:  `{ client-type: clash, type: vless, server: 1.1.1.1 }`,
			key:  "type",
			want: "vless",
		},
		{
			name: "提取嵌套花括号对象",
			raw:  `{ name: Node1, reality-opts: { public-key: abcdef, short-id: 123456 }, type: vless }`,
			key:  "reality-opts",
			want: "{ public-key: abcdef, short-id: 123456 }",
		},
		{
			name: "嵌套对象之后的普通字段提取",
			raw:  `{ reality-opts: { public-key: abcdef, short-id: 123456 }, type: vless, server: 2.2.2.2 }`,
			key:  "server",
			want: "2.2.2.2",
		},
		{
			name: "键与冒号之间包含多余空白",
			raw:  `{ name  :  "MyNode" , port : 8443 }`,
			key:  "name",
			want: "MyNode",
		},
		{
			name: "无引号标量值后紧跟闭合花括号",
			raw:  `{ server: 1.2.3.4, port: 443 }`,
			key:  "port",
			want: "443",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractField(tc.raw, tc.key)
			if got != tc.want {
				t.Fatalf("extractField(%q, %q) = %q, 期望: %q", tc.raw, tc.key, got, tc.want)
			}
		})
	}
}

// TestParseClashYAMLProxiesRobustness 验证单行和多行 YAML 配置解析。
func TestParseClashYAMLProxiesRobustness(t *testing.T) {
	yamlContent := `
mixed-port: 7890
proxies:
  - { name: '剩余流量：975.52 GB', server: 203.10.98.189, port: 443, udp: true, type: hysteria2, password: pass1, fingerprint: fp1 }
  - { name: 🇯🇵AWS日本1号, type: vless, server: aws.jp.node, port: 443, uuid: u-123, reality-opts: { public-key: pbk1, short-id: sid1 } }
  - name: "多行节点-HY2"
    type: hysteria2
    server: 203.10.99.51
    port: 50000
    ports: 50000-55000
    password: pass2
proxy-groups:
`
	nodes := parseClashYAMLProxies(yamlContent)
	if len(nodes) != 3 {
		t.Fatalf("期望解析出 3 个节点，实际解析出: %d", len(nodes))
	}

	if nodes[0].Name != "剩余流量：975.52 GB" || nodes[0].Protocol != "hysteria2" || nodes[0].Server != "203.10.98.189:443" {
		t.Fatalf("节点 1 解析不符合预期: %+v", nodes[0])
	}

	if nodes[1].Name != "🇯🇵AWS日本1号" || nodes[1].Protocol != "vless" || nodes[1].Server != "aws.jp.node:443" {
		t.Fatalf("节点 2 解析不符合预期: %+v", nodes[1])
	}
	if !strings.Contains(nodes[1].Payload, "reality-opts:") {
		t.Fatalf("节点 2 Payload 应保留 reality-opts，实际: %s", nodes[1].Payload)
	}

	if nodes[2].Name != "多行节点-HY2" || nodes[2].Protocol != "hysteria2" || nodes[2].Server != "203.10.99.51:50000" {
		t.Fatalf("节点 3 解析不符合预期: %+v", nodes[2])
	}
}

// TestParseHysteria2URIComprehensive 验证 parseHysteria2URI 提取指纹、多端口、混淆等参数。
func TestParseHysteria2URIComprehensive(t *testing.T) {
	rawURI := "hysteria2://my-password@203.10.99.51:50000/?sni=www.bing.com&pinSHA256=1d7995901a93bada6d17f10289441793e8ec54ee314d9f04f3a9d05daa622331&mport=50000-55000&obfs=salamander&obfs-password=obfspass123&alpn=h3#%F0%9F%87%AF%F0%9F%87%B5%E6%97%A5%E6%9C%AC%E4%B8%93%E7%BA%BF"
	node, err := parseProxyURI(rawURI)
	if err != nil {
		t.Fatalf("解析 Hysteria2 URI 失败: %v", err)
	}

	if node.Protocol != "hysteria2" || node.Server != "203.10.99.51:50000" || node.Name != "🇯🇵日本专线" {
		t.Fatalf("基础信息不符合预期: %+v", node)
	}

	payload := node.Payload
	if !strings.Contains(payload, `password: "my-password"`) {
		t.Fatalf("Payload 缺少 password: %s", payload)
	}
	if !strings.Contains(payload, `sni: "www.bing.com"`) {
		t.Fatalf("Payload 缺少 sni: %s", payload)
	}
	if !strings.Contains(payload, `fingerprint: "1d7995901a93bada6d17f10289441793e8ec54ee314d9f04f3a9d05daa622331"`) {
		t.Fatalf("Payload 缺少 fingerprint 证书指纹: %s", payload)
	}
	if !strings.Contains(payload, "skip-cert-verify: true") {
		t.Fatalf("Payload 缺少 skip-cert-verify: %s", payload)
	}
	if !strings.Contains(payload, `ports: "50000-55000"`) {
		t.Fatalf("Payload 缺少 ports 多端口跳变: %s", payload)
	}
	if !strings.Contains(payload, `obfs: "salamander"`) || !strings.Contains(payload, `obfs-password: "obfspass123"`) {
		t.Fatalf("Payload 缺少混淆参数: %s", payload)
	}
	if !strings.Contains(payload, `alpn:`) || !strings.Contains(payload, `"h3"`) {
		t.Fatalf("Payload 缺少 alpn 参数: %s", payload)
	}
	if !strings.Contains(payload, "udp: true") {
		t.Fatalf("Payload 缺少 udp: true: %s", payload)
	}
}

// TestParseVlessURIComprehensive 验证 parseVlessURI 提取 Reality、WS、gRPC 等参数。
func TestParseVlessURIComprehensive(t *testing.T) {
	t.Run("Reality 节点", func(t *testing.T) {
		rawURI := "vless://3725dcb7-5767-472d-93be-872cdd4a7e0f@aws.jp:443?type=tcp&security=reality&flow=xtls-rprx-vision&fp=chrome&sni=osxapps.itunes.apple.com&pbk=egq3FRi4oqkJ-iJ40r-pk10g7tawGg6o9c4UDGOPDU4&sid=9824e11ad3a632f8&spx=%2Ftest#AWS-Reality"
		node, err := parseProxyURI(rawURI)
		if err != nil {
			t.Fatalf("解析 VLESS Reality 失败: %v", err)
		}
		if node.Protocol != "vless" || node.Server != "aws.jp:443" || node.Name != "AWS-Reality" {
			t.Fatalf("基础信息不符合预期: %+v", node)
		}
		p := node.Payload
		if !strings.Contains(p, `uuid: 3725dcb7-5767-472d-93be-872cdd4a7e0f`) {
			t.Fatalf("缺少 uuid: %s", p)
		}
		if !strings.Contains(p, `flow: "xtls-rprx-vision"`) {
			t.Fatalf("缺少 flow: %s", p)
		}
		if !strings.Contains(p, `client-fingerprint: "chrome"`) {
			t.Fatalf("缺少 client-fingerprint: %s", p)
		}
		if !strings.Contains(p, `servername: "osxapps.itunes.apple.com"`) {
			t.Fatalf("缺少 servername: %s", p)
		}
		if !strings.Contains(p, "reality-opts:") || !strings.Contains(p, `public-key: "egq3FRi4oqkJ-iJ40r-pk10g7tawGg6o9c4UDGOPDU4"`) || !strings.Contains(p, `short-id: "9824e11ad3a632f8"`) {
			t.Fatalf("缺少 reality-opts: %s", p)
		}
		if !strings.Contains(p, `spider-x: "/test"`) {
			t.Fatalf("缺少 spider-x: %s", p)
		}
	})

	t.Run("WebSocket 节点", func(t *testing.T) {
		rawURI := "vless://my-uuid@cf.node.com:443?type=ws&security=tls&sni=cf.node.com&fp=safari&path=%2Fws-path&host=custom.host.com#CF-WS"
		node, err := parseProxyURI(rawURI)
		if err != nil {
			t.Fatalf("解析 VLESS WS 失败: %v", err)
		}
		p := node.Payload
		if !strings.Contains(p, "ws-opts:") || !strings.Contains(p, `path: "/ws-path"`) || !strings.Contains(p, `Host: "custom.host.com"`) {
			t.Fatalf("缺少 ws-opts: %s", p)
		}
	})

	t.Run("gRPC 节点", func(t *testing.T) {
		rawURI := "vless://my-uuid@grpc.node.com:443?type=grpc&security=tls&sni=grpc.node.com&serviceName=my-grpc-service#GRPC-Node"
		node, err := parseProxyURI(rawURI)
		if err != nil {
			t.Fatalf("解析 VLESS gRPC 失败: %v", err)
		}
		p := node.Payload
		if !strings.Contains(p, "grpc-opts:") || !strings.Contains(p, `grpc-service-name: "my-grpc-service"`) {
			t.Fatalf("缺少 grpc-opts: %s", p)
		}
	})
}

// TestFetchAndParseSubscriptionClashMetaPriority 验证优先使用 ClashMeta UA 并拉取原生配置。
func TestFetchAndParseSubscriptionClashMetaPriority(t *testing.T) {
	var requestedUAs []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua := r.Header.Get("User-Agent")
		requestedUAs = append(requestedUAs, ua)

		if ua == "ClashMeta" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`
mixed-port: 7890
proxies:
  - { name: '原生Meta节点1', type: hysteria2, server: 1.2.3.4, port: 443 }
  - { name: '原生Meta节点2', type: vless, server: 5.6.7.8, port: 443 }
`))
			return
		}

		// 其他 UA 返回空或错误
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	nodes, err := fetchAndParseSubscription(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("拉取订阅失败: %v", err)
	}

	if len(requestedUAs) != 1 || requestedUAs[0] != "ClashMeta" {
		t.Fatalf("期望首选 ClashMeta UA 且一次成功，实际请求 UA: %v", requestedUAs)
	}

	if len(nodes) != 2 || nodes[0].Name != "原生Meta节点1" || nodes[1].Name != "原生Meta节点2" {
		t.Fatalf("解析出的节点不符合预期: %+v", nodes)
	}
}

// TestParseTuicURI 验证 parseTuicURI 解析 TUIC URI 规范及参数构造。
func TestParseTuicURI(t *testing.T) {
	rawURI := "tuic://my-uuid-123:my-password-456@tuic.example.com:8444/?sni=tuic.example.com&alpn=h3&congestion_control=bbr&udp_relay_mode=native&allow_insecure=1#%F0%9F%87%AF%F0%9F%87%B5%E6%97%A5%E6%9C%AC-TUIC"
	node, err := parseProxyURI(rawURI)
	if err != nil {
		t.Fatalf("解析 TUIC URI 失败: %v", err)
	}

	if node.Protocol != "tuic" || node.Server != "tuic.example.com:8444" || node.Name != "🇯🇵日本-TUIC" {
		t.Fatalf("基础信息不符合预期: %+v", node)
	}

	p := node.Payload
	if !strings.Contains(p, "type: tuic") {
		t.Fatalf("Payload 缺少 type: tuic: %s", p)
	}
	if !strings.Contains(p, `uuid: "my-uuid-123"`) || !strings.Contains(p, `password: "my-password-456"`) {
		t.Fatalf("Payload 缺少 uuid 或 password: %s", p)
	}
	if !strings.Contains(p, `sni: "tuic.example.com"`) {
		t.Fatalf("Payload 缺少 sni: %s", p)
	}
	if !strings.Contains(p, "alpn:") || !strings.Contains(p, `"h3"`) {
		t.Fatalf("Payload 缺少 alpn: %s", p)
	}
	if !strings.Contains(p, `congestion-controller: "bbr"`) || !strings.Contains(p, `udp-relay-mode: "native"`) {
		t.Fatalf("Payload 缺少拥塞控制或 UDP 中继参数: %s", p)
	}
	if !strings.Contains(p, "skip-cert-verify: true") {
		t.Fatalf("Payload 缺少 skip-cert-verify: %s", p)
	}
	if !strings.Contains(p, "udp: true") {
		t.Fatalf("Payload 缺少 udp: true: %s", p)
	}
}

// TestParseClashYAMLStandaloneDashAndSubarray 验证独立破折号与子数组缩进情况下的节点切分。
func TestParseClashYAMLStandaloneDashAndSubarray(t *testing.T) {
	sampleYAML := `
mixed-port: 7890
proxies:
  -
    name: '节点1-TUIC'
    type: tuic
    server: jp1.node.com
    port: 8444
    uuid: u-123
    password: p-123
    alpn:
      - h3
    congestion-controller: bbr
  -
    name: '节点2-HY2'
    server: jp2.node.com
    port: 443
    type: hysteria2
    password: p-456
    ports: 20000-25000
proxy-groups:
`
	nodes := parseClashYAMLProxies(sampleYAML)
	if len(nodes) != 2 {
		t.Fatalf("期望解析出 2 个节点，实际解析出 %d 个", len(nodes))
	}

	if nodes[0].Name != "节点1-TUIC" || nodes[0].Protocol != "tuic" || nodes[0].Server != "jp1.node.com:8444" {
		t.Fatalf("节点 1 解析不符合预期: %+v", nodes[0])
	}
	if !strings.Contains(nodes[0].Payload, "alpn:\n  - h3") {
		t.Fatalf("节点 1 子数组缩进被破坏: %s", nodes[0].Payload)
	}

	if nodes[1].Name != "节点2-HY2" || nodes[1].Protocol != "hysteria2" || nodes[1].Server != "jp2.node.com:443" {
		t.Fatalf("节点 2 解析不符合预期: %+v", nodes[1])
	}
	if !strings.Contains(nodes[1].Payload, "ports: 20000-25000") {
		t.Fatalf("节点 2 Payload 缺少 ports: %s", nodes[1].Payload)
	}
}

// TestRunMiaospeedTuicLive 实测真实 TUIC 节点的 MiaoSpeed 连通性。
func TestRunMiaospeedTuicLive(t *testing.T) {
	if _, err := os.Stat("/tmp/miaospeed"); err != nil {
		t.Skip("本地未找到 /tmp/miaospeed，跳过实机测速")
	}

	rawPayload := "name: \"TUIC-Test\"\ntype: tuic\nserver: jp4.mtf.llc\nport: 8444\nuuid: 74503f56-4b80-4017-a062-04c6d8a25527\npassword: 74503f56-4b80-4017-a062-04c6d8a25527\nskip-cert-verify: false\nalpn:\n  - h3\ncongestion-controller: bbr\nudp-relay-mode: native\n"
	job := Job{
		ID:     "live-tuic-01",
		Kind:   "miaospeed",
		Target: rawPayload,
		Query:  "conn",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res, raw, err := runMiaospeedJob(ctx, "/tmp/miaospeed", "", job, testLogger{t}, func(p Progress) {
		t.Logf("Progress: %d/%d (%s)", p.Current, p.Total, p.NodeName)
	})
	if err != nil {
		t.Fatalf("TUIC 测速失败: %v", err)
	}
	t.Logf("TUIC 测速结果: %s", res)
	if !strings.Contains(string(raw), `"http_code":204`) {
		t.Fatalf("期望 HTTP 204，实际: %s", string(raw))
	}
}

// TestFetchMtfSubscriptionAllNodes 验证从真实的 mtf.llc 订阅中完整拉取全部节点（含 VLESS, HY2, TUIC）。
func TestFetchMtfSubscriptionAllNodes(t *testing.T) {
	subURL := "https://mtf.llc/s/87d9ad4e06304a12638ccfc9552274b5"
	nodes, err := fetchAndParseSubscription(context.Background(), subURL)
	if err != nil {
		if strings.Contains(err.Error(), "429") || strings.Contains(err.Error(), "超时") || strings.Contains(err.Error(), "connect") {
			t.Skipf("外部机场订阅限流或网络不可达，跳过在线测试: %v", err)
		}
		t.Fatalf("拉取 mtf 订阅失败: %v", err)
	}

	// 上游机场节点数量可能变动，只校验不少于 40 个且三种协议均存在
	if len(nodes) < 40 {
		t.Fatalf("期望至少拉取 40 个节点，实际拉取 %d 个节点", len(nodes))
	}

	protoCounts := make(map[string]int)
	for _, n := range nodes {
		protoCounts[n.Protocol]++
	}
	t.Logf("订阅节点协议分布: %+v", protoCounts)
	if protoCounts["tuic"] == 0 || protoCounts["vless"] == 0 || protoCounts["hysteria2"] == 0 {
		t.Fatalf("协议分布不完整: %+v", protoCounts)
	}
}

// TestParseSSRURI 验证 ShadowsocksR URI 解析（含 remarks/obfsparam/protoparam）。
func TestParseSSRURI(t *testing.T) {
	// SSR 标准格式：host:port:protocol:method:obfs:base64(password)/?remarks=base64&obfsparam=base64&protoparam=base64
	inner := "1.2.3.4:8388:auth_aes128_md5:aes-128-cfb:tls1.2_ticket_auth:" +
		base64.URLEncoding.EncodeToString([]byte("pass123")) +
		"/?remarks=" + base64.URLEncoding.EncodeToString([]byte("香港SSR")) +
		"&obfsparam=" + base64.URLEncoding.EncodeToString([]byte("bing.com")) +
		"&protoparam=" + base64.URLEncoding.EncodeToString([]byte("123456"))
	uri := "ssr://" + base64.URLEncoding.EncodeToString([]byte(inner))

	node, err := parseProxyURI(uri)
	if err != nil {
		t.Fatalf("解析 SSR 失败: %v", err)
	}
	if node.Protocol != "ssr" || node.Server != "1.2.3.4:8388" || node.Name != "香港SSR" {
		t.Fatalf("基础信息不符合预期: %+v", node)
	}
	p := node.Payload
	if !strings.Contains(p, "type: ssr") || !strings.Contains(p, "cipher: aes-128-cfb") || !strings.Contains(p, `password: "pass123"`) {
		t.Fatalf("Payload 缺少核心字段: %s", p)
	}
	if !strings.Contains(p, "protocol: auth_aes128_md5") || !strings.Contains(p, "obfs: tls1.2_ticket_auth") {
		t.Fatalf("Payload 缺少协议或混淆: %s", p)
	}
	if !strings.Contains(p, `obfs-param: "bing.com"`) || !strings.Contains(p, `protocol-param: "123456"`) {
		t.Fatalf("Payload 缺少参数: %s", p)
	}
	if !strings.Contains(p, "udp: true") {
		t.Fatalf("Payload 缺少 udp: %s", p)
	}
}

// TestParseHysteria1URI 验证 Hysteria v1 URI 解析。
func TestParseHysteria1URI(t *testing.T) {
	uri := "hysteria://hy1.node.com:443?auth=secret123&upmbps=100&downmbps=200&peer=hy1.node.com&insecure=1&alpn=h3#HY1-Test"
	node, err := parseProxyURI(uri)
	if err != nil {
		t.Fatalf("解析 Hysteria1 失败: %v", err)
	}
	if node.Protocol != "hysteria" || node.Server != "hy1.node.com:443" || node.Name != "HY1-Test" {
		t.Fatalf("基础信息不符合预期: %+v", node)
	}
	p := node.Payload
	if !strings.Contains(p, "type: hysteria") || !strings.Contains(p, "protocol: udp") {
		t.Fatalf("Payload 缺少协议信息: %s", p)
	}
	if !strings.Contains(p, `auth-str: "secret123"`) || !strings.Contains(p, `up: "100"`) || !strings.Contains(p, `down: "200"`) {
		t.Fatalf("Payload 缺少 auth/up/down: %s", p)
	}
	if !strings.Contains(p, `sni: "hy1.node.com"`) || !strings.Contains(p, "skip-cert-verify: true") {
		t.Fatalf("Payload 缺少 TLS 配置: %s", p)
	}
}

// TestParseSocks5URI 验证 SOCKS5 URI 解析。
func TestParseSocks5URI(t *testing.T) {
	uri := "socks5://admin:123456@proxy.lan:1080#Local-Socks5"
	node, err := parseProxyURI(uri)
	if err != nil {
		t.Fatalf("解析 Socks5 失败: %v", err)
	}
	if node.Protocol != "socks5" || node.Server != "proxy.lan:1080" || node.Name != "Local-Socks5" {
		t.Fatalf("基础信息不符合预期: %+v", node)
	}
	p := node.Payload
	if !strings.Contains(p, "type: socks5") || !strings.Contains(p, `username: "admin"`) || !strings.Contains(p, `password: "123456"`) {
		t.Fatalf("Payload 缺少认证信息: %s", p)
	}
	if !strings.Contains(p, "udp: true") {
		t.Fatalf("Payload 缺少 udp: %s", p)
	}
}

// TestParseSnellURI 验证 Snell URI 解析。
func TestParseSnellURI(t *testing.T) {
	uri := "snell://snell.node.com:443?psk=mysnellsecret&version=4&obfs=http&host=bing.com#Snell-Test"
	node, err := parseProxyURI(uri)
	if err != nil {
		t.Fatalf("解析 Snell 失败: %v", err)
	}
	if node.Protocol != "snell" || node.Server != "snell.node.com:443" || node.Name != "Snell-Test" {
		t.Fatalf("基础信息不符合预期: %+v", node)
	}
	p := node.Payload
	if !strings.Contains(p, "type: snell") || !strings.Contains(p, `psk: "mysnellsecret"`) || !strings.Contains(p, "version: 4") {
		t.Fatalf("Payload 缺少核心字段: %s", p)
	}
	if !strings.Contains(p, "obfs-opts:") || !strings.Contains(p, `mode: "http"`) || !strings.Contains(p, `host: "bing.com"`) {
		t.Fatalf("Payload 缺少 obfs-opts: %s", p)
	}
}

// TestParseVMessEnhanced 验证 VMess 解析增强（gRPC、指纹、UDP）。
func TestParseVMessEnhanced(t *testing.T) {
	v := map[string]any{
		"v":    "2",
		"ps":   "JP-VMess-gRPC",
		"add":  "grpc.jp.example",
		"port": 443,
		"id":   "b831381d-6324-4d53-ad4f-8cda48b30811",
		"aid":  0,
		"scy":  "auto",
		"net":  "grpc",
		"tls":  "tls",
		"path": "my-grpc-svc",
		"host": "grpc.jp.example",
		"sni":  "grpc.jp.example",
		"fp":   "chrome",
	}
	b, _ := json.Marshal(v)
	uri := "vmess://" + base64.StdEncoding.EncodeToString(b)
	node, err := parseProxyURI(uri)
	if err != nil {
		t.Fatalf("解析 VMess 失败: %v", err)
	}
	if node.Protocol != "vmess" || node.Name != "JP-VMess-gRPC" {
		t.Fatalf("基础信息不符合预期: %+v", node)
	}
	p := node.Payload
	if !strings.Contains(p, "grpc-opts:") || !strings.Contains(p, `grpc-service-name: "my-grpc-svc"`) {
		t.Fatalf("Payload 缺少 grpc-opts: %s", p)
	}
	if !strings.Contains(p, `client-fingerprint: "chrome"`) {
		t.Fatalf("Payload 缺少 client-fingerprint: %s", p)
	}
	if !strings.Contains(p, "udp: true") {
		t.Fatalf("Payload 缺少 udp: %s", p)
	}
}

// TestParseSSEnhanced 验证 Shadowsocks 解析增强（plugin、UDP）。
func TestParseSSEnhanced(t *testing.T) {
	// SIP002 带 plugin
	userInfo := base64.URLEncoding.EncodeToString([]byte("aes-128-gcm:pass123"))
	uri := "ss://" + userInfo + "@1.2.3.4:8388?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dbing.com#HK-SS"
	node, err := parseProxyURI(uri)
	if err != nil {
		t.Fatalf("解析 SS 失败: %v", err)
	}
	if node.Protocol != "ss" || node.Server != "1.2.3.4:8388" || node.Name != "HK-SS" {
		t.Fatalf("基础信息不符合预期: %+v", node)
	}
	p := node.Payload
	if !strings.Contains(p, "type: ss") || !strings.Contains(p, "udp: true") {
		t.Fatalf("Payload 缺少 udp: %s", p)
	}
	if !strings.Contains(p, `plugin: "obfs-local"`) {
		t.Fatalf("Payload 缺少 plugin: %s", p)
	}
}

// TestMiaospeedMultiNodeBatchPlanAndTotalNodes 验证批量测速计划时长优化与 TotalNodes 跟踪。
func TestMiaospeedMultiNodeBatchPlanAndTotalNodes(t *testing.T) {
	// 1. 单节点默认下载测速 5s
	planSingle := buildMiaospeedTestPlan(Job{Query: "full"}, 1)
	if planSingle.DownloadDuration != 5 {
		t.Fatalf("单节点期望下载时长 5s，实际: %d", planSingle.DownloadDuration)
	}

	// 2. 多节点批量测速下载时长优化为 3s
	planMulti := buildMiaospeedTestPlan(Job{Query: "full"}, 48)
	if planMulti.DownloadDuration != 3 {
		t.Fatalf("多节点期望下载时长 3s，实际: %d", planMulti.DownloadDuration)
	}

	// 3. parseSlaveTaskResult 正确记录 TotalNodes
	task := &slaveTask{
		Results: []slaveEntrySlot{
			{Grouping: "g1"},
			{Grouping: "g2"},
		},
	}
	nodes := []MiaospeedNode{
		{Name: "Node1"},
		{Name: "Node2"},
	}
	rep := parseSlaveTaskResult(task, nodes, 48, planMulti, 10*time.Second)
	if rep.TotalNodes != 48 {
		t.Fatalf("期望 TotalNodes=48，实际: %d", rep.TotalNodes)
	}
	if len(rep.SubReports) != 2 {
		t.Fatalf("期望 SubReports=2，实际: %d", len(rep.SubReports))
	}
	if rep.SubReports[0].TotalNodes != 48 {
		t.Fatalf("SubReport 期望 TotalNodes=48，实际: %d", rep.SubReports[0].TotalNodes)
	}
}

// TestSelectJobNodesUnlimited 验证节点数量默认无上限，仅在指定 Count 时截取。
func TestSelectJobNodesUnlimited(t *testing.T) {
	nodes := make([]MiaospeedNode, 150)
	for i := range nodes {
		nodes[i] = MiaospeedNode{Name: fmt.Sprintf("Node-%d", i+1)}
	}

	// 1. 未指定 Count (0 或负数) 时，全量保留全部 150 个节点，不再受原 80 个上限限制
	selected := selectJobNodes(nodes, 0)
	if len(selected) != 150 {
		t.Fatalf("默认期望无上限 (150 个节点)，实际: %d", len(selected))
	}
	selectedNeg := selectJobNodes(nodes, -1)
	if len(selectedNeg) != 150 {
		t.Fatalf("负数 Count 期望全量保留 (150 个节点)，实际: %d", len(selectedNeg))
	}

	// 2. 指定有效 Count 时按 Count 截断
	selectedCount := selectJobNodes(nodes, 60)
	if len(selectedCount) != 60 {
		t.Fatalf("指定 Count=60 期望截取 60 个节点，实际: %d", len(selectedCount))
	}

	// 3. 指定 Count 超过总数时返回全部节点
	selectedOver := selectJobNodes(nodes, 200)
	if len(selectedOver) != 150 {
		t.Fatalf("指定 Count 超限期望返回全部 150 个节点，实际: %d", len(selectedOver))
	}
}

// TestCalcMiaospeedTimeout 验证测试时间限制根据节点数量动态计算。
func TestCalcMiaospeedTimeout(t *testing.T) {
	// 1. 单节点保底 90s
	if got := CalcMiaospeedTimeout(0); got != 90*time.Second {
		t.Fatalf("0 节点期望保底 90s，实际: %v", got)
	}
	if got := CalcMiaospeedTimeout(1); got != 90*time.Second {
		t.Fatalf("1 节点期望保底 90s，实际: %v", got)
	}

	// 2. 10 节点: 60s + 10*12s = 180s (3 分钟)
	if got := CalcMiaospeedTimeout(10); got != 180*time.Second {
		t.Fatalf("10 节点期望 180s，实际: %v", got)
	}

	// 3. 100 节点: 60s + 100*12s = 1260s (21 分钟)
	if got := CalcMiaospeedTimeout(100); got != 1260*time.Second {
		t.Fatalf("100 节点期望 1260s，实际: %v", got)
	}

	// 4. 200 节点: 60s + 200*12s = 2460s (41 分钟)
	if got := CalcMiaospeedTimeout(200); got != 2460*time.Second {
		t.Fatalf("200 节点期望 2460s，实际: %v", got)
	}
}

// TestMiaospeedJobTimeoutAllowsLongRuns 验证 miaospeed 任务在 client 侧允许超过普通任务 10 分钟上限。
func TestMiaospeedJobTimeoutAllowsLongRuns(t *testing.T) {
	// 普通任务被限制在 10 分钟
	normalJob := Job{Kind: "ping", TimeoutMS: 1800000} // 30 分钟
	if got := normalJob.Timeout(); got != 10*time.Minute {
		t.Fatalf("普通任务期望夹在 10 分钟，实际: %v", got)
	}

	// miaospeed 任务允许长达数十分钟甚至数小时
	miaoJob := Job{Kind: "miaospeed", TimeoutMS: 1800000} // 30 分钟
	if got := miaoJob.Timeout(); got != 30*time.Minute {
		t.Fatalf("miaospeed 任务期望允许 30 分钟，实际: %v", got)
	}
}

// TestParseProxyContent_Configs 验证对各类代理配置文件（Clash YAML、Sing-box JSON、裸列表、Base64及多行URI）的解析。
func TestParseProxyContent_Configs(t *testing.T) {
	t.Run("Clash YAML 完整配置文件（带顶格注释、BOM与CRLF）", func(t *testing.T) {
		clashConfig := "\xef\xbb\xbfport: 7890\r\nsocks-port: 7891\r\nallow-lan: true\r\nmode: Rule\r\n\r\nproxies:\r\n" +
			"# 顶格注释不应阻断解析\r\n" +
			"  - name: \"HK-01\"\r\n" +
			"    type: ss\r\n" +
			"    server: 1.1.1.1\r\n" +
			"    port: 8388\r\n" +
			"    cipher: aes-128-gcm\r\n" +
			"    password: \"pass123\"\r\n" +
			"# 第二段顶格注释\r\n" +
			"  - {name: \"JP-02\", type: trojan, server: 2.2.2.2, port: 443, password: \"trojanpass\"}\r\n" +
			"\r\nproxy-groups:\r\n  - name: PROXY\r\n    type: select\r\n    proxies:\r\n      - HK-01\r\n"

		nodes, err := parseProxyContent(clashConfig)
		if err != nil {
			t.Fatalf("解析 Clash 配置文件失败: %v", err)
		}
		if len(nodes) != 2 {
			t.Fatalf("期望解析出 2 个节点，实际: %d (%+v)", len(nodes), nodes)
		}
		if nodes[0].Name != "HK-01" || nodes[0].Protocol != "ss" || nodes[0].Server != "1.1.1.1:8388" {
			t.Errorf("节点 1 解析不符合预期: %+v", nodes[0])
		}
		if nodes[1].Name != "JP-02" || nodes[1].Protocol != "trojan" || nodes[1].Server != "2.2.2.2:443" {
			t.Errorf("节点 2 解析不符合预期: %+v", nodes[1])
		}
	})

	t.Run("裸 YAML 节点列表（无顶层 proxies:）", func(t *testing.T) {
		rawYaml := `- name: "US-01"
  type: hysteria2
  server: us.example.com
  port: 8443
  password: "hy2password"
- name: "SG-02"
  type: vless
  server: sg.example.com
  port: 443
  uuid: "00000000-0000-0000-0000-000000000000"
`
		nodes, err := parseProxyContent(rawYaml)
		if err != nil {
			t.Fatalf("解析裸 YAML 列表失败: %v", err)
		}
		if len(nodes) != 2 {
			t.Fatalf("期望解析出 2 个节点，实际: %d", len(nodes))
		}
		if nodes[0].Name != "US-01" || nodes[0].Protocol != "hysteria2" {
			t.Errorf("节点 1 异常: %+v", nodes[0])
		}
		if nodes[1].Name != "SG-02" || nodes[1].Protocol != "vless" {
			t.Errorf("节点 2 异常: %+v", nodes[1])
		}
	})

	t.Run("Sing-box JSON 配置文件（包含 outbounds 与 Reality）", func(t *testing.T) {
		singboxJSON := `{
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct-out"
    },
    {
      "type": "vless",
      "tag": "US-Reality",
      "server": "us-reality.com",
      "server_port": 443,
      "uuid": "uuid-1234",
      "flow": "xtls-rprx-vision",
      "tls": {
        "enabled": true,
        "server_name": "yahoo.com",
        "utls": {
          "enabled": true,
          "fingerprint": "chrome"
        },
        "reality": {
          "enabled": true,
          "public_key": "pubkey-123",
          "short_id": "short-1"
        }
      }
    },
    {
      "type": "shadowsocks",
      "tag": "HK-SS",
      "server": "1.2.3.4",
      "server_port": 8388,
      "method": "2022-blake3-aes-128-gcm",
      "password": "sspassword"
    },
    {
      "type": "block",
      "tag": "block-out"
    }
  ]
}`
		nodes, err := parseProxyContent(singboxJSON)
		if err != nil {
			t.Fatalf("解析 Sing-box JSON 失败: %v", err)
		}
		if len(nodes) != 2 {
			t.Fatalf("期望解析出 2 个节点（过滤 direct/block），实际: %d", len(nodes))
		}
		if nodes[0].Name != "US-Reality" || nodes[0].Protocol != "vless" {
			t.Errorf("Sing-box VLESS 节点解析错误: %+v", nodes[0])
		}
		if !strings.Contains(nodes[0].Payload, "reality-opts:") || !strings.Contains(nodes[0].Payload, `public-key: "pubkey-123"`) {
			t.Errorf("Sing-box Reality Payload 错误:\n%s", nodes[0].Payload)
		}
		if nodes[1].Name != "HK-SS" || nodes[1].Protocol != "ss" {
			t.Errorf("Sing-box SS 节点解析错误: %+v", nodes[1])
		}
	})

	t.Run("Base64 订阅文本文件", func(t *testing.T) {
		plainList := "trojan://pass1@t1.com:443#Trojan-1\r\nvless://uuid@v1.com:443?security=tls#VLESS-1\r\n"
		b64Content := base64.StdEncoding.EncodeToString([]byte(plainList))

		nodes, err := parseProxyContent(b64Content)
		if err != nil {
			t.Fatalf("解析 Base64 订阅失败: %v", err)
		}
		if len(nodes) != 2 {
			t.Fatalf("期望解析出 2 个节点，实际: %d", len(nodes))
		}
		if nodes[0].Name != "Trojan-1" || nodes[1].Name != "VLESS-1" {
			t.Errorf("Base64 节点名称解析异常: %+v", nodes)
		}
	})

	t.Run("多行代理 URI 文本文件（带空行与注释）", func(t *testing.T) {
		multiLines := `# 我的自建节点
ss://YWVzLTEyOC1nY206cGFzczEyMw==@1.2.3.4:8388#My-SS

// 备用节点
hysteria2://mypass@hy2.example:443#My-HY2
`
		nodes, err := parseProxyContent(multiLines)
		if err != nil {
			t.Fatalf("解析多行 URI 文本失败: %v", err)
		}
		if len(nodes) != 2 {
			t.Fatalf("期望解析出 2 个节点，实际: %d", len(nodes))
		}
		if nodes[0].Name != "My-SS" || nodes[1].Name != "My-HY2" {
			t.Errorf("多行 URI 节点名称异常: %+v", nodes)
		}
	})

	t.Run("单个原生 YAML 节点", func(t *testing.T) {
		singleYaml := `name: "My-Single-Node"
type: trojan
server: single.example.com
port: 443
password: "pwd"
`
		nodes, err := parseProxyContent(singleYaml)
		if err != nil {
			t.Fatalf("解析单原生 YAML 节点失败: %v", err)
		}
		if len(nodes) != 1 {
			t.Fatalf("期望解析出 1 个节点，实际: %d", len(nodes))
		}
		if nodes[0].Name != "My-Single-Node" || nodes[0].Protocol != "trojan" || nodes[0].Server != "single.example.com:443" {
			t.Errorf("单 YAML 节点解析异常: %+v", nodes[0])
		}
	})
}

// TestMultiNodePlanSkipsHijackAndIncludesFastIPScript 验证多节点批量测速跳过硬编码 42s 超时的 matrixHijack 并注入快速 GeoIP 脚本。
func TestMultiNodePlanSkipsHijackAndIncludesFastIPScript(t *testing.T) {
	// 单节点应包含 matrixHijack
	planSingle := buildMiaospeedTestPlan(Job{Query: "full"}, 1)
	hasHijackSingle := false
	for _, m := range planSingle.Matrices {
		if m.Type == matrixHijack {
			hasHijackSingle = true
			break
		}
	}
	if !hasHijackSingle {
		t.Fatal("单节点全量测速应保留 matrixHijack")
	}

	// 多节点（如 130 个节点）应跳过 matrixHijack，避免每个死节点被硬编码 42s 超时阻塞
	planMulti := buildMiaospeedTestPlan(Job{Query: "full"}, 130)
	for _, m := range planMulti.Matrices {
		if m.Type == matrixHijack {
			t.Fatal("多节点全量测速不应包含 matrixHijack（会导致死节点卡住 42s）")
		}
	}

	// 验证注入了 Type: "ip" 的快速 GeoIP 脚本
	hasFastIP := false
	for _, s := range planMulti.Scripts {
		if s.Type == "ip" && strings.Contains(s.Content, "ip_resolve") {
			hasFastIP = true
			break
		}
	}
	if !hasFastIP {
		t.Fatal("全量测速脚本应包含 Type=ip 的快速 ip_resolve 脚本以避免默认 IPv6 超时")
	}
}

// TestExecuteMiaospeedTaskPreservesPartialProgressOnTimeout 验证当多节点测速中途超时或断开时，已测完的节点结果不会丢失。
func TestExecuteMiaospeedTaskPreservesPartialProgressOnTimeout(t *testing.T) {
	token := "secret-token"
	handler := websocket.Handler(func(ws *websocket.Conn) {
		var req slaveRequest
		if err := websocket.JSON.Receive(ws, &req); err != nil {
			return
		}
		// 发送前 2 个节点的完成进度
		for i := 0; i < 2; i++ {
			_ = websocket.JSON.Send(ws, slaveResponse{
				Progress: &slaveProgress{
					Index: i,
					Record: &slaveEntrySlot{
						Grouping: "test",
						Matrices: []matrixResponse{
							{Type: matrixRTTPing, Payload: `{"Value":25.0}`},
							{Type: matrixHTTPPing, Payload: `{"Value":35.0}`},
							{Type: matrixPacketLoss, Payload: `{"Value":0}`},
						},
					},
				},
			})
		}
		// 模拟第 3 个节点卡住直到客户端上下文超时
		time.Sleep(500 * time.Millisecond)
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	wsURL := "ws://" + server.Listener.Addr().String() + "/"
	origin := "http://" + server.Listener.Addr().String() + "/"
	nodes := []MiaospeedNode{
		{Name: "Node-1", Protocol: "vless", Server: "1.1.1.1:443"},
		{Name: "Node-2", Protocol: "vless", Server: "2.2.2.2:443"},
		{Name: "Node-3-Stuck", Protocol: "vless", Server: "3.3.3.3:443"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	report, err := executeMiaospeedTask(ctx, wsURL, origin, token, nodes, 3, Job{ID: "partial-test"}, nil, nil)
	if err != nil {
		t.Fatalf("期望在有已完成节点进度时返回部分结果而非报错丢弃，实际 err=%v", err)
	}
	if len(report.SubReports) != 2 {
		t.Fatalf("期望保留已完成的 2 个节点报告，实际: %d", len(report.SubReports))
	}
	if report.SubReports[0].NodeName != "Node-1" || report.SubReports[1].NodeName != "Node-2" {
		t.Fatalf("保留的节点名称异常: %+v", report.SubReports)
	}
}

// TestIPv6NodeSupportAndDualStackScript 验证全协议对 IPv6 字面量节点地址的解析、安全引用格式化及双栈落地探测脚本。
func TestIPv6NodeSupportAndDualStackScript(t *testing.T) {
	t.Run("VLESS IPv6 节点", func(t *testing.T) {
		uri := "vless://80a6c919-fcc8-49da-ace8-84bf0b75e81a@[2409:8a71:6a00:1953::615]:443?security=tls&sni=example.com#IPv6-VLESS"
		node, err := parseProxyURI(uri)
		if err != nil {
			t.Fatalf("解析 VLESS IPv6 失败: %v", err)
		}
		if node.Server != "[2409:8a71:6a00:1953::615]:443" {
			t.Fatalf("Server 期望标准中括号 IPv6 host:port，实际: %q", node.Server)
		}
		if !strings.Contains(node.Payload, `server: "2409:8a71:6a00:1953::615"`) {
			t.Fatalf("Payload 期望包含转义后的 IPv6 地址，实际:\n%s", node.Payload)
		}
	})

	t.Run("Trojan IPv6 节点", func(t *testing.T) {
		uri := "trojan://password123@[2001:db8::1]:8443#IPv6-Trojan"
		node, err := parseProxyURI(uri)
		if err != nil {
			t.Fatalf("解析 Trojan IPv6 失败: %v", err)
		}
		if node.Server != "[2001:db8::1]:8443" {
			t.Fatalf("Server 期望 [2001:db8::1]:8443，实际: %q", node.Server)
		}
		if !strings.Contains(node.Payload, `server: "2001:db8::1"`) {
			t.Fatalf("Payload 期望包含 server: \"2001:db8::1\"，实际:\n%s", node.Payload)
		}
	})

	t.Run("Hysteria2 IPv6 节点", func(t *testing.T) {
		uri := "hysteria2://password123@[2606:4700::1]:443?sni=bing.com#IPv6-HY2"
		node, err := parseProxyURI(uri)
		if err != nil {
			t.Fatalf("解析 Hysteria2 IPv6 失败: %v", err)
		}
		if node.Server != "[2606:4700::1]:443" {
			t.Fatalf("Server 期望 [2606:4700::1]:443，实际: %q", node.Server)
		}
		if !strings.Contains(node.Payload, `server: "2606:4700::1"`) {
			t.Fatalf("Payload 期望包含 server: \"2606:4700::1\"，实际:\n%s", node.Payload)
		}
	})

	t.Run("Sing-box JSON IPv6 节点提取", func(t *testing.T) {
		sbJSON := `{
  "outbounds": [
    {
      "type": "vless",
      "tag": "SB-IPv6-Node",
      "server": "2409:8a71:6a00:1953::1",
      "server_port": 443,
      "uuid": "00000000-0000-0000-0000-000000000000"
    }
  ]
}`
		nodes, err := parseProxyContent(sbJSON)
		if err != nil {
			t.Fatalf("解析 Sing-box JSON 失败: %v", err)
		}
		if len(nodes) != 1 {
			t.Fatalf("期望提取 1 个节点，实际: %d", len(nodes))
		}
		if nodes[0].Server != "[2409:8a71:6a00:1953::1]:443" {
			t.Fatalf("Sing-box 提取的 IPv6 节点 Server 期望带中括号，实际: %q", nodes[0].Server)
		}
		if !strings.Contains(nodes[0].Payload, `server: "2409:8a71:6a00:1953::1"`) {
			t.Fatalf("Payload 期望引用 IPv6 纯地址，实际:\n%s", nodes[0].Payload)
		}
	})

	t.Run("双栈快速 IP 探测脚本覆盖与回退", func(t *testing.T) {
		scripts := buildDefaultMediaScripts()
		var ipScript *slaveScript
		for i := range scripts {
			if scripts[i].Type == "ip" {
				ipScript = &scripts[i]
				break
			}
		}
		if ipScript == nil {
			t.Fatal("缺少 Type=ip 的快速探测脚本")
		}
		if !strings.Contains(ipScript.Content, "1.1.1.1") || !strings.Contains(ipScript.Content, "[2606:4700:4700::1111]") {
			t.Fatalf("ip_resolve 必须包含 IPv4 与 IPv6 Cloudflare trace 双端点，实际:\n%s", ipScript.Content)
		}
		if !strings.Contains(ipScript.Content, "ipv6.ipleak.net") {
			t.Fatalf("handler 必须支持 ipv6.ipleak.net 探测 IPv6 归属地，实际:\n%s", ipScript.Content)
		}
	})
}

func TestIPv6InboundGeoFallback(t *testing.T) {
	node := &MiaospeedNode{
		Name:     "SS2022-v6",
		Protocol: "ss",
		Server:   "[2406:da18:1:1::1]:8388",
	}
	// 模拟 miaospeed 遇到 IPv6 时原生未切端口导致只返回 Domain
	slot := slaveEntrySlot{
		Matrices: []matrixResponse{
			{Type: matrixInboundGeoIP, Payload: `{"Domain":"[2406:da18:1:1::1]:8388"}`},
		},
	}
	rep := parseSingleSlot(slot, node, miaospeedTestPlan{})
	if rep.InboundGeo == "" {
		t.Fatal("IPv6 节点的入站信息不应为空")
	}
	if !strings.Contains(rep.InboundGeo, "2406:da18:1:1::1") {
		t.Fatalf("入站信息应包含节点的 IPv6 地址，实际: %q", rep.InboundGeo)
	}
}
