package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/net/websocket"
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

	report, err := executeMiaospeedTask(context.Background(), wsURL, origin, token, nodes, job, nil)
	if err != nil {
		t.Fatalf("任务执行失败: %v", err)
	}

	if report.NodeName != "Tokyo-Node" || report.PingRTTMs != 35.2 || report.PingConnMs != 48.6 {
		t.Fatalf("报告延迟不符合预期: %+v", report)
	}
	if report.HTTPCode != 204 || report.UDPType != "FullCone" {
		t.Fatalf("连通性或 UDP 类型不符合预期: %+v", report)
	}
	if report.AvgSpeedBps != 52428800 || report.AvgUploadBps != 20971520 {
		t.Fatalf("报告下行或上行速度不符合预期: %+v", report)
	}
	if report.InboundGeo != "中国 广州 (14.215.x.x)" || report.Hijack != "正常" {
		t.Fatalf("拓扑信息不符合预期: %+v", report)
	}

	formatted := report.Format()
	if !strings.Contains(formatted, "MiaoSpeed 测速报告 · 全量测试") ||
		!strings.Contains(formatted, "UDP NAT 类型: FullCone") ||
		!strings.Contains(formatted, "下行 (4 线程): 平均 50.00 MB/s") ||
		!strings.Contains(formatted, "上行 (4 线程): 平均 20.00 MB/s") {
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
			wantMatrices:      []string{matrixRTTPing, matrixHTTPPing, matrixPacketLoss, matrixHTTPCode, matrixInboundGeoIP, matrixOutboundGeoIP, matrixHijack, matrixUDPType, matrixAverageSpeed, matrixMaxSpeed, matrixAverageUpload, matrixMaxUpload},
			wantDownThreading: 4,
			wantUpThreading:   4,
		},
		{
			name:         "连通性测试 (connectivity)",
			job:          Job{ID: "t1", Query: "connectivity"},
			wantDesc:     "连通性测试",
			wantMatrices: []string{matrixRTTPing, matrixHTTPPing, matrixHTTPCode},
		},
		{
			name:         "拓扑测试 (topology)",
			job:          Job{ID: "t2", Query: "拓扑测试"},
			wantDesc:     "拓扑测试",
			wantMatrices: []string{matrixInboundGeoIP, matrixOutboundGeoIP, matrixHijack},
		},
		{
			name:              "多线程测速 (multithread)",
			job:               Job{ID: "t3", Query: "多线程测速", Count: 8},
			wantDesc:          "多线程测速",
			wantMatrices:      []string{matrixAverageSpeed, matrixMaxSpeed},
			wantDownThreading: 8,
		},
		{
			name:              "单线程测速 (singlethread)",
			job:               Job{ID: "t4", Query: "单线程测速"},
			wantDesc:          "单线程测速",
			wantMatrices:      []string{matrixAverageSpeed, matrixMaxSpeed},
			wantDownThreading: 1,
		},
		{
			name:            "上行速度测试 (upload)",
			job:             Job{ID: "t5", Query: "upload"},
			wantDesc:        "上行速度测试",
			wantMatrices:    []string{matrixAverageUpload, matrixMaxUpload},
			wantUpThreading: 4,
		},
		{
			name:         "延迟测试 (latency)",
			job:          Job{ID: "t6", Query: "latency"},
			wantDesc:     "延迟测试",
			wantMatrices: []string{matrixRTTPing, matrixHTTPPing, matrixPacketLoss, matrixMaxRTTPing},
		},
		{
			name:         "UDP类型测试 (udp)",
			job:          Job{ID: "t7", Query: "udp类型"},
			wantDesc:     "UDP类型测试",
			wantMatrices: []string{matrixUDPType},
		},
		{
			name:         "组合测试：延迟+UDP类型",
			job:          Job{ID: "t8", Query: "latency,udp"},
			wantDesc:     "延迟测试 + UDP类型测试",
			wantMatrices: []string{matrixRTTPing, matrixHTTPPing, matrixPacketLoss, matrixMaxRTTPing, matrixUDPType},
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
