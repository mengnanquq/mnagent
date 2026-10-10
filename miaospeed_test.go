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

	report, err := executeMiaospeedTask(context.Background(), wsURL, origin, token, nodes, job, nil, nil)
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
