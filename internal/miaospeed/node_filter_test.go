package miaospeed

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"testing"

	yaml2 "gopkg.in/yaml.v2"
)

func TestFilterBlockedNodes(t *testing.T) {
	orig := lookupNodeIPs
	defer func() { lookupNodeIPs = orig }()
	lookupNodeIPs = func(_ context.Context, host string) ([]net.IP, error) {
		switch host {
		case "internal.example":
			return []net.IP{net.ParseIP("10.0.0.5")}, nil
		case "mixed.example":
			return []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("169.254.169.254")}, nil
		case "public.example":
			return []net.IP{net.ParseIP("1.1.1.1")}, nil
		default:
			return nil, errors.New("no such host")
		}
	}

	payload := func(server string) string {
		return "name: n\ntype: ss\nserver: " + server + "\nport: 443\npassword: p\n"
	}
	nodes := []MiaospeedNode{
		{Name: "pub-ip", Server: "8.8.8.8:443", Protocol: "ss", Payload: payload("8.8.8.8")},
		{Name: "pub-domain", Server: "public.example:443", Protocol: "ss", Payload: payload("public.example")},
		{Name: "loopback", Server: "127.0.0.1:22", Protocol: "ss", Payload: payload("127.0.0.1")},
		{Name: "v6-loopback", Server: "[::1]:8080", Protocol: "ss", Payload: payload("::1")},
		{Name: "metadata", Server: "169.254.169.254:80", Protocol: "ss", Payload: payload("169.254.169.254")},
		{Name: "internal-domain", Server: "Internal.Example.:443", Protocol: "ss", Payload: payload("Internal.Example.")},
		{Name: "mixed", Server: "mixed.example:443", Protocol: "ss", Payload: payload("mixed.example")},
		{Name: "unresolvable", Server: "nx.example:443", Protocol: "ss", Payload: payload("nx.example")},
		{Name: "empty", Server: "", Protocol: "ss", Payload: payload("")},
	}
	kept, removed := filterBlockedNodes(context.Background(), nodes, nil)
	// 域名解析失败一律 fail-closed 剔除，只保留能确认安全的节点。
	want := map[string]bool{"pub-ip": true, "pub-domain": true}
	if len(kept) != len(want) {
		t.Fatalf("应保留 %d 个节点，实际 %d：%+v", len(want), len(kept), kept)
	}
	for _, n := range kept {
		if !want[n.Name] {
			t.Fatalf("不应保留节点 %s", n.Name)
		}
	}
	if removed != len(nodes)-len(want) {
		t.Fatalf("剔除数量错误：%d", removed)
	}
	for _, n := range kept {
		if n.Name == "unresolvable" {
			t.Fatal("域名无法解析的节点应被 fail-closed 剔除")
		}
	}
	// 域名节点的 payload 必须钉死到校验过的 IP，Server 字段保留原域名供报告展示。
	for _, n := range kept {
		if n.Name != "pub-domain" {
			continue
		}
		if n.Server != "public.example:443" {
			t.Fatalf("Server 字段不应被改写：%s", n.Server)
		}
		if !strings.Contains(n.Payload, "server: \"1.1.1.1\"") {
			t.Fatalf("payload 的 server 未钉死到校验过的 IP：%s", n.Payload)
		}
	}
}

func TestPinNodeServerIPPinsPayloadAndKeepsSNI(t *testing.T) {
	cases := []struct {
		name     string
		node     MiaospeedNode
		wantIn   []string
		wantNot  []string
		wantFlow bool
	}{
		{
			name: "vmess 无 servername 时补原域名",
			node: MiaospeedNode{
				Name:     "vmess",
				Protocol: "vmess",
				Server:   "edge.example:443",
				Payload:  "name: vmess\ntype: vmess\nserver: edge.example\nport: 443\nuuid: u\n",
			},
			wantIn: []string{"server: \"1.1.1.1\"", "servername: \"edge.example\""},
		},
		{
			name: "trojan 已有 sni 时不覆盖",
			node: MiaospeedNode{
				Name:     "trojan",
				Protocol: "trojan",
				Server:   "edge.example:443",
				Payload:  "name: trojan\ntype: trojan\nserver: edge.example\nport: 443\nsni: \"front.example\"\n",
			},
			wantIn:  []string{"server: \"1.1.1.1\"", "sni: \"front.example\""},
			wantNot: []string{"sni: \"edge.example\""},
		},
		{
			name: "hysteria2 补 sni",
			node: MiaospeedNode{
				Name:     "hy2",
				Protocol: "hysteria2",
				Server:   "edge.example:443",
				Payload:  "name: hy2\ntype: hysteria2\nserver: edge.example\nport: 443\n",
			},
			wantIn: []string{"server: \"1.1.1.1\"", "sni: \"edge.example\""},
		},
		{
			name: "hysteria2 的 peer 不再视为已设置 SNI",
			node: MiaospeedNode{
				Name:     "hy2-peer",
				Protocol: "hysteria2",
				Server:   "edge.example:443",
				Payload:  "name: hy2\ntype: hysteria2\nserver: edge.example\nport: 443\npeer: legacy.example\n",
			},
			wantIn:  []string{"server: \"1.1.1.1\"", "sni: \"edge.example\""},
			wantNot: []string{"sni: \"legacy.example\""},
		},
		{
			name: "http(s) 代理补 sni",
			node: MiaospeedNode{
				Name:     "https",
				Protocol: "http",
				Server:   "edge.example:443",
				Payload:  "name: https\ntype: http\nserver: edge.example\nport: 443\ntls: true\n",
			},
			wantIn: []string{"server: \"1.1.1.1\"", "sni: \"edge.example\""},
		},
		{
			name: "ss 无 SNI 字段",
			node: MiaospeedNode{
				Name:     "ss",
				Protocol: "ss",
				Server:   "edge.example:8388",
				Payload:  "name: ss\ntype: ss\nserver: edge.example\nport: 8388\ncipher: aes-256-gcm\n",
			},
			wantIn:  []string{"server: \"1.1.1.1\""},
			wantNot: []string{"sni:", "servername:"},
		},
		{
			name: "ws Host 不抑制 SNI 补全",
			node: MiaospeedNode{
				Name:     "vless-ws",
				Protocol: "vless",
				Server:   "edge.example:443",
				Payload:  "name: v\nserver: edge.example\nport: 443\nws-opts:\n  headers:\n    Host: \"cdn.example\"\n",
			},
			wantIn: []string{"server: \"1.1.1.1\"", "Host: \"cdn.example\"", "servername: \"edge.example\""},
		},
		{
			name: "IPv6 字面量服务器",
			node: MiaospeedNode{
				Name:     "v6",
				Protocol: "ss",
				Server:   "[2409:8a71::1]:8388",
				Payload:  "name: v6\ntype: ss\nserver: 2409:8a71::1\nport: 8388\n",
			},
			wantIn: []string{"server: \"1.1.1.1\""},
		},
		{
			name: "流式映射改写",
			node: MiaospeedNode{
				Name:     "flow",
				Protocol: "vmess",
				Server:   "edge.example:443",
				Payload:  "{name: flow, type: vmess, server: edge.example, port: 443}",
			},
			wantIn: []string{"server: \"1.1.1.1\"", "servername: \"edge.example\""},
		},
		{
			name: "带缩进的块式映射",
			node: MiaospeedNode{
				Name:     "indented",
				Protocol: "ss",
				Server:   "edge.example:443",
				Payload:  "  name: i\n  type: ss\n  server: edge.example\n  port: 443\n",
			},
			wantIn: []string{"  server: \"1.1.1.1\"\n"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := pinNodeServerIP(tc.node, net.ParseIP("1.1.1.1"))
			if err != nil {
				t.Fatalf("pinNodeServerIP 报错：%v", err)
			}
			for _, w := range tc.wantIn {
				if !strings.Contains(got.Payload, w) {
					t.Fatalf("payload 缺少 %q：%s", w, got.Payload)
				}
			}
			for _, w := range tc.wantNot {
				if strings.Contains(got.Payload, w) {
					t.Fatalf("payload 不应包含 %q：%s", w, got.Payload)
				}
			}
			if got.Server != tc.node.Server {
				t.Fatalf("Server 字段不应被改写：%s", got.Server)
			}
		})
	}
}

func TestPinNodeServerIPRejectsAmbiguousPayload(t *testing.T) {
	cases := []struct {
		name    string
		payload string
	}{
		{"缺少 server 字段", "name: a\ntype: ss\nport: 443\n"},
		{"重复 server 字段", "name: a\nserver: 1.1.1.1\nport: 443\nserver: 6.6.6.6\n"},
		{"只有嵌套 server 字段", "name: a\nport: 443\nws-opts:\n  server: 1.1.1.1\n"},
		{"空 payload", ""},
		{"流式映射缺少 server", "{name: a, port: 443}"},
		{"流式映射重复 server", "{name: a, server: 1.1.1.1, server: 6.6.6.6}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := pinNodeServerIP(MiaospeedNode{Name: tc.name, Protocol: "ss", Server: "a.example:443", Payload: tc.payload}, net.ParseIP("1.1.1.1")); err == nil {
				t.Fatalf("应拒绝无法可靠改写的 payload：%s", tc.payload)
			}
		})
	}
}

func TestFilterBlockedNodesDropsUnpinnableDomainNode(t *testing.T) {
	orig := lookupNodeIPs
	defer func() { lookupNodeIPs = orig }()
	lookupNodeIPs = func(_ context.Context, _ string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("1.1.1.1")}, nil
	}
	nodes := []MiaospeedNode{
		{Name: "bad", Server: "edge.example:443", Protocol: "ss", Payload: "name: bad\ntype: ss\nport: 443\n"},
		{Name: "good", Server: "edge.example:443", Protocol: "ss", Payload: "name: good\ntype: ss\nserver: edge.example\nport: 443\n"},
	}
	kept, removed := filterBlockedNodes(context.Background(), nodes, nil)
	if len(kept) != 1 || kept[0].Name != "good" {
		t.Fatalf("只应保留可安全改写的节点：%+v", kept)
	}
	if removed != 1 {
		t.Fatalf("剔除数量错误：%d", removed)
	}
}

func TestFilterBlockedNodesPinsLiteralIPPayload(t *testing.T) {
	nodes := []MiaospeedNode{
		{
			Name:     "literal-decoy",
			Server:   "8.8.8.8:443",
			Protocol: "ss",
			Payload:  "name: n\ntype: ss\nserver: 127.0.0.1\nport: 443\n",
		},
	}
	kept, removed := filterBlockedNodes(context.Background(), nodes, nil)
	if removed != 0 || len(kept) != 1 {
		t.Fatalf("字面 IP 节点应保留并钉死 payload，kept=%+v removed=%d", kept, removed)
	}
	if got := topLevelPayloadServer(t, kept[0].Payload); got != "8.8.8.8" {
		t.Fatalf("payload 顶层 server 应钉死为被校验的 8.8.8.8，实际 %q：%s", got, kept[0].Payload)
	}
}

// TestFilterBlockedNodesRejectsParserDecoys 覆盖解析器与过滤器叠加后的两种绕过：
// 校验的是诱饵地址、payload 实际指向另一个地址。
func TestFilterBlockedNodesRejectsParserDecoys(t *testing.T) {
	orig := lookupNodeIPs
	defer func() { lookupNodeIPs = orig }()
	lookupNodeIPs = func(_ context.Context, host string) ([]net.IP, error) {
		if host == "edge.example" {
			return []net.IP{net.ParseIP("1.1.1.1")}, nil
		}
		return nil, errors.New("no such host")
	}

	cases := []struct {
		name       string
		content    string
		wantKept   bool
		wantServer string
	}{
		{
			name: "流式项嵌套映射里的 server 诱饵",
			content: "proxies:\n" +
				"  - {name: x, type: ss, ws-opts: {server: 1.1.1.1}, server: 127.0.0.1, port: 22, cipher: aes-256-gcm, password: p}\n",
			wantKept: false,
		},
		{
			name:       "单 YAML 顶层私网 server + 末尾嵌套公网诱饵",
			content:    "name: x\ntype: ss\nserver: 127.0.0.1\nport: 22\nnotes:\n  server: 8.8.8.8\n",
			wantKept:   false,
			wantServer: "",
		},
		{
			name:       "单 YAML 顶层域名 + 末尾嵌套非地址诱饵",
			content:    "name: x\ntype: ss\nserver: edge.example\nport: 443\nnotes:\n  host: 8.8.8.8\n",
			wantKept:   true,
			wantServer: "1.1.1.1",
		},
		{
			name:       "单 YAML 前置嵌套非地址诱饵 + 顶层域名",
			content:    "name: x\ntype: ss\nnotes:\n  host: 127.0.0.1\nserver: edge.example\nport: 443\n",
			wantKept:   true,
			wantServer: "1.1.1.1",
		},
		{
			name:       "嵌套 server 诱饵",
			content:    "name: x\ntype: ss\nserver: edge.example\nport: 443\nnotes:\n  server: 8.8.8.8\n",
			wantKept:   false,
			wantServer: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nodes, err := parseProxyContent(tc.content)
			if err != nil {
				t.Fatalf("解析配置失败：%v", err)
			}
			kept, _ := filterBlockedNodes(context.Background(), nodes, nil)
			if got := len(kept) > 0; got != tc.wantKept {
				t.Fatalf("保留结果不符：kept=%+v", kept)
			}
			if tc.wantKept && topLevelPayloadServer(t, kept[0].Payload) != tc.wantServer {
				t.Fatalf("payload 顶层 server 应为 %s，实际：%s", tc.wantServer, kept[0].Payload)
			}
		})
	}
}

// TestFilterBlockedNodesPayloadServerInvariant 验证通用不变量：过滤后每个保留节点的
// payload 顶层 server 必须等于本次校验过的地址（字面 IP 或域名解析结果）。
func TestFilterBlockedNodesPayloadServerInvariant(t *testing.T) {
	orig := lookupNodeIPs
	defer func() { lookupNodeIPs = orig }()
	lookupNodeIPs = func(_ context.Context, host string) ([]net.IP, error) {
		if host == "public.example" {
			return []net.IP{net.ParseIP("1.1.1.1")}, nil
		}
		return nil, errors.New("no such host")
	}

	nodes := []MiaospeedNode{
		{Name: "literal", Server: "8.8.8.8:443", Protocol: "ss", Payload: "name: a\ntype: ss\nserver: 8.8.8.8\nport: 443\n"},
		{Name: "block", Server: "public.example:443", Protocol: "ss", Payload: "name: b\ntype: ss\nserver: public.example\nport: 443\n"},
		{Name: "flow", Server: "public.example:443", Protocol: "vmess", Payload: "{name: c, type: vmess, ws-opts: {host: 6.6.6.6}, server: public.example, port: 443}"},
		{Name: "nested-notes", Server: "public.example:443", Protocol: "ss", Payload: "name: d\ntype: ss\nserver: public.example\nport: 443\nnotes:\n  host: 9.9.9.9\n"},
		{Name: "blocked-literal", Server: "127.0.0.1:22", Protocol: "ss", Payload: "name: e\ntype: ss\nserver: 8.8.8.8\nport: 22\n"},
		{Name: "unpinnable", Server: "public.example:443", Protocol: "ss", Payload: "name: f\nport: 443\n"},
	}
	kept, removed := filterBlockedNodes(context.Background(), nodes, nil)
	if removed != 2 || len(kept) != 4 {
		t.Fatalf("应保留 4 个、剔除 2 个，实际 kept=%+v removed=%d", kept, removed)
	}
	want := map[string]string{
		"literal":      "8.8.8.8",
		"block":        "1.1.1.1",
		"flow":         "1.1.1.1",
		"nested-notes": "1.1.1.1",
	}
	for _, n := range kept {
		if got := topLevelPayloadServer(t, n.Payload); got != want[n.Name] {
			t.Fatalf("节点 %s 的 payload 顶层 server = %q，应为被校验地址 %q：%s", n.Name, got, want[n.Name], n.Payload)
		}
	}
}

// testAddressFieldNames 是 mihomo 出站配置里能直接决定拨号目标地址的字段名。
var testAddressFieldNames = []string{"server", "ip", "ipv6", "peers", "control-url", "endpoint"}

// testMihomoKeyNormalize 复刻 mihomo structure.DefaultKeyReplacer（"_" -> "-"）。
func testMihomoKeyNormalize(key string) string {
	return strings.ReplaceAll(key, "_", "-")
}

// testMihomoAddressField 返回该键在 mihomo structure.Decoder 语义（replacer + EqualFold）
// 下命中的地址类字段名。
func testMihomoAddressField(key string) (string, bool) {
	norm := testMihomoKeyNormalize(key)
	for _, field := range testAddressFieldNames {
		if strings.EqualFold(norm, testMihomoKeyNormalize(field)) {
			return field, true
		}
	}
	return "", false
}

// collectAddressKeyPaths 递归收集所有命中地址类字段的键路径。
func collectAddressKeyPaths(value interface{}, path string, out *[]string) {
	switch typed := value.(type) {
	case map[interface{}]interface{}:
		for key, child := range typed {
			name, ok := key.(string)
			if !ok {
				continue
			}
			next := path + "." + name
			if field, ok := testMihomoAddressField(name); ok {
				*out = append(*out, next+"→"+field)
			}
			collectAddressKeyPaths(child, next, out)
		}
	case map[string]interface{}:
		for key, child := range typed {
			next := path + "." + key
			if field, ok := testMihomoAddressField(key); ok {
				*out = append(*out, next+"→"+field)
			}
			collectAddressKeyPaths(child, next, out)
		}
	case []interface{}:
		for i, child := range typed {
			collectAddressKeyPaths(child, fmt.Sprintf("%s[%d]", path, i), out)
		}
	}
}

// assertPinnedServerOnly 用 yaml.v2 解码（与 miaospeed 同版本），按 mihomo 的
// replacer + EqualFold 语义归一所有键，断言能映射到地址类字段的键有且只有一个：
// 顶层 server，且值等于钉死的 IP。
func assertPinnedServerOnly(t *testing.T, payload, wantServer string) {
	t.Helper()
	var decoded map[string]interface{}
	if err := yaml2.Unmarshal([]byte(payload), &decoded); err != nil {
		t.Fatalf("payload 无法用 yaml.v2 解码：%v\n%s", err, payload)
	}
	serverCount := 0
	var serverValue interface{}
	for key, value := range decoded {
		field, ok := testMihomoAddressField(key)
		if !ok {
			continue
		}
		if field != "server" {
			t.Fatalf("顶层出现地址字段 %q（mihomo 归一后命中 %q）：%s", key, field, payload)
		}
		serverCount++
		serverValue = value
	}
	if serverCount != 1 {
		t.Fatalf("payload 必须恰好有一个能映射到地址字段的顶层键，实际 %d 个：%s", serverCount, payload)
	}
	if got := fmt.Sprint(serverValue); got != wantServer {
		t.Fatalf("顶层 server = %q，应为钉死地址 %q：%s", got, wantServer, payload)
	}
	var paths []string
	for _, value := range decoded {
		collectAddressKeyPaths(value, "$", &paths)
	}
	if len(paths) != 0 {
		t.Fatalf("嵌套字段里出现地址类键 %v：%s", paths, payload)
	}
}

// TestFilterBlockedNodesRejectsKeyNormalizationBypasses 覆盖 C-1/H-1/H-2/M-1：
// mihomo 的 structure.Decoder 先精确匹配字段名，未命中再用 "_"→"-" + EqualFold
// 匹配，所以 `IP:`、`iP:`、`SERVER:`、`ſerver:` 等写法都能绕过只认原文的检查；
// 非白名单协议、非字符串 type、带标签的键、嵌套地址字段和超大 payload 同样必须剔除。
func TestFilterBlockedNodesRejectsKeyNormalizationBypasses(t *testing.T) {
	orig := lookupNodeIPs
	defer func() { lookupNodeIPs = orig }()
	lookupNodeIPs = func(_ context.Context, host string) ([]net.IP, error) {
		if host == "public.example" {
			return []net.IP{net.ParseIP("1.1.1.1")}, nil
		}
		return nil, errors.New("no such host")
	}

	oversized := "name: p\ntype: ss\nserver: public.example\nport: 443\ncipher: aes-256-gcm\npassword: p\n# " +
		strings.Repeat("x", maxNodePayloadBytes) + "\n"

	cases := []struct {
		name     string
		protocol string
		payload  string
	}{
		{
			name:     "tuic 大写 IP 键",
			protocol: "tuic",
			payload:  "name: p\ntype: tuic\nserver: public.example\nport: 8443\nuuid: u\npassword: p\nIP: 169.254.169.254\n",
		},
		{
			name:     "tuic 首字母大写 Ip 键",
			protocol: "tuic",
			payload:  "name: p\ntype: tuic\nserver: public.example\nport: 8443\nuuid: u\npassword: p\nIp: 169.254.169.254\n",
		},
		{
			name:     "tuic 混合大小写 iP 键",
			protocol: "tuic",
			payload:  "name: p\ntype: tuic\nserver: public.example\nport: 8443\nuuid: u\npassword: p\niP: 169.254.169.254\n",
		},
		{
			name:     "wireguard 大写 PEERS 键",
			protocol: "wireguard",
			payload: "name: p\ntype: wireguard\nserver: public.example\nport: 51820\nprivate-key: x\n" +
				"PEERS:\n  - server: 169.254.169.254\n    port: 51820\n    public-key: y\n",
		},
		{
			name:     "wireguard 首字母大写 Peers 键",
			protocol: "wireguard",
			payload: "name: p\ntype: wireguard\nserver: public.example\nport: 51820\nprivate-key: x\n" +
				"Peers:\n  - server: 169.254.169.254\n    port: 51820\n    public-key: y\n",
		},
		{
			name:     "白名单协议上的大写 PEERS 键",
			protocol: "socks5",
			payload:  "name: p\ntype: socks5\nserver: public.example\nport: 1080\nPEERS: 169.254.169.254\n",
		},
		{
			name:     "非 ASCII 的 server 键",
			protocol: "trojan",
			payload:  "name: p\ntype: trojan\nserver: public.example\nport: 443\npassword: p\n\u017ferver: 169.254.169.254\n",
		},
		{
			name:     "大写 SERVER 键",
			protocol: "trojan",
			payload:  "name: p\ntype: trojan\nserver: public.example\nport: 443\npassword: p\nSERVER: 169.254.169.254\n",
		},
		{
			name:     "Server 与 server 同时出现",
			protocol: "trojan",
			payload:  "name: p\ntype: trojan\nserver: public.example\nport: 443\npassword: p\nServer: 169.254.169.254\n",
		},
		{
			name:     "只有大写 SERVER 键",
			protocol: "trojan",
			payload:  "name: p\ntype: trojan\nSERVER: public.example\nport: 443\npassword: p\n",
		},
		{
			name:     "顶层 control-url 字段",
			protocol: "ss",
			payload:  "name: p\ntype: ss\nserver: public.example\nport: 443\ncipher: aes-256-gcm\npassword: p\ncontrol-url: http://169.254.169.254/\n",
		},
		{
			name:     "wireguard 协议不在白名单",
			protocol: "wireguard",
			payload:  "name: p\ntype: wireguard\nserver: public.example\nport: 51820\nprivate-key: x\npublic-key: y\n",
		},
		{
			name:     "tailscale 协议不在白名单",
			protocol: "tailscale",
			payload:  "name: p\ntype: tailscale\nhostname: h\n",
		},
		{
			name:     "未知协议",
			protocol: "shadowsocks",
			payload:  "name: p\ntype: shadowsocks\nserver: public.example\nport: 443\npassword: p\n",
		},
		{
			name:     "type 为数字",
			protocol: "ss",
			payload:  "name: p\ntype: 42\nserver: public.example\nport: 443\npassword: p\n",
		},
		{
			name:     "type 为布尔",
			protocol: "ss",
			payload:  "name: p\ntype: true\nserver: public.example\nport: 443\npassword: p\n",
		},
		{
			name:     "type 键被改写成大写",
			protocol: "ss",
			payload:  "name: p\nTYPE: ss\nserver: public.example\nport: 443\npassword: p\n",
		},
		{
			name:     "!!binary 键覆盖 server",
			protocol: "trojan",
			payload: "name: p\ntype: trojan\nserver: public.example\nport: 443\npassword: p\n" +
				"? !!binary c2VydmVy\n: 169.254.169.254\n",
		},
		{
			name:     "!!merge 键覆盖 server",
			protocol: "trojan",
			payload: "name: p\ntype: trojan\nserver: public.example\nport: 443\npassword: p\n" +
				"? !!merge x\n: 169.254.169.254\n",
		},
		{
			name:     "嵌套 server（vless xhttp download-settings）",
			protocol: "vless",
			payload: "name: p\ntype: vless\nserver: public.example\nport: 443\nuuid: u\nnetwork: xhttp\n" +
				"xhttp-opts:\n  path: /x\n  download-settings:\n    server: 169.254.169.254\n    port: 443\n",
		},
		{
			name:     "嵌套非 ASCII server 键",
			protocol: "vless",
			payload: "name: p\ntype: vless\nserver: public.example\nport: 443\nuuid: u\n" +
				"xhttp-opts:\n  download-settings:\n    \u017ferver: 169.254.169.254\n",
		},
		{
			name:     "hysteria2 realm server-url",
			protocol: "hysteria2",
			payload: "name: p\ntype: hysteria2\nserver: public.example\nport: 443\npassword: p\n" +
				"realm-opts:\n  enable: true\n  server-url: http://169.254.169.254/\n",
		},
		{
			name:     "dialer-proxy 改走另一个出站",
			protocol: "ss",
			payload:  "name: p\ntype: ss\nserver: public.example\nport: 443\ncipher: aes-256-gcm\npassword: p\ndialer-proxy: other\n",
		},
		// M-1：ech-opts.query-server-name 会覆盖 ECH 的 HTTPS 记录查询域名（ech.go:33-38），
		// 等于让探针主机用 SystemResolver 去查攻击者指定的域名，必须逐层拦截。
		{
			name:     "trojan ech-opts.query-server-name",
			protocol: "trojan",
			payload: "name: p\ntype: trojan\nserver: public.example\nport: 443\npassword: p\n" +
				"ech-opts:\n  enable: true\n  query-server-name: metadata.google.internal\n",
		},
		{
			name:     "vmess ech-opts.query-server-name",
			protocol: "vmess",
			payload: "name: p\ntype: vmess\nserver: public.example\nport: 443\nuuid: u\nalterId: 0\ncipher: auto\n" +
				"ech-opts:\n  enable: true\n  query-server-name: metadata.google.internal\n",
		},
		{
			name:     "vless ech-opts.query-server-name",
			protocol: "vless",
			payload: "name: p\ntype: vless\nserver: public.example\nport: 443\nuuid: u\n" +
				"ech-opts:\n  enable: true\n  query-server-name: metadata.google.internal\n",
		},
		{
			name:     "ss v2ray-plugin tls ech-opts.query-server-name",
			protocol: "ss",
			payload: "name: p\ntype: ss\nserver: public.example\nport: 443\ncipher: aes-256-gcm\npassword: p\n" +
				"plugin: v2ray-plugin\nplugin-opts:\n  mode: websocket\n  tls: true\n" +
				"  ech-opts:\n    enable: true\n    query-server-name: metadata.google.internal\n",
		},
		{
			name:     "tuic ech-opts.query-server-name",
			protocol: "tuic",
			payload: "name: p\ntype: tuic\nserver: public.example\nport: 8443\nuuid: u\npassword: p\n" +
				"ech-opts:\n  enable: true\n  query-server-name: metadata.google.internal\n",
		},
		{
			name:     "trojan ech-opts 大小写变体 Query_Server_Name",
			protocol: "trojan",
			payload: "name: p\ntype: trojan\nserver: public.example\nport: 443\npassword: p\n" +
				"ech-opts:\n  ENABLE: true\n  Query_Server_Name: metadata.google.internal\n",
		},
		{
			name:     "tuic ech-opts 大小写变体 Query_Server_Name",
			protocol: "tuic",
			payload: "name: p\ntype: tuic\nserver: public.example\nport: 8443\nuuid: u\npassword: p\n" +
				"ECH-Opts:\n  enable: true\n  Query_Server_Name: metadata.google.internal\n",
		},
		// L1：顶层禁止表与嵌套表同源，url/server-url/stun-servers/query-server-name
		// 出现在顶层同样必须剔除（server 例外）。
		{
			name:     "顶层 url 字段（ss）",
			protocol: "ss",
			payload:  "name: p\ntype: ss\nserver: public.example\nport: 443\ncipher: aes-256-gcm\npassword: p\nurl: http://169.254.169.254/\n",
		},
		{
			name:     "顶层 url 字段（大写 URL）",
			protocol: "ss",
			payload:  "name: p\ntype: ss\nserver: public.example\nport: 443\ncipher: aes-256-gcm\npassword: p\nURL: http://169.254.169.254/\n",
		},
		{
			name:     "顶层 server-url 字段",
			protocol: "hysteria2",
			payload:  "name: p\ntype: hysteria2\nserver: public.example\nport: 443\npassword: p\nserver-url: http://169.254.169.254/\n",
		},
		{
			name:     "顶层 stun-servers 字段",
			protocol: "hysteria2",
			payload:  "name: p\ntype: hysteria2\nserver: public.example\nport: 443\npassword: p\nstun-servers:\n  - 169.254.169.254:3478\n",
		},
		{
			name:     "顶层 query-server-name 字段",
			protocol: "trojan",
			payload:  "name: p\ntype: trojan\nserver: public.example\nport: 443\npassword: p\nquery-server-name: metadata.google.internal\n",
		},
		{
			name:     "超大 payload",
			protocol: "ss",
			payload:  oversized,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nodes := []MiaospeedNode{{
				Name:     tc.name,
				Server:   "public.example:443",
				Protocol: tc.protocol,
				Payload:  tc.payload,
			}}
			kept, removed := filterBlockedNodes(context.Background(), nodes, nil)
			if len(kept) != 0 || removed != 1 {
				t.Fatalf("该节点应被剔除，kept=%+v removed=%d\npayload:\n%s", kept, removed, tc.payload)
			}
		})
	}
}

// TestFilterBlockedNodesKeepsECHConfigWithoutQueryServerName 确认没有封禁整个 ech-opts：
// ech-opts.enable 只是开关、ech-opts.config 是本地 base64（ech.go:24-31 解码后不再联网），
// 所以只带 enable/config 的节点（携带本地 ECH 配置）必须保留；
// 只有 query-server-name（会去查攻击者指定的域名）被拦截（见上一个测试）。
func TestFilterBlockedNodesKeepsECHConfigWithoutQueryServerName(t *testing.T) {
	orig := lookupNodeIPs
	defer func() { lookupNodeIPs = orig }()
	lookupNodeIPs = func(_ context.Context, host string) ([]net.IP, error) {
		if host == "public.example" {
			return []net.IP{net.ParseIP("1.1.1.1")}, nil
		}
		return nil, errors.New("no such host")
	}

	cases := []struct {
		name     string
		protocol string
		payload  string
	}{
		{
			name:     "trojan ech-opts enable+config",
			protocol: "trojan",
			payload: "name: p\ntype: trojan\nserver: public.example\nport: 443\npassword: p\n" +
				"ech-opts:\n  enable: true\n  config: AQIDBA==\n",
		},
		{
			name:     "vmess ech-opts enable+config",
			protocol: "vmess",
			payload: "name: p\ntype: vmess\nserver: public.example\nport: 443\nuuid: u\nalterId: 0\ncipher: auto\n" +
				"ech-opts:\n  enable: true\n  config: AQIDBA==\n",
		},
		{
			name:     "vless ech-opts enable+config",
			protocol: "vless",
			payload: "name: p\ntype: vless\nserver: public.example\nport: 443\nuuid: u\n" +
				"ech-opts:\n  enable: true\n  config: AQIDBA==\n",
		},
		{
			name:     "ss v2ray-plugin tls ech-opts enable+config",
			protocol: "ss",
			payload: "name: p\ntype: ss\nserver: public.example\nport: 443\ncipher: aes-256-gcm\npassword: p\n" +
				"plugin: v2ray-plugin\nplugin-opts:\n  mode: websocket\n  tls: true\n" +
				"  ech-opts:\n    enable: true\n    config: AQIDBA==\n",
		},
		{
			name:     "tuic ech-opts enable+config",
			protocol: "tuic",
			payload: "name: p\ntype: tuic\nserver: public.example\nport: 8443\nuuid: u\npassword: p\n" +
				"ech-opts:\n  enable: true\n  config: AQIDBA==\n",
		},
		{
			name:     "hysteria2 ech-opts 仅 enable",
			protocol: "hysteria2",
			payload:  "name: p\ntype: hysteria2\nserver: public.example\nport: 443\npassword: p\nech-opts:\n  enable: false\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nodes := []MiaospeedNode{{
				Name:     tc.name,
				Server:   "public.example:443",
				Protocol: tc.protocol,
				Payload:  tc.payload,
			}}
			kept, removed := filterBlockedNodes(context.Background(), nodes, nil)
			if removed != 0 || len(kept) != 1 {
				t.Fatalf("只带 enable/config 的 ech-opts 不应导致剔除，kept=%+v removed=%d\npayload:\n%s", kept, removed, tc.payload)
			}
			assertPinnedServerOnly(t, kept[0].Payload, "1.1.1.1")
		})
	}
}

// TestFilterBlockedNodesCapsCandidateResolution 覆盖 M-2：
// 过滤发生在 selectJobNodes 截断之前，必须先按 maxNodeFilterCandidates 截断候选节点，
// 否则大量唯一主机名会把 DNS 解析扇出放大到任意量级。
// 这里把上限调小，断言：解析调用次数不超过上限、超出的节点计入剔除、
// 保留的节点仍是原顺序的前缀（不重排，selectJobNodes 的选择语义不变）。
func TestFilterBlockedNodesCapsCandidateResolution(t *testing.T) {
	origLookup := lookupNodeIPs
	origCap := maxNodeFilterCandidates
	defer func() {
		lookupNodeIPs = origLookup
		maxNodeFilterCandidates = origCap
	}()

	// 默认上限必须不小于单次批量的节点数上限，否则缓冲不足会在正常订阅上误削弱筛选容量。
	if origCap < maxMiaospeedNodes {
		t.Fatalf("maxNodeFilterCandidates=%d 不应小于 maxMiaospeedNodes=%d", origCap, maxMiaospeedNodes)
	}
	maxNodeFilterCandidates = 5

	var lookups atomic.Int32
	lookupNodeIPs = func(_ context.Context, host string) ([]net.IP, error) {
		lookups.Add(1)
		return []net.IP{net.ParseIP("1.1.1.1")}, nil
	}

	const total = 200
	nodes := make([]MiaospeedNode, 0, total)
	for i := 0; i < total; i++ {
		host := fmt.Sprintf("node-%03d.example", i)
		nodes = append(nodes, MiaospeedNode{
			Name:     host,
			Server:   host + ":443",
			Protocol: "ss",
			Payload:  "name: p\ntype: ss\nserver: " + host + "\nport: 443\ncipher: aes-256-gcm\npassword: p\n",
		})
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	kept, removed := filterBlockedNodes(context.Background(), nodes, logger)

	if got := lookups.Load(); got > int32(maxNodeFilterCandidates) {
		t.Fatalf("DNS 解析次数 %d 超过上限 %d", got, maxNodeFilterCandidates)
	}
	if len(kept) != maxNodeFilterCandidates {
		t.Fatalf("应保留 %d 个候选节点，实际 %d", maxNodeFilterCandidates, len(kept))
	}
	if want := total - maxNodeFilterCandidates; removed != want {
		t.Fatalf("超出上限的节点应计入剔除，removed=%d want=%d", removed, want)
	}
	for i, n := range kept {
		if n.Name != nodes[i].Name {
			t.Fatalf("保留的节点顺序应与输入一致，第 %d 个是 %q，应为 %q", i, n.Name, nodes[i].Name)
		}
	}
	if !strings.Contains(buf.String(), "候选节点数超过单次安全检查上限") {
		t.Fatalf("截断应记入剔除原因统计，日志：%s", buf.String())
	}
}

// TestSanitizeNodeNameForLogRemovesInvisibleRunes 覆盖 L3：除了控制字符，
// 日志里还必须去掉 Cf（U+202E 双向覆盖、U+200B 零宽空格）与 Co（私用区）字符，
// 否则节点名可以翻转/隐藏日志内容。
func TestSanitizeNodeNameForLogRemovesInvisibleRunes(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{name: "双向覆盖与零宽字符", in: "a\u202eb\u200bc", want: "abc"},
		{name: "私用区字符", in: "x\ue000y\uf8ffz", want: "xyz"},
		{name: "控制字符仍被去掉", in: "a\x00b\x1bc", want: "abc"},
		{name: "正常中日文保留", in: "香港 01 节点", want: "香港 01 节点"},
		{name: "全是不可见字符", in: "\u200b\u202e", want: "(无名)"},
		{name: "首尾不可见字符被裁剪", in: "\u200b\ufeff节点\u202e", want: "节点"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeNodeNameForLog(tc.in); got != tc.want {
				t.Fatalf("sanitizeNodeNameForLog(%q) = %q，应为 %q", tc.in, got, tc.want)
			}
		})
	}
	// 截断仍然生效（按 rune 计数，见 nodeDropLogNameRunes）。
	long := strings.Repeat("节", nodeDropLogNameRunes+5)
	if got := sanitizeNodeNameForLog(long); got != strings.Repeat("节", nodeDropLogNameRunes)+"..." {
		t.Fatalf("超长节点名应截断到 %d 个字符，实际 %q", nodeDropLogNameRunes, got)
	}
}

// TestFilterBlockedNodesAllowPrivateOnlySkipsIPRange 覆盖 L4：
// -allow-private-probes 只跳过“IP 是否落在私网/保留段”，
// 协议白名单、payload 结构、禁止字段、钉死与钉死后的语义回验都照常执行。
func TestFilterBlockedNodesAllowPrivateOnlySkipsIPRange(t *testing.T) {
	orig := lookupNodeIPs
	defer func() { lookupNodeIPs = orig }()
	lookupNodeIPs = func(_ context.Context, host string) ([]net.IP, error) {
		switch host {
		case "internal.example":
			return []net.IP{net.ParseIP("10.0.0.5")}, nil
		case "public.example":
			return []net.IP{net.ParseIP("1.1.1.1")}, nil
		default:
			return nil, errors.New("no such host")
		}
	}

	privateAllowed := nodeFilterPolicy{AllowPrivate: true}

	t.Run("私网域名节点保留并钉死到私网 IP", func(t *testing.T) {
		nodes := []MiaospeedNode{{
			Name:     "internal-domain",
			Server:   "internal.example:443",
			Protocol: "ss",
			Payload:  "name: p\ntype: ss\nserver: internal.example\nport: 443\ncipher: aes-256-gcm\npassword: p\n",
		}}
		kept, removed := filterBlockedNodesWithPolicy(context.Background(), nodes, privateAllowed, nil)
		if removed != 0 || len(kept) != 1 {
			t.Fatalf("AllowPrivate 时私网域名节点应保留，kept=%+v removed=%d", kept, removed)
		}
		if kept[0].Server != "internal.example:443" {
			t.Fatalf("Server 字段应保留原域名供报告展示，实际 %q", kept[0].Server)
		}
		assertPinnedServerOnly(t, kept[0].Payload, "10.0.0.5")
	})

	t.Run("私网字面 IP 节点保留并钉死", func(t *testing.T) {
		nodes := []MiaospeedNode{{
			Name:     "internal-ip",
			Server:   "10.0.0.7:443",
			Protocol: "trojan",
			Payload:  "name: p\ntype: trojan\nserver: 10.0.0.7\nport: 443\npassword: p\nsni: front.example\n",
		}}
		kept, removed := filterBlockedNodesWithPolicy(context.Background(), nodes, privateAllowed, nil)
		if removed != 0 || len(kept) != 1 {
			t.Fatalf("AllowPrivate 时私网字面 IP 节点应保留，kept=%+v removed=%d", kept, removed)
		}
		assertPinnedServerOnly(t, kept[0].Payload, "10.0.0.7")
	})

	// 下面这些节点即使 AllowPrivate 也必须剔除：被跳过的只有 IP 段判定。
	dropped := []struct {
		name     string
		protocol string
		server   string
		payload  string
	}{
		{
			name:     "非白名单协议",
			protocol: "wireguard",
			server:   "internal.example:51820",
			payload:  "name: p\ntype: wireguard\nserver: internal.example\nport: 51820\nprivate-key: x\npublic-key: y\n",
		},
		{
			name:     "顶层 ip 覆盖字段",
			protocol: "tuic",
			server:   "internal.example:8443",
			payload:  "name: p\ntype: tuic\nserver: internal.example\nport: 8443\nuuid: u\npassword: p\nip: 169.254.169.254\n",
		},
		{
			name:     "嵌套 server 字段",
			protocol: "vless",
			server:   "internal.example:443",
			payload: "name: p\ntype: vless\nserver: internal.example\nport: 443\nuuid: u\nnetwork: xhttp\n" +
				"xhttp-opts:\n  path: /x\n  download-settings:\n    server: 169.254.169.254\n",
		},
		{
			name:     "嵌套 ech-opts.query-server-name",
			protocol: "trojan",
			server:   "internal.example:443",
			payload: "name: p\ntype: trojan\nserver: internal.example\nport: 443\npassword: p\n" +
				"ech-opts:\n  enable: true\n  query-server-name: metadata.google.internal\n",
		},
		{
			name:     "域名无法解析（无法钉死）",
			protocol: "ss",
			server:   "nx.example:443",
			payload:  "name: p\ntype: ss\nserver: nx.example\nport: 443\ncipher: aes-256-gcm\npassword: p\n",
		},
		{
			name:     "payload 缺少 server",
			protocol: "ss",
			server:   "internal.example:443",
			payload:  "name: p\nport: 443\ncipher: aes-256-gcm\npassword: p\n",
		},
	}
	for _, tc := range dropped {
		t.Run(tc.name, func(t *testing.T) {
			nodes := []MiaospeedNode{{
				Name:     tc.name,
				Server:   tc.server,
				Protocol: tc.protocol,
				Payload:  tc.payload,
			}}
			kept, removed := filterBlockedNodesWithPolicy(context.Background(), nodes, privateAllowed, nil)
			if len(kept) != 0 || removed != 1 {
				t.Fatalf("AllowPrivate 只跳过 IP 段判定，其他闸门违规仍应剔除，kept=%+v removed=%d\npayload:\n%s", kept, removed, tc.payload)
			}
		})
	}

	t.Run("默认策略仍然拦截私网地址", func(t *testing.T) {
		nodes := []MiaospeedNode{{
			Name:     "internal-domain",
			Server:   "internal.example:443",
			Protocol: "ss",
			Payload:  "name: p\ntype: ss\nserver: internal.example\nport: 443\ncipher: aes-256-gcm\npassword: p\n",
		}}
		kept, removed := filterBlockedNodes(context.Background(), nodes, nil)
		if len(kept) != 0 || removed != 1 {
			t.Fatalf("默认策略必须拦截私网地址，kept=%+v removed=%d", kept, removed)
		}
	})
}

// TestFilterBlockedNodesAllowsInertUnderscoreLookalike 确认 `i_p` 不会被当成 `ip`：
// mihomo 的 DefaultKeyReplacer 只把 "_" 换成 "-"，`i_p` 归一后是 `i-p`，
// 与字段名 `ip` 做 EqualFold 不相等，因此不会覆盖拨号地址。
// 这里断言节点保留，并用 mihomo 语义的匹配器确认它不属于地址类字段。
func TestFilterBlockedNodesAllowsInertUnderscoreLookalike(t *testing.T) {
	orig := lookupNodeIPs
	defer func() { lookupNodeIPs = orig }()
	lookupNodeIPs = func(_ context.Context, host string) ([]net.IP, error) {
		if host == "public.example" {
			return []net.IP{net.ParseIP("1.1.1.1")}, nil
		}
		return nil, errors.New("no such host")
	}
	if field, ok := testMihomoAddressField("i_p"); ok {
		t.Fatalf("i_p 不应命中地址字段，实际命中 %q", field)
	}
	nodes := []MiaospeedNode{{
		Name:     "underscore",
		Server:   "public.example:8443",
		Protocol: "tuic",
		Payload:  "name: p\ntype: tuic\nserver: public.example\nport: 8443\nuuid: u\npassword: p\ni_p: 169.254.169.254\n",
	}}
	kept, removed := filterBlockedNodes(context.Background(), nodes, nil)
	if removed != 0 || len(kept) != 1 {
		t.Fatalf("i_p 不会命 mihomo 的 ip 字段，节点应保留，kept=%+v removed=%d", kept, removed)
	}
	assertPinnedServerOnly(t, kept[0].Payload, "1.1.1.1")
}

// TestFilterBlockedNodesPayloadSizeLimit 验证单节点 payload 上限（M-1）：
// 恰好在上限内应保留，超过上限直接剔除，不做解析。
func TestFilterBlockedNodesPayloadSizeLimit(t *testing.T) {
	orig := lookupNodeIPs
	defer func() { lookupNodeIPs = orig }()
	lookupNodeIPs = func(_ context.Context, host string) ([]net.IP, error) {
		if host == "public.example" {
			return []net.IP{net.ParseIP("1.1.1.1")}, nil
		}
		return nil, errors.New("no such host")
	}

	base := "name: p\ntype: ss\nserver: public.example\nport: 443\ncipher: aes-256-gcm\npassword: p\n"
	padTo := func(total int) string {
		padding := total - len(base) - len("# \n")
		if padding < 0 {
			padding = 0
		}
		payload := base + "# " + strings.Repeat("x", padding) + "\n"
		if len(payload) != total {
			t.Fatalf("构造的 payload 长度 = %d，期望 %d", len(payload), total)
		}
		return payload
	}

	for _, tc := range []struct {
		name    string
		payload string
		wantLen bool
	}{
		{name: "恰好在上限内", payload: padTo(maxNodePayloadBytes), wantLen: true},
		{name: "超过上限一个字节", payload: padTo(maxNodePayloadBytes + 1), wantLen: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nodes := []MiaospeedNode{{Name: tc.name, Server: "public.example:443", Protocol: "ss", Payload: tc.payload}}
			kept, removed := filterBlockedNodes(context.Background(), nodes, nil)
			if tc.wantLen {
				if removed != 0 || len(kept) != 1 {
					t.Fatalf("上限内的节点应保留，kept=%d removed=%d", len(kept), removed)
				}
				return
			}
			if len(kept) != 0 || removed != 1 {
				t.Fatalf("超过上限的节点应剔除，kept=%d removed=%d", len(kept), removed)
			}
		})
	}
}

// TestKeptNodeDialAddressInvariant 是白名单性质测试：对所有被保留的白名单协议节点，
// 用 yaml.v2 解码 payload，按 EqualFold + replacer 归一共所有键，断言能映射到
// 地址类字段（server/ip/ipv6/peers/control-url/endpoint）的键只有一个顶层 server，
// 且它的值就是本次钉死的 IP。
func TestKeptNodeDialAddressInvariant(t *testing.T) {
	orig := lookupNodeIPs
	defer func() { lookupNodeIPs = orig }()
	lookupNodeIPs = func(_ context.Context, host string) ([]net.IP, error) {
		if host == "public.example" {
			return []net.IP{net.ParseIP("1.1.1.1")}, nil
		}
		return nil, errors.New("no such host")
	}

	payloads := []struct {
		protocol string
		port     int
		payload  string
	}{
		{"ss", 8388, "name: ss\ntype: ss\nserver: public.example\nport: 8388\ncipher: aes-256-gcm\npassword: p\n"},
		{"ssr", 8388, "name: ssr\ntype: ssr\nserver: public.example\nport: 8388\ncipher: aes-128-cfb\npassword: p\nprotocol: origin\nobfs: plain\n"},
		{"socks5", 1080, "name: sk\ntype: socks5\nserver: public.example\nport: 1080\nusername: u\npassword: p\n"},
		{"http", 8080, "name: ht\ntype: http\nserver: public.example\nport: 8080\ntls: true\nsni: front.example\nheaders:\n  X-Test: 1\n"},
		{"vmess", 443, "name: vm\ntype: vmess\nserver: public.example\nport: 443\nuuid: u\nalterId: 0\ncipher: auto\nnetwork: ws\nws-opts:\n  path: /ws\n  headers:\n    Host: cdn.example\nservername: front.example\n"},
		{"vless", 443, "name: vl\ntype: vless\nserver: public.example\nport: 443\nuuid: u\nnetwork: ws\ntls: true\nservername: front.example\nws-opts:\n  path: /ws\n"},
		{"trojan", 443, "name: tr\ntype: trojan\nserver: public.example\nport: 443\npassword: p\nsni: front.example\n"},
		{"snell", 8388, "name: sn\ntype: snell\nserver: public.example\nport: 8388\npsk: p\nversion: 4\n"},
		{"hysteria", 443, "name: hy\ntype: hysteria\nserver: public.example\nport: 443\nports: 1000-2000\nprotocol: udp\nup: 100 mbps\ndown: 100 mbps\nauth-str: a\nsni: front.example\n"},
		{"hysteria2", 443, "name: hy2\ntype: hysteria2\nserver: public.example\nport: 443\nports: 1000-2000\npassword: p\nsni: front.example\n"},
		{"anytls", 443, "name: at\ntype: anytls\nserver: public.example\nport: 443\npassword: p\nsni: front.example\n"},
		{"tuic", 8443, "name: tu\ntype: tuic\nserver: public.example\nport: 8443\nuuid: u\npassword: p\nsni: front.example\n"},
	}

	nodes := make([]MiaospeedNode, 0, len(payloads))
	for i, item := range payloads {
		nodes = append(nodes, MiaospeedNode{
			Name:     fmt.Sprintf("node-%d-%s", i, item.protocol),
			Server:   fmt.Sprintf("public.example:%d", item.port),
			Protocol: item.protocol,
			Payload:  item.payload,
		})
	}
	kept, removed := filterBlockedNodes(context.Background(), nodes, nil)
	if removed != 0 || len(kept) != len(nodes) {
		t.Fatalf("白名单协议的正常节点应全部保留，removed=%d kept=%d", removed, len(kept))
	}
	for _, n := range kept {
		assertPinnedServerOnly(t, n.Payload, "1.1.1.1")
	}
}

// TestFilterBlockedNodesLogsDropReasonsWithoutPayload 验证 M-2：剔除原因写 warn 日志，
// 带节点名（去控制字符、截断）与按原因分类的计数，但绝不输出 payload 内容。
func TestFilterBlockedNodesLogsDropReasonsWithoutPayload(t *testing.T) {
	orig := lookupNodeIPs
	defer func() { lookupNodeIPs = orig }()
	lookupNodeIPs = func(_ context.Context, host string) ([]net.IP, error) {
		if host == "public.example" {
			return []net.IP{net.ParseIP("1.1.1.1")}, nil
		}
		return nil, errors.New("no such host")
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	longName := strings.Repeat("N", nodeDropLogNameRunes+32)
	nodes := []MiaospeedNode{
		{
			Name:     "bad\nname\x00",
			Server:   "public.example:443",
			Protocol: "wireguard",
			Payload: "name: p\ntype: wireguard\nserver: public.example\nport: 51820\n" +
				"private-key: BADPAYLOADSECRET\npublic-key: y\n",
		},
		{
			Name:     longName,
			Server:   "127.0.0.1:22",
			Protocol: "ss",
			Payload:  "name: p\ntype: ss\nserver: 127.0.0.1\nport: 22\npassword: BADPAYLOADSECRET\n",
		},
		{
			Name:     "good",
			Server:   "public.example:443",
			Protocol: "ss",
			Payload:  "name: p\ntype: ss\nserver: public.example\nport: 443\ncipher: aes-256-gcm\npassword: GOODPAYLOADSECRET\n",
		},
	}
	kept, removed := filterBlockedNodes(context.Background(), nodes, logger)
	if removed != 2 || len(kept) != 1 {
		t.Fatalf("应保留 1 个、剔除 2 个，实际 kept=%d removed=%d", len(kept), removed)
	}
	out := buf.String()
	if strings.Contains(out, "BADPAYLOADSECRET") || strings.Contains(out, "GOODPAYLOADSECRET") {
		t.Fatalf("日志不得包含 payload 内容：%s", out)
	}
	if !strings.Contains(out, "badname") {
		t.Fatalf("日志应包含去控制字符后的节点名：%s", out)
	}
	if !strings.Contains(out, strings.Repeat("N", nodeDropLogNameRunes)+"...") {
		t.Fatalf("超长节点名应截断到 %d 字符：%s", nodeDropLogNameRunes, out)
	}
	if strings.Contains(out, longName) {
		t.Fatalf("日志不应包含未截断的超长节点名：%s", out)
	}
	if !strings.Contains(out, "节点协议不在允许的白名单中") {
		t.Fatalf("日志应包含剔除原因：%s", out)
	}
	if !strings.Contains(out, "节点剔除原因统计") || !strings.Contains(out, "total=2") {
		t.Fatalf("日志应包含按原因分类的计数：%s", out)
	}
}

// topLevelPayloadServer 用与 miaospeed 相同的 yaml.v2 解码 payload 并取出顶层 server，
// 仅用于测试断言；不复用实现里的文本扫描，避免“实现和测试一起错”。
func topLevelPayloadServer(t *testing.T, payload string) string {
	t.Helper()
	var decoded map[string]interface{}
	if err := yaml2.Unmarshal([]byte(payload), &decoded); err != nil {
		t.Fatalf("payload 无法用 yaml.v2 解码：%v\n%s", err, payload)
	}
	if decoded == nil {
		t.Fatalf("payload 不是 YAML 映射：%s", payload)
	}
	value, ok := decoded["server"]
	if !ok {
		t.Fatalf("payload 缺少顶层 server：%s", payload)
	}
	return fmt.Sprint(value)
}

func TestPickNodeIPPrefersIPv4(t *testing.T) {
	got := pickNodeIP([]net.IP{net.ParseIP("2409:8a71::1"), net.ParseIP("1.1.1.1")})
	if got == nil || got.To4() == nil {
		t.Fatalf("应优先选择 IPv4：%v", got)
	}
	got = pickNodeIP([]net.IP{net.ParseIP("2409:8a71::1")})
	if got == nil || got.To4() != nil {
		t.Fatalf("只有 IPv6 时应返回 IPv6：%v", got)
	}
	if got := pickNodeIP(nil); got != nil {
		t.Fatalf("无可用地址时应返回 nil：%v", got)
	}
}

// TestFilterBlockedNodesPinsSingBoxPayload 验证 sing-box 生成的 payload 与
// MiaospeedNode.Server 同源，过滤后同样满足“payload 顶层 server == 被校验地址”。
func TestFilterBlockedNodesPinsSingBoxPayload(t *testing.T) {
	orig := lookupNodeIPs
	defer func() { lookupNodeIPs = orig }()
	lookupNodeIPs = func(_ context.Context, host string) ([]net.IP, error) {
		if host == "sing.example" {
			return []net.IP{net.ParseIP("1.1.1.1")}, nil
		}
		return nil, errors.New("no such host")
	}
	nodes := parseSingBoxJSON(`{"outbounds":[{"type":"vless","tag":"sb","server":"sing.example","server_port":443,"uuid":"u","tls":{"enabled":true}}]}`)
	if len(nodes) != 1 {
		t.Fatalf("应解析出 1 个 sing-box 节点：%+v", nodes)
	}
	kept, removed := filterBlockedNodes(context.Background(), nodes, nil)
	if removed != 0 || len(kept) != 1 {
		t.Fatalf("sing-box 节点应保留，kept=%+v removed=%d", kept, removed)
	}
	if got := topLevelPayloadServer(t, kept[0].Payload); got != "1.1.1.1" {
		t.Fatalf("sing-box payload 顶层 server = %q，应为 1.1.1.1：%s", got, kept[0].Payload)
	}
}

// TestFilterBlockedNodesRejectsYAMLSemanticServerBypasses 覆盖 C1：文本扫描只认裸
// `server:`，但 yaml.v2 会把引号键、标签键、显式键、重复键与 `<<` 合并键按语义
// 归一，可能让后写的地址覆盖钉死值。最终语义闸门必须全部 fail-closed。
func TestFilterBlockedNodesRejectsYAMLSemanticServerBypasses(t *testing.T) {
	orig := lookupNodeIPs
	defer func() { lookupNodeIPs = orig }()
	lookupNodeIPs = func(_ context.Context, host string) ([]net.IP, error) {
		if host == "public.example" {
			return []net.IP{net.ParseIP("1.1.1.1")}, nil
		}
		return nil, errors.New("no such host")
	}

	cases := []struct {
		name    string
		payload string
	}{
		{
			name:    "双引号重复 server 键",
			payload: "name: p\ntype: socks5\nserver: 1.2.3.4\nport: 22\n\"server\": 127.0.0.1\n",
		},
		{
			name:    "单引号重复 server 键",
			payload: "name: p\ntype: socks5\nserver: 1.2.3.4\nport: 22\n'server': 127.0.0.1\n",
		},
		{
			name:    "带 !!str 标签的重复 server 键",
			payload: "name: p\ntype: socks5\nserver: 1.2.3.4\nport: 22\n!!str server: 127.0.0.1\n",
		},
		{
			name:    "显式键重复 server",
			payload: "name: p\ntype: socks5\nserver: 1.2.3.4\nport: 22\n? server\n: 127.0.0.1\n",
		},
		{
			name:    "合并键内联映射覆盖 server",
			payload: "name: p\ntype: trojan\nserver: 1.2.3.4\nport: 443\npassword: x\n<<: &m\n  server: 169.254.169.254\n",
		},
		{
			name:    "合并键别名覆盖 server",
			payload: "base: &b\n  server: 169.254.169.254\nname: p\ntype: trojan\nserver: 1.2.3.4\nport: 443\npassword: x\n<<: *b\n",
		},
		{
			name:    "CRLF 重复 server 键",
			payload: "name: p\r\ntype: socks5\r\nserver: 1.2.3.4\r\nport: 22\r\n\"server\": 127.0.0.1\r\n",
		},
		{
			name:    "BOM 重复 server 键",
			payload: "\ufeffname: p\ntype: socks5\nserver: 1.2.3.4\nport: 22\n\"server\": 127.0.0.1\n",
		},
		{
			name:    "流式映射重复 server 键",
			payload: "{name: p, type: socks5, server: 1.2.3.4, port: 22, \"server\": 127.0.0.1}",
		},
		{
			name:    "只有引号 server 键",
			payload: "name: p\ntype: socks5\nport: 22\n\"server\": 127.0.0.1\n",
		},
		{
			name:    "只有合并键提供 server",
			payload: "name: p\ntype: trojan\nport: 443\n<<: &m\n  server: 169.254.169.254\n",
		},
		{
			name:    "server 值使用锚点",
			payload: "name: p\ntype: ss\nserver: &a 1.2.3.4\nport: 443\n",
		},
		{
			name:    "server 值使用别名",
			payload: "base: &b 1.2.3.4\nname: p\ntype: ss\nserver: *b\nport: 443\n",
		},
		{
			name:    "多 YAML 文档",
			payload: "name: p\ntype: ss\nserver: 1.2.3.4\nport: 443\n---\nname: q\ntype: ss\nserver: 6.6.6.6\nport: 443\n",
		},
		{
			name:    "根不是映射",
			payload: "- name: p\n  type: ss\n  server: 1.2.3.4\n  port: 443\n",
		},
		{
			name:    "重复非 server 键",
			payload: "name: p\nname: q\ntype: ss\nserver: 1.2.3.4\nport: 443\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nodes := []MiaospeedNode{{
				Name:     tc.name,
				Server:   "public.example:443",
				Protocol: "ss",
				Payload:  tc.payload,
			}}
			kept, removed := filterBlockedNodes(context.Background(), nodes, nil)
			if len(kept) != 0 || removed != 1 {
				t.Fatalf("语义上可能覆盖 server 的节点应被剔除，kept=%+v removed=%d\npayload:\n%s", kept, removed, tc.payload)
			}
		})
	}
}

// TestFilterBlockedNodesRejectsClashListSemanticBypasses 覆盖 C1 在 Clash 列表项
// （块式与流式）里的变体：单个节点 payload 仍由 parseClashYAMLProxies 切分后
// 走同一语义闸门。
func TestFilterBlockedNodesRejectsClashListSemanticBypasses(t *testing.T) {
	orig := lookupNodeIPs
	defer func() { lookupNodeIPs = orig }()
	lookupNodeIPs = func(_ context.Context, host string) ([]net.IP, error) {
		if host == "public.example" {
			return []net.IP{net.ParseIP("1.1.1.1")}, nil
		}
		return nil, errors.New("no such host")
	}

	cases := []struct{ name, content string }{
		{
			name: "proxies 块项双引号 server 覆盖",
			content: "proxies:\n" +
				"  - name: x\n    type: socks5\n    server: public.example\n    port: 22\n    \"server\": 127.0.0.1\n",
		},
		{
			name: "proxies 块项合并键覆盖",
			content: "proxies:\n" +
				"  - name: x\n    type: trojan\n    server: public.example\n    port: 443\n    password: x\n    <<: &m\n      server: 169.254.169.254\n",
		},
		{
			name: "proxies 流式项双引号 server 覆盖",
			content: "proxies:\n" +
				"  - {name: x, type: ss, server: public.example, port: 22, cipher: aes-256-gcm, password: p, \"server\": 198.51.100.1}\n",
		},
		{
			name: "proxies 流式项单引号 server 覆盖",
			content: "proxies:\n" +
				"  - {name: x, type: ss, server: public.example, port: 22, cipher: aes-256-gcm, password: p, 'server': 198.51.100.1}\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nodes, err := parseProxyContent(tc.content)
			if err != nil {
				t.Fatalf("解析配置失败：%v\n%s", err, tc.content)
			}
			kept, removed := filterBlockedNodes(context.Background(), nodes, nil)
			if len(kept) != 0 || removed != len(nodes) {
				t.Fatalf("含语义覆盖的节点应全部剔除，kept=%+v removed=%d\n%s", kept, removed, tc.content)
			}
		})
	}
}

// TestFilterBlockedNodesRejectsProtocolAddressOverrides 覆盖 C2/C3：
// tuic 顶层 ip 与 wireguard peers[].server 会覆盖 mihomo 实际拨号地址。
func TestFilterBlockedNodesRejectsProtocolAddressOverrides(t *testing.T) {
	orig := lookupNodeIPs
	defer func() { lookupNodeIPs = orig }()
	lookupNodeIPs = func(_ context.Context, host string) ([]net.IP, error) {
		if host == "public.example" {
			return []net.IP{net.ParseIP("1.1.1.1")}, nil
		}
		return nil, errors.New("no such host")
	}

	cases := []struct {
		name     string
		protocol string
		payload  string
	}{
		{
			name:     "tuic 顶层 ip 覆盖拨号地址",
			protocol: "tuic",
			payload:  "name: p\ntype: tuic\nserver: public.example\nport: 8443\nuuid: u\npassword: p\nip: 169.254.169.254\n",
		},
		{
			name:     "tuic 类型大小写不敏感",
			protocol: "tuic",
			payload:  "name: p\ntype: TUIC\nserver: public.example\nport: 8443\nuuid: u\npassword: p\nip: 127.0.0.1\n",
		},
		{
			name:     "wireguard 单 peer server 覆盖",
			protocol: "wireguard",
			payload: "name: p\ntype: wireguard\nserver: public.example\nport: 51820\nprivate-key: x\n" +
				"peers:\n  - server: 169.254.169.254\n    port: 51820\n    public-key: y\n",
		},
		{
			name:     "wireguard 顶层 server 与 peers 同时存在",
			protocol: "wireguard",
			payload: "name: p\ntype: WireGuard\nserver: public.example\nport: 51820\nprivate-key: x\npublic-key: y\n" +
				"peers:\n  - server: public.example\n    port: 51820\n    public-key: z\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nodes := []MiaospeedNode{{
				Name:     tc.name,
				Server:   "public.example:443",
				Protocol: tc.protocol,
				Payload:  tc.payload,
			}}
			kept, removed := filterBlockedNodes(context.Background(), nodes, nil)
			if len(kept) != 0 || removed != 1 {
				t.Fatalf("协议地址覆盖字段应导致节点被剔除，kept=%+v removed=%d", kept, removed)
			}
		})
	}
}

// TestFilterBlockedNodesKeepsNormalProtocolNodes 验证白名单内全部协议的正常节点不会
// 被语义闸门误伤，并且最终 yaml.v2 解码出的连接地址就是本次校验并钉死的地址。
func TestFilterBlockedNodesKeepsNormalProtocolNodes(t *testing.T) {
	orig := lookupNodeIPs
	defer func() { lookupNodeIPs = orig }()
	lookupNodeIPs = func(_ context.Context, host string) ([]net.IP, error) {
		if host == "public.example" {
			return []net.IP{net.ParseIP("1.1.1.1")}, nil
		}
		return nil, errors.New("no such host")
	}

	cases := []struct {
		name     string
		protocol string
		port     int
		payload  string
	}{
		{
			name:     "vmess ws tls",
			protocol: "vmess",
			port:     443,
			payload: "name: v\ntype: vmess\nserver: public.example\nport: 443\nuuid: u\nalterId: 0\ncipher: auto\n" +
				"network: ws\nws-opts:\n  path: /ws\n  headers:\n    Host: cdn.example\nservername: front.example\n",
		},
		{
			name:     "vless ws tls",
			protocol: "vless",
			port:     443,
			payload: "name: v\ntype: vless\nserver: public.example\nport: 443\nuuid: u\nnetwork: ws\ntls: true\n" +
				"servername: front.example\nws-opts:\n  path: /ws\n",
		},
		{
			name:     "trojan",
			protocol: "trojan",
			port:     443,
			payload:  "name: t\ntype: trojan\nserver: public.example\nport: 443\npassword: p\nsni: front.example\n",
		},
		{
			name:     "trojan 大写 SNI 键不会被重复补全",
			protocol: "trojan",
			port:     443,
			payload:  "name: t\ntype: trojan\nserver: public.example\nport: 443\npassword: p\nSNI: front.example\n",
		},
		{
			name:     "shadowsocks",
			protocol: "ss",
			port:     8388,
			payload:  "name: s\ntype: ss\nserver: public.example\nport: 8388\ncipher: aes-256-gcm\npassword: p\n",
		},
		{
			name:     "hysteria2",
			protocol: "hysteria2",
			port:     443,
			payload:  "name: h\ntype: hysteria2\nserver: public.example\nport: 443\npassword: p\nsni: front.example\n",
		},
		{
			name:     "tuic 无 ip",
			protocol: "tuic",
			port:     8443,
			payload: "name: t\ntype: tuic\nserver: public.example\nport: 8443\nuuid: u\npassword: p\nsni: front.example\n" +
				"congestion-controller: bbr\nudp-relay-mode: native\n",
		},
		{
			name:     "shadowsocksr",
			protocol: "ssr",
			port:     8388,
			payload:  "name: r\ntype: ssr\nserver: public.example\nport: 8388\ncipher: aes-128-cfb\npassword: p\nprotocol: origin\nobfs: plain\n",
		},
		{
			name:     "socks5",
			protocol: "socks5",
			port:     1080,
			payload:  "name: k\ntype: socks5\nserver: public.example\nport: 1080\nusername: u\npassword: p\n",
		},
		{
			name:     "http",
			protocol: "http",
			port:     8080,
			payload:  "name: h\ntype: http\nserver: public.example\nport: 8080\ntls: true\nsni: front.example\nheaders:\n  X-Test: 1\n",
		},
		{
			name:     "snell",
			protocol: "snell",
			port:     8388,
			payload:  "name: s\ntype: snell\nserver: public.example\nport: 8388\npsk: p\nversion: 4\n",
		},
		{
			name:     "hysteria v1 带端口跳跃",
			protocol: "hysteria",
			port:     443,
			payload: "name: h\ntype: hysteria\nserver: public.example\nport: 443\nports: 1000-2000\nprotocol: udp\n" +
				"up: 100 mbps\ndown: 100 mbps\nauth-str: a\nsni: front.example\n",
		},
		{
			name:     "hysteria2 带端口跳跃",
			protocol: "hysteria2",
			port:     443,
			payload:  "name: h\ntype: hysteria2\nserver: public.example\nport: 443\nports: 1000-2000\npassword: p\n",
		},
		{
			name:     "anytls",
			protocol: "anytls",
			port:     443,
			payload:  "name: a\ntype: anytls\nserver: public.example\nport: 443\npassword: p\nsni: front.example\n",
		},
		{
			name:     "vmess mekya 传输（url 不改变拨号目标）",
			protocol: "vmess",
			port:     443,
			payload: "name: m\ntype: vmess\nserver: public.example\nport: 443\nuuid: u\nalterId: 0\ncipher: auto\n" +
				"network: mekya\ntls: true\nservername: front.example\n",
		},
		{
			name:     "CRLF 正常节点",
			protocol: "ss",
			port:     8388,
			payload:  "name: s\r\ntype: ss\r\nserver: public.example\r\nport: 8388\r\ncipher: aes-256-gcm\r\npassword: p\r\n",
		},
		{
			name:     "BOM 正常节点",
			protocol: "ss",
			port:     8388,
			payload:  "\ufeffname: s\ntype: ss\nserver: public.example\nport: 8388\ncipher: aes-256-gcm\npassword: p\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nodes := []MiaospeedNode{{
				Name:     tc.name,
				Server:   fmt.Sprintf("public.example:%d", tc.port),
				Protocol: tc.protocol,
				Payload:  tc.payload,
			}}
			kept, removed := filterBlockedNodes(context.Background(), nodes, nil)
			if removed != 0 || len(kept) != 1 {
				t.Fatalf("正常节点不应被误剔除，kept=%+v removed=%d", kept, removed)
			}
			if got := topLevelPayloadServer(t, kept[0].Payload); got != "1.1.1.1" {
				t.Fatalf("payload 顶层 server = %q，应为校验地址 1.1.1.1：%s", got, kept[0].Payload)
			}
		})
	}
}

// TestFilterBlockedNodesKeepsTrailingCommentNode 验证 `server: 1.2.3.4 # 备注`
// 的行尾注释不会把地址一起带入，合法公网节点应保留。
func TestFilterBlockedNodesKeepsTrailingCommentNode(t *testing.T) {
	orig := lookupNodeIPs
	defer func() { lookupNodeIPs = orig }()
	lookupNodeIPs = func(_ context.Context, host string) ([]net.IP, error) {
		if host == "public.example" {
			return []net.IP{net.ParseIP("1.1.1.1")}, nil
		}
		return nil, errors.New("no such host")
	}

	cases := []struct{ name, content, wantServer string }{
		{
			name: "Clash 列表项行尾注释",
			content: "proxies:\n" +
				"  - name: c\n    type: ss\n    server: public.example # 备注\n    port: 443\n    cipher: aes-256-gcm\n    password: p\n",
			wantServer: "public.example:443",
		},
		{
			name:       "单 YAML 节点行尾注释",
			content:    "name: c\ntype: ss\nserver: public.example # 备注\nport: 443\ncipher: aes-256-gcm\npassword: p\n",
			wantServer: "public.example:443",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nodes, err := parseProxyContent(tc.content)
			if err != nil {
				t.Fatalf("解析配置失败：%v", err)
			}
			if len(nodes) != 1 {
				t.Fatalf("应解析出 1 个节点：%+v", nodes)
			}
			if nodes[0].Server != tc.wantServer {
				t.Fatalf("Server = %q，应为 %q", nodes[0].Server, tc.wantServer)
			}
			kept, removed := filterBlockedNodes(context.Background(), nodes, nil)
			if removed != 0 || len(kept) != 1 {
				t.Fatalf("带行尾注释的公网节点应保留，kept=%+v removed=%d", kept, removed)
			}
			if got := topLevelPayloadServer(t, kept[0].Payload); got != "1.1.1.1" {
				t.Fatalf("payload 顶层 server = %q，应为 1.1.1.1：%s", got, kept[0].Payload)
			}
		})
	}
}

// TestStripYAMLInlineComment 验证只剥离引号外的行尾注释，`#` 紧贴值或位于引号内时保留。
func TestStripYAMLInlineComment(t *testing.T) {
	cases := []struct{ in, want string }{
		{"server: 1.2.3.4 # 备注", "server: 1.2.3.4"},
		{"server: 1.2.3.4\t# 备注", "server: 1.2.3.4"},
		{"server: 1.2.3.4#不是注释", "server: 1.2.3.4#不是注释"},
		{`name: "a # b" # 备注`, `name: "a # b"`},
		{`name: 'a # b' # 备注`, `name: 'a # b'`},
		{"# 整行注释", ""},
	}
	for _, tc := range cases {
		if got := stripYAMLInlineComment(tc.in); got != tc.want {
			t.Fatalf("stripYAMLInlineComment(%q) = %q，期望 %q", tc.in, got, tc.want)
		}
	}
}

// TestFilterBlockedNodesPinsIPv6Canonical 验证 IPv6 钉死后 yaml.v2 解码出的 server
// 与 net.IP.String() 的规范形式完全一致。
func TestFilterBlockedNodesPinsIPv6Canonical(t *testing.T) {
	orig := lookupNodeIPs
	defer func() { lookupNodeIPs = orig }()
	lookupNodeIPs = func(_ context.Context, host string) ([]net.IP, error) {
		if host == "v6.example" {
			return []net.IP{net.ParseIP("2606:4700:0:0:0:0:0:1")}, nil
		}
		return nil, errors.New("no such host")
	}
	nodes := []MiaospeedNode{{
		Name:     "v6",
		Server:   "v6.example:443",
		Protocol: "trojan",
		Payload:  "name: v6\ntype: trojan\nserver: v6.example\nport: 443\npassword: p\n",
	}}
	kept, removed := filterBlockedNodes(context.Background(), nodes, nil)
	if removed != 0 || len(kept) != 1 {
		t.Fatalf("IPv6 域名节点应保留，kept=%+v removed=%d", kept, removed)
	}
	if got, want := topLevelPayloadServer(t, kept[0].Payload), "2606:4700::1"; got != want {
		t.Fatalf("payload 顶层 server = %q，应为规范 IPv6 %q：%s", got, want, kept[0].Payload)
	}
}
