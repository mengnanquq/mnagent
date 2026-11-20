package miaospeed

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// yamlScalar 从 Payload 中取 key 对应的双引号标量并按 Go 转义规则还原。
// quoteYAML 的输出与 Go 字符串字面量兼容（\\ \" \n \r \t），因此可以直接 Unquote；
// 如果字段未转义而含换行/引号，这里会解析失败，从而暴露 YAML 结构被破坏的问题。
func yamlScalar(t *testing.T, payload, key string) string {
	t.Helper()
	for _, line := range strings.Split(payload, "\n") {
		if !strings.HasPrefix(line, key+": ") {
			continue
		}
		raw := strings.TrimPrefix(line, key+": ")
		value, err := strconv.Unquote(raw)
		if err != nil {
			t.Fatalf("字段 %s 不是合法的双引号 YAML 标量: %q（%v）\npayload:\n%s", key, raw, err, payload)
		}
		return value
	}
	t.Fatalf("payload 中未找到字段 %s:\n%s", key, payload)
	return ""
}

// TestSingBoxYAMLFieldsAreQuoted 覆盖 sing-box 转换中的 cipher/uuid/network 等字段。
func TestSingBoxYAMLFieldsAreQuoted(t *testing.T) {
	t.Run("shadowsocks cipher", func(t *testing.T) {
		ob := singBoxOutbound{
			Type:       "shadowsocks",
			Server:     "1.2.3.4",
			ServerPort: 8388,
			Method:     "aes-256-gcm\"\n: injected",
			Password:   "p\"w\n:123",
		}
		node := convertSingBoxOutbound(ob)
		if node == nil {
			t.Fatal("转换结果为空")
		}
		if got := yamlScalar(t, node.Payload, "cipher"); got != ob.Method {
			t.Fatalf("cipher = %q, want %q", got, ob.Method)
		}
		if got := yamlScalar(t, node.Payload, "password"); got != ob.Password {
			t.Fatalf("password = %q, want %q", got, ob.Password)
		}
	})

	t.Run("vmess uuid/cipher/network", func(t *testing.T) {
		ob := singBoxOutbound{
			Type:       "vmess",
			Server:     "1.2.3.4",
			ServerPort: 443,
			UUID:       "uuid\"\n: injected",
			Security:   "auto\"\n:bad",
			Transport: &struct {
				Type        string            `json:"type"`
				Path        string            `json:"path"`
				Headers     map[string]string `json:"headers"`
				ServiceName string            `json:"service_name"`
			}{Type: "ws\"\n:bad"},
		}
		node := convertSingBoxOutbound(ob)
		if node == nil {
			t.Fatal("转换结果为空")
		}
		if got := yamlScalar(t, node.Payload, "uuid"); got != ob.UUID {
			t.Fatalf("uuid = %q, want %q", got, ob.UUID)
		}
		if got := yamlScalar(t, node.Payload, "cipher"); got != ob.Security {
			t.Fatalf("cipher = %q, want %q", got, ob.Security)
		}
		if got := yamlScalar(t, node.Payload, "network"); got != ob.Transport.Type {
			t.Fatalf("network = %q, want %q", got, ob.Transport.Type)
		}
	})

	t.Run("vless uuid/network", func(t *testing.T) {
		ob := singBoxOutbound{
			Type:       "vless",
			Server:     "1.2.3.4",
			ServerPort: 443,
			UUID:       "uuid\"\n: injected",
			Transport: &struct {
				Type        string            `json:"type"`
				Path        string            `json:"path"`
				Headers     map[string]string `json:"headers"`
				ServiceName string            `json:"service_name"`
			}{Type: "grpc\"\n:bad"},
		}
		node := convertSingBoxOutbound(ob)
		if node == nil {
			t.Fatal("转换结果为空")
		}
		if got := yamlScalar(t, node.Payload, "uuid"); got != ob.UUID {
			t.Fatalf("uuid = %q, want %q", got, ob.UUID)
		}
		if got := yamlScalar(t, node.Payload, "network"); got != ob.Transport.Type {
			t.Fatalf("network = %q, want %q", got, ob.Transport.Type)
		}
	})

	t.Run("trojan network", func(t *testing.T) {
		ob := singBoxOutbound{
			Type:       "trojan",
			Server:     "1.2.3.4",
			ServerPort: 443,
			Password:   "p",
			Transport: &struct {
				Type        string            `json:"type"`
				Path        string            `json:"path"`
				Headers     map[string]string `json:"headers"`
				ServiceName string            `json:"service_name"`
			}{Type: "grpc\"\n:bad"},
		}
		node := convertSingBoxOutbound(ob)
		if node == nil {
			t.Fatal("转换结果为空")
		}
		if got := yamlScalar(t, node.Payload, "network"); got != ob.Transport.Type {
			t.Fatalf("network = %q, want %q", got, ob.Transport.Type)
		}
	})
}

// TestURIYAMLFieldsAreQuoted 覆盖 ss/vmess/ssr/hysteria/snell URI 解析中
// 直接从 URI 取值并写入 YAML 的字段。
func TestURIYAMLFieldsAreQuoted(t *testing.T) {
	t.Run("ss method", func(t *testing.T) {
		method := "aes-256-gcm\"\n"
		password := "pa:ss\"\nword"
		userInfo := base64.RawURLEncoding.EncodeToString([]byte(method + ":" + password))
		node, err := parseProxyURI("ss://" + userInfo + "@1.2.3.4:8388#SS")
		if err != nil {
			t.Fatal(err)
		}
		if got := yamlScalar(t, node.Payload, "cipher"); got != method {
			t.Fatalf("cipher = %q, want %q", got, method)
		}
		if got := yamlScalar(t, node.Payload, "password"); got != password {
			t.Fatalf("password = %q, want %q", got, password)
		}
	})

	t.Run("vmess uuid/cipher/network", func(t *testing.T) {
		uuid := "uuid\"\n: injected"
		cipher := "auto\"\n:bad"
		netType := "ws\"\n:tcp"
		payload, err := json.Marshal(map[string]any{
			"ps": "n", "add": "1.2.3.4", "port": 443,
			"id": uuid, "aid": 0, "scy": cipher, "net": netType,
		})
		if err != nil {
			t.Fatal(err)
		}
		node, err := parseProxyURI("vmess://" + base64.RawURLEncoding.EncodeToString(payload))
		if err != nil {
			t.Fatal(err)
		}
		// vmess JSON 字段会先经过 sanitizeYAMLToken 去掉换行/制表符。
		if got := yamlScalar(t, node.Payload, "uuid"); got != sanitizeYAMLToken(uuid) {
			t.Fatalf("uuid = %q, want %q", got, sanitizeYAMLToken(uuid))
		}
		if got := yamlScalar(t, node.Payload, "cipher"); got != sanitizeYAMLToken(cipher) {
			t.Fatalf("cipher = %q, want %q", got, sanitizeYAMLToken(cipher))
		}
		if got := yamlScalar(t, node.Payload, "network"); got != sanitizeYAMLToken(netType) {
			t.Fatalf("network = %q, want %q", got, sanitizeYAMLToken(netType))
		}
	})

	t.Run("ssr cipher/protocol/obfs", func(t *testing.T) {
		method := "aes-256-cfb\"\n"
		protocol := "auth_sha1_v4\"\n"
		obfs := "tls1.2_ticket_auth\""
		main := "1.2.3.4:8388:" + protocol + ":" + method + ":" + obfs + ":" +
			base64.RawURLEncoding.EncodeToString([]byte("pass"))
		node, err := parseProxyURI("ssr://" + base64.RawURLEncoding.EncodeToString([]byte(main)))
		if err != nil {
			t.Fatal(err)
		}
		if got := yamlScalar(t, node.Payload, "cipher"); got != method {
			t.Fatalf("cipher = %q, want %q", got, method)
		}
		if got := yamlScalar(t, node.Payload, "protocol"); got != protocol {
			t.Fatalf("protocol = %q, want %q", got, protocol)
		}
		if got := yamlScalar(t, node.Payload, "obfs"); got != obfs {
			t.Fatalf("obfs = %q, want %q", got, obfs)
		}
	})

	t.Run("hysteria protocol", func(t *testing.T) {
		protocol := "udp\"\n:bad"
		q := url.Values{}
		q.Set("protocol", protocol)
		node, err := parseProxyURI("hysteria://1.2.3.4:443?" + q.Encode() + "#HY")
		if err != nil {
			t.Fatal(err)
		}
		if got := yamlScalar(t, node.Payload, "protocol"); got != protocol {
			t.Fatalf("protocol = %q, want %q", got, protocol)
		}
	})

	t.Run("snell version 非数字时丢弃节点", func(t *testing.T) {
		version := "4\"\n:bad"
		q := url.Values{}
		q.Set("version", version)
		if node, err := parseProxyURI("snell://psk@1.2.3.4:443?" + q.Encode() + "#SN"); err == nil || node != nil {
			t.Fatalf("非法 snell version 应丢弃节点，实际 node=%v err=%v", node, err)
		}
	})
}

// TestSnellVersionIsInteger 验证 snell version 以整数输出（不是字符串 "4"）。
func TestSnellVersionIsInteger(t *testing.T) {
	node, err := parseProxyURI("snell://psk@1.2.3.4:443#SN")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(node.Payload, "version: 4\n") {
		t.Fatalf("snell version 应以整数输出，实际 payload:\n%s", node.Payload)
	}
	if strings.Contains(node.Payload, `version: "4"`) {
		t.Fatalf("snell version 不应被 quoteYAML 变成字符串，实际 payload:\n%s", node.Payload)
	}
	q := url.Values{}
	q.Set("version", "5")
	node, err = parseProxyURI("snell://psk@1.2.3.4:443?" + q.Encode() + "#SN")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(node.Payload, "version: 5\n") {
		t.Fatalf("显式 version=5 应以整数输出，实际 payload:\n%s", node.Payload)
	}
}

// TestQuoteYAMLEscapesControlChars 验证其余 C0 控制字符与 DEL 被转义为 \xNN，
// 输出可被 YAML/Go 的双引号标量解析还原。
func TestQuoteYAMLEscapesControlChars(t *testing.T) {
	in := "a\x00b\x01c\x1fd\x7fe\tf"
	quoted := quoteYAML(in)
	for _, raw := range []byte{0x00, 0x01, 0x1f, 0x7f} {
		if strings.IndexByte(quoted, raw) >= 0 {
			t.Fatalf("quoteYAML 输出仍包含原始控制字节 0x%02x: %q", raw, quoted)
		}
	}
	got, err := strconv.Unquote(quoted)
	if err != nil {
		t.Fatalf("quoteYAML 输出不是合法双引号标量: %q（%v）", quoted, err)
	}
	if got != in {
		t.Fatalf("控制字符还原失败: got %q, want %q", got, in)
	}
	for _, want := range []string{`\x00`, `\x01`, `\x1f`, `\x7f`} {
		if !strings.Contains(quoted, want) {
			t.Fatalf("quoteYAML 输出缺少转义 %s: %q", want, quoted)
		}
	}
}
