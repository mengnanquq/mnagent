package miaospeed

import (
	"strings"
	"testing"
)

// 本文件是 mihomo 出站 option 结构体的“字段快照”，用来防止节点安全闸门的禁止表
// 与 mihomo 实际解码的字段名脱节（闸门按字段名拦截，字段名对不上就是空隙）。
//
// 快照按 mihomo v1.19.33-x365-miu.2（github.com/AirportR/mihomo，即 miaospeed 依赖的
// 版本）的 adapter/outbound/*.go 手工抄录，只包含 `proxy:"..."` 标签（不含 `proxy:"-"`）：
//
//	adapter/outbound/base.go:193-207          BasicOption（所有协议共享）
//	adapter/outbound/shadowsocks.go:43-56     ShadowSocksOption
//	adapter/outbound/shadowsocksr.go:28-40    ShadowSocksROption
//	adapter/outbound/socks5.go:30-44          Socks5Option
//	adapter/outbound/http.go:28-43            HttpOption
//	adapter/outbound/vmess.go:53-89           VmessOption
//	adapter/outbound/vless.go:58-91           VlessOption
//	adapter/outbound/trojan.go:45-69          TrojanOption
//	adapter/outbound/snell.go:32-43           SnellOption
//	adapter/outbound/hysteria.go:101-129      HysteriaOption
//	adapter/outbound/hysteria2.go:39-73       Hysteria2Option
//	adapter/outbound/anytls.go:27-51          AnyTLSOption
//	adapter/outbound/tuic.go:34-70            TuicOption
//
// 这里绝不能 import mihomo：那会把整个代理内核拉进 agent，也等于新增依赖。
// 因为无法在测试里反射 mihomo 的结构体，快照只能靠人工维护：
//
//	升级 miaospeed / mihomo 版本时必须重新核对本文件，逐个比对 option 结构体的
//	proxy tag 字段名；任何新增或改名的“地址类”字段（server/ip/url/... 的同类）
//	都必须先补进 nodeForbiddenAddressKeys 或 nodeForbiddenNestedKeys，再更新快照，
//	否则新字段会成为绕过闸门（把拨号目标改到内网/元数据地址）的空隙。
const mihomoSnapshotVersion = "v1.19.33-x365-miu.2"

// mihomoBasicOptionFields 是 base.go:193-207 的 BasicOption 字段（所有白名单协议都内嵌）。
const mihomoBasicOptionFields = "tfo mptcp interface-name routing-mark ip-version dialer-proxy"

// mihomoOptionFieldSnapshot 记录白名单 12 个协议顶层 proxy tag 字段名（空格分隔，已含 BasicOption）。
var mihomoOptionFieldSnapshot = map[string]string{
	"ss": "name server port password cipher udp plugin plugin-opts udp-over-tcp udp-over-tcp-version " +
		"client-fingerprint " + mihomoBasicOptionFields,
	"ssr": "name server port password cipher obfs obfs-param protocol protocol-param udp " +
		mihomoBasicOptionFields,
	"socks5": "name server port username password tls udp skip-cert-verify name-cert-verify " +
		"fingerprint certificate private-key " + mihomoBasicOptionFields,
	"http": "name server port username password tls sni skip-cert-verify name-cert-verify " +
		"fingerprint certificate private-key headers " + mihomoBasicOptionFields,
	"vmess": "name server port uuid alterId cipher udp network tls alpn skip-cert-verify " +
		"name-cert-verify fingerprint certificate private-key servername ech-opts shadow-tls-opts " +
		"restls-opts jls-opts reality-opts tlsmirror-opts mekya-opts mkcp-opts http-opts h2-opts " +
		"grpc-opts ws-opts packet-addr xudp packet-encoding global-padding authenticated-length " +
		"client-fingerprint " + mihomoBasicOptionFields,
	"vless": "name server port uuid flow tls alpn udp packet-addr xudp packet-encoding encryption " +
		"network ech-opts shadow-tls-opts restls-opts jls-opts reality-opts http-opts h2-opts " +
		"grpc-opts ws-opts xhttp-opts ws-headers skip-cert-verify name-cert-verify fingerprint " +
		"certificate private-key servername client-fingerprint " + mihomoBasicOptionFields,
	"trojan": "name server port password alpn sni skip-cert-verify name-cert-verify fingerprint " +
		"certificate private-key udp network ech-opts shadow-tls-opts restls-opts jls-opts " +
		"reality-opts grpc-opts ws-opts ss-opts client-fingerprint " + mihomoBasicOptionFields,
	"snell": "name server port psk udp version reuse obfs-opts client-fingerprint " +
		mihomoBasicOptionFields,
	"hysteria": "name server port ports protocol obfs-protocol up up-speed down down-speed auth " +
		"auth-str obfs sni ech-opts skip-cert-verify name-cert-verify fingerprint certificate " +
		"private-key alpn recv-window-conn recv-window disable-mtu-discovery fast-open hop-interval " +
		mihomoBasicOptionFields,
	"hysteria2": "name server port ports hop-interval up down password obfs obfs-password " +
		"obfs-min-packet-size obfs-max-packet-size sni ech-opts skip-cert-verify name-cert-verify " +
		"fingerprint certificate private-key alpn cwnd bbr-profile udp-mtu handshake-timeout " +
		"realm-opts initial-stream-receive-window max-stream-receive-window " +
		"initial-connection-receive-window max-connection-receive-window " + mihomoBasicOptionFields,
	"anytls": "name server port password alpn sni ech-opts shadow-tls-opts restls-opts jls-opts " +
		"client-fingerprint skip-cert-verify name-cert-verify fingerprint certificate private-key " +
		"udp client-metadata idle-session-check-interval idle-session-timeout min-idle-session " +
		"disable-reuse " + mihomoBasicOptionFields,
	"tuic": "name server port token uuid password ip heartbeat-interval alpn reduce-rtt " +
		"request-timeout udp-relay-mode congestion-controller disable-sni " +
		"max-udp-relay-packet-size fast-open max-open-streams cwnd bbr-profile skip-cert-verify " +
		"name-cert-verify fingerprint certificate private-key recv-window-conn recv-window " +
		"disable-mtu-discovery max-datagram-frame-size sni ech-opts udp-over-stream " +
		"udp-over-stream-version " + mihomoBasicOptionFields,
}

// mihomoNestedAddressFieldSnapshot 是 mihomo 白名单协议里已知的“嵌套地址类字段”路径快照。
// 这些字段不在协议 option 的顶层，但同样能让 mihomo 去访问 server 以外的地址：
//
//	ss.plugin-opts.ech-opts.query-server-name            shadowsocks.go:68/85（v2ray/gost obfs 的 ECH）
//	vless.xhttp-opts.download-settings.server            vless.go:137（vless.go:724-726 用它生成 downloadAddr）
//	vless.xhttp-opts.download-settings.ech-opts.query-server-name  vless.go:141（同上，嵌套 ECH）
//	vmess.mekya-opts.url                                 vmess.go:118
//	hysteria2.realm-opts.server-url                      hysteria2.go:77
//	hysteria2.realm-opts.stun-servers                    hysteria2.go:80
//	*（所有带 ech-opts 的协议）.ech-opts.query-server-name  ech.go:12-17（vmess/vless/trojan/hysteria/
//	                                                     hysteria2/anytls/tuic 顶层都有 ech-opts）
//
// 路径里的 "*" 表示“任意协议顶层”，实际比对的仍然只是叶子字段名。
var mihomoNestedAddressFieldSnapshot = []string{
	"*.ech-opts.query-server-name",
	"ss.plugin-opts.ech-opts.query-server-name",
	"vless.xhttp-opts.download-settings.server",
	"vless.xhttp-opts.download-settings.ech-opts.query-server-name",
	"vmess.mekya-opts.url",
	"hysteria2.realm-opts.server-url",
	"hysteria2.realm-opts.stun-servers",
}

// mihomoAddressSemanticFields 是快照里具有“目标/查询地址”语义的顶层字段名。
// 新增 mihomo 版本若出现同类字段（例如新的外链 URL 字段），先补进这里并同步禁止表。
var mihomoAddressSemanticFields = []string{
	"ip", "ipv6", "peers", "control-url", "endpoint",
	"url", "server-url", "stun-servers", "query-server-name", "dialer-proxy",
}

// TestMihomoOptionFieldSnapshotMatchesWhitelist 校验快照覆盖范围：白名单协议与快照一一对应，
// 且每个协议都能看到 server/port 字段（顶层 server 是闸门唯一允许的拨号目标）。
func TestMihomoOptionFieldSnapshotMatchesWhitelist(t *testing.T) {
	if len(mihomoOptionFieldSnapshot) != len(allowedNodeProtocols) {
		t.Fatalf("字段快照协议数 %d 与白名单协议数 %d 不一致（mihomo %s 升级后必须重新核对）",
			len(mihomoOptionFieldSnapshot), len(allowedNodeProtocols), mihomoSnapshotVersion)
	}
	for protocol := range allowedNodeProtocols {
		fields, ok := mihomoOptionFieldSnapshot[protocol]
		if !ok {
			t.Fatalf("白名单协议 %q 缺少 mihomo 字段快照（mihomo %s）", protocol, mihomoSnapshotVersion)
		}
		if !snapshotHasField(fields, "server") || !snapshotHasField(fields, "port") {
			t.Fatalf("协议 %q 的字段快照必须包含 server/port：%s", protocol, fields)
		}
	}
	for protocol := range mihomoOptionFieldSnapshot {
		if _, ok := allowedNodeProtocols[protocol]; !ok {
			t.Fatalf("字段快照里的协议 %q 不在白名单中", protocol)
		}
	}
}

// TestMihomoSnapshotAddressFieldsAreForbidden 断言禁止表覆盖快照里所有已知地址类字段：
//   - 顶层：除 server（唯一允许的拨号目标）以外，全部必须命中 nodeForbiddenTopLevelKeys；
//   - 嵌套：任意深度的 server 与全部地址类字段都必须命中 nodeForbiddenNestedKeys。
//
// 这个测试的作用是“文档化 + 回归”：mihomo 升级、改动禁止表或快照时，
// 地址类字段一旦漏掉就会在这里失败。
func TestMihomoSnapshotAddressFieldsAreForbidden(t *testing.T) {
	for protocol, fields := range mihomoOptionFieldSnapshot {
		for _, field := range strings.Fields(fields) {
			if field == "server" {
				// 顶层 server 是唯一允许的拨号目标，但嵌套 server 必须被拦截。
				if !nodeNestedKeyForbidden(field) {
					t.Fatalf("协议 %q 的嵌套字段 server 必须在嵌套禁止表里", protocol)
				}
				continue
			}
			if !isMihomoAddressSemanticField(field) {
				continue
			}
			if _, bad := nodeForbiddenTopLevelKeys[normalizePayloadKey(field)]; !bad {
				t.Fatalf("协议 %q 的顶层地址字段 %q 必须被顶层禁止表拦截（mihomo %s）",
					protocol, field, mihomoSnapshotVersion)
			}
			if !nodeNestedKeyForbidden(field) {
				t.Fatalf("协议 %q 的地址字段 %q 必须被嵌套禁止表拦截（mihomo %s）",
					protocol, field, mihomoSnapshotVersion)
			}
		}
	}

	for _, path := range mihomoNestedAddressFieldSnapshot {
		idx := strings.LastIndex(path, ".")
		if idx < 0 || idx == len(path)-1 {
			t.Fatalf("嵌套字段快照路径 %q 格式错误", path)
		}
		leaf := path[idx+1:]
		if !nodeNestedKeyForbidden(leaf) {
			t.Fatalf("快照里的嵌套地址字段 %q（%s）必须被嵌套禁止表拦截（mihomo %s）",
				leaf, path, mihomoSnapshotVersion)
		}
	}
}

// TestMihomoSnapshotECHOptsKeepsEnableAndConfig 确认 ech-opts 没有被整块封禁：
// 只拦截 query-server-name（会让探针去解析攻击者指定域名），
// enable/config 不联网因此必须继续放行（ech.go:24-31 只在本地解 base64）。
func TestMihomoSnapshotECHOptsKeepsEnableAndConfig(t *testing.T) {
	for _, field := range []string{"enable", "config"} {
		if nodeNestedKeyForbidden(field) {
			t.Fatalf("ech-opts.%s 不联网，不应被封禁（mihomo %s）", field, mihomoSnapshotVersion)
		}
	}
	if !nodeNestedKeyForbidden("query-server-name") {
		t.Fatal("ech-opts.query-server-name 会让探针解析攻击者指定的域名，必须封禁")
	}
}

// TestMihomoSnapshotTLSHostKeysExist 交叉校验 nodeTLSHostKey 返回的 SNI 字段名
// 确实存在于对应协议的 mihomo option 里：钉死 server 后补的 SNI 字段名一旦写错，
// mihomo 会忽略它并按 IP 做 TLS 握手，节点直接不可用。
func TestMihomoSnapshotTLSHostKeysExist(t *testing.T) {
	for protocol, fields := range mihomoOptionFieldSnapshot {
		key := nodeTLSHostKey(protocol)
		if key == "" {
			continue
		}
		if !snapshotHasField(fields, key) {
			t.Fatalf("协议 %q 的 SNI 字段 %q 不在 mihomo 字段快照里（mihomo %s）：%s",
				protocol, key, mihomoSnapshotVersion, fields)
		}
	}
}

// snapshotHasField 判断空格分隔的字段快照里是否包含指定字段（区分大小写，与 proxy tag 一致）。
func snapshotHasField(fields, want string) bool {
	for _, field := range strings.Fields(fields) {
		if field == want {
			return true
		}
	}
	return false
}

// isMihomoAddressSemanticField 判断字段名是否属于“目标/查询地址”语义。
func isMihomoAddressSemanticField(field string) bool {
	for _, known := range mihomoAddressSemanticFields {
		if field == known {
			return true
		}
	}
	return false
}
