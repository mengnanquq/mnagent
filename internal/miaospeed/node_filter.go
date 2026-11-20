package miaospeed

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
	"unicode"

	yaml2 "gopkg.in/yaml.v2"
	yaml3 "gopkg.in/yaml.v3"

	"github.com/mengnanquq/mnagent/internal/probe"
)

// 节点服务器地址同样受内网拦截约束：否则用户可以提交指向 127.0.0.1、10.x 或云元数据地址的节点，
// 借测速结果探测探针主机所在内网的端口开放情况。

const (
	nodeResolveTimeout     = 3 * time.Second
	nodeResolveConcurrency = 16

	// maxNodePayloadBytes 限制单个节点 payload 的大小。语义闸门要对 payload 做
	// yaml.v3 结构解析 + yaml.v2 解码，64KB 远大于任何正常节点配置，
	// 同时把超大/恶意 payload 的解析开销钉死在上限内（超出直接剔除）。
	maxNodePayloadBytes = 64 << 10

	// maxNodePayloadDepth 限制嵌套映射/序列的深度，避免深层嵌套导致递归失控。
	maxNodePayloadDepth = 32

	// nodeDropLogSamples 是剔除明细日志的条数上限。
	nodeDropLogSamples = 3

	// nodeDropLogNameRunes 是日志里节点名的最大字符数。
	nodeDropLogNameRunes = 48
)

// lookupNodeIPs 解析节点服务器地址（测试中可替换）。
var lookupNodeIPs = func(ctx context.Context, host string) ([]net.IP, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, a.IP)
	}
	return ips, nil
}

// maxNodeFilterCandidates 是进入语义闸门（含 DNS 解析）的候选节点上限。
// 过滤发生在 selectJobNodes 截断之前，如果直接对所有节点做过滤，攻击者可以用大量
// 唯一主机名把一次任务的 DNS 查询次数放大到任意量级。因此先按上限截断候选节点，
// 再做过滤、再交给 selectJobNodes：上限取 maxMiaospeedNodes 的 3 倍，为闸门剔除
// 留出缓冲，保证正常订阅在过滤后仍能选满 maxMiaospeedNodes 个节点；超出上限的
// 节点按剔除处理并计入 drop 统计（fail-closed，绝不把未过滤的节点下发给 miaospeed）。
// 用 var 而非常量：测试可以在更小的上限下验证解析次数与截断语义。
var maxNodeFilterCandidates = maxMiaospeedNodes * 3

// nodeHostResult 记录单个主机名的校验结果：是否被拦截；域名主机还会带上已通过校验的 IP，
// 供 filterBlockedNodes 把 payload 中的 server 钉死到该 IP（防止 DNS 重绑定绕过校验）。
type nodeHostResult struct {
	blocked bool
	ip      net.IP
}

// nodeFilterPolicy 是语义闸门的开关。-allow-private-probes 只关闭“IP 是否落在
// 私网/保留段”这一步检查，协议白名单、payload 结构与禁止字段、钉死 server、
// 钉死后的语义回验全部照常执行：私网地址同样必须被钉死并校验，
// 否则“允许私网”就会变成绕过整个闸门的开关。
type nodeFilterPolicy struct {
	// AllowPrivate 允许服务器地址落在私网/保留段（仅跳过 IP 段判定）。
	AllowPrivate bool
}

// filterBlockedNodes 按默认策略（禁止私网/保留/元数据地址）过滤节点。
func filterBlockedNodes(ctx context.Context, nodes []MiaospeedNode, log Logger) ([]MiaospeedNode, int) {
	return filterBlockedNodesWithPolicy(ctx, nodes, nodeFilterPolicy{}, log)
}

// filterBlockedNodesWithPolicy 剔除服务器地址指向私有、保留或云元数据地址的节点，
// 返回保留的节点与剔除数量。
// 域名解析失败时按 fail-closed 处理：无法确认目标是否安全就直接剔除，绝不把未经校验的域名
// 交给 miaospeed 去解析连接（否则 DNS 抖动或解析差异都可能绕过 SSRF 守卫）。
// 无法识别服务器地址的节点同样一律剔除，防止借畸形配置绕过检查。
//
// 候选节点数同样有上限（maxNodeFilterCandidates）：超出部分不参与 DNS 解析，
// 直接计入剔除数量，避免订阅里的海量唯一主机名放大探针的 DNS 查询。
//
// 保留下来的域名节点会把 payload 的 server 字段改写为本次校验过的 IP：miaospeed 连接时
// 只按 payload 解析目标，若继续下发原始域名，miaospeed 的二次解析就可能拿到与校验时不同的
// 地址（DNS 重绑定）。改写同时会把原域名补到 SNI/Host 字段，保证 TLS/REALITY 正常。
// 剔除原因会通过 log 以 warn 级别输出（最多 3 条明细 + 按原因分类的计数），
// 便于定位“订阅里哪些节点被拦了、为什么被拦”；日志只输出静态原因分类和截断后的
// 节点名，绝不输出 payload 内容（payload 里有密码）。
func filterBlockedNodesWithPolicy(ctx context.Context, nodes []MiaospeedNode, policy nodeFilterPolicy, log Logger) ([]MiaospeedNode, int) {
	stats := &nodeDropStats{}
	// 先截断候选节点再收集主机名：解析扇出的规模只取决于 candidates，
	// 与订阅里到底塞了多少节点无关。
	candidates := nodes
	if len(candidates) > maxNodeFilterCandidates {
		for _, n := range candidates[maxNodeFilterCandidates:] {
			stats.record(n, "候选节点数超过单次安全检查上限")
		}
		candidates = candidates[:maxNodeFilterCandidates]
	}

	hostSet := make(map[string]bool)
	for _, n := range candidates {
		h := normalizeNodeHost(n.Server)
		if h != "" {
			hostSet[h] = false
		}
	}
	// 先固定待查列表再并发写入 map：直接在 range 期间写 map 会与已启动的解析协程并发写同一张 map。
	hosts := make([]string, 0, len(hostSet))
	for h := range hostSet {
		hosts = append(hosts, h)
	}

	var mu sync.Mutex
	// 先同步处理字面 IP，再并发解析域名：所有 map 写入都必须持锁，
	// 否则主协程与解析协程会同时写同一张 map（-race 会直接报错）。
	results := make(map[string]nodeHostResult, len(hosts))
	pending := make([]string, 0, len(hosts))
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			// 字面 IP 也要记录已校验地址：payload 可能被构造成指向另一个地址，
			// 必须同样钉死到本次校验过的 IP，不能因为 Server 是字面 IP 就放行原 payload。
			// AllowPrivate 只跳过 IP 段判定，钉死与后续语义回验照常执行。
			results[h] = nodeHostResult{blocked: !policy.AllowPrivate && probe.IsBlockedProbeIP(ip), ip: ip}
			continue
		}
		pending = append(pending, h)
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, nodeResolveConcurrency)
	for _, h := range pending {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			rctx, cancel := context.WithTimeout(ctx, nodeResolveTimeout)
			defer cancel()
			ips, err := lookupNodeIPs(rctx, h)
			// 解析失败或没有返回任何地址：无法验证安全性，按 fail-closed 剔除。
			res := nodeHostResult{blocked: err != nil || len(ips) == 0}
			if !res.blocked && !policy.AllowPrivate {
				for _, ip := range ips {
					if probe.IsBlockedProbeIP(ip) {
						res.blocked = true
						break
					}
				}
			}
			if !res.blocked {
				res.ip = pickNodeIP(ips)
			}
			mu.Lock()
			results[h] = res
			mu.Unlock()
		}(h)
	}
	wg.Wait()

	// AllowPrivate 只是关闭 IP 段判定，解析失败的原因描述要相应区分，
	// 避免日志把“允许私网”的节点说成“指向私有地址”。
	addressReason := "服务器地址指向私有/保留/元数据地址，或域名无法解析"
	if policy.AllowPrivate {
		addressReason = "服务器地址无法解析"
	}

	kept := make([]MiaospeedNode, 0, len(candidates))
	for _, n := range candidates {
		h := normalizeNodeHost(n.Server)
		res, ok := results[h]
		if h == "" {
			stats.record(n, "节点缺少服务器地址")
			continue
		}
		if !ok || res.blocked {
			stats.record(n, addressReason)
			continue
		}
		// 无论 Server 是域名还是字面 IP，都无条件把 payload 顶层 server 钉死为
		// 本次校验过的地址：否则可以构造“校验的是诱饵、miaospeed 实际连另一个地址”的节点。
		pinned, err := pinNodeServerIP(n, res.ip)
		if err != nil {
			stats.record(n, err.Error())
			continue
		}
		n = pinned
		// 钉死后再做一次独立的语义回验：以 miaospeed 同版本 YAML 的解码结果为准，
		// 并拒绝不在白名单内的协议与会覆盖拨号地址的字段。任何失败都剔除节点。
		if err := verifyPinnedNodePayload(n.Payload, res.ip); err != nil {
			stats.record(n, err.Error())
			continue
		}
		kept = append(kept, n)
	}
	stats.warn(log)
	return kept, stats.total
}

// nodeDropStats 汇总一次节点过滤的剔除原因。原因文本一律使用静态分类，
// 绝不拼接 payload 内容（节点配置里含密码）；节点名只做去控制字符 + 截断。
type nodeDropStats struct {
	total   int
	order   []string
	counts  map[string]int
	samples []nodeDropSample
}

type nodeDropSample struct {
	name   string
	reason string
}

func (s *nodeDropStats) record(node MiaospeedNode, reason string) {
	s.total++
	if s.counts == nil {
		s.counts = make(map[string]int, 4)
	}
	if _, ok := s.counts[reason]; !ok {
		s.order = append(s.order, reason)
	}
	s.counts[reason]++
	if len(s.samples) < nodeDropLogSamples {
		s.samples = append(s.samples, nodeDropSample{name: sanitizeNodeNameForLog(node.Name), reason: reason})
	}
}

// warn 输出最多 3 条“节点名 + 原因”明细和按原因分类的计数。
func (s *nodeDropStats) warn(log Logger) {
	if log == nil || s.total == 0 {
		return
	}
	for i, sample := range s.samples {
		log.Warn("节点被安全闸门剔除", "index", i+1, "node", sample.name, "reason", sample.reason)
	}
	parts := make([]string, 0, len(s.order))
	for _, reason := range s.order {
		parts = append(parts, fmt.Sprintf("%s=%d", reason, s.counts[reason]))
	}
	log.Warn("节点剔除原因统计", "total", s.total, "counts", strings.Join(parts, "; "))
}

// sanitizeNodeNameForLog 去掉节点名里的控制字符与不可见格式字符并截断长度，
// 防止日志注入与超长行。
// Cf（格式字符，如 U+202E RIGHT-TO-LEFT OVERRIDE、U+200B ZERO WIDTH SPACE）能翻转
// 终端里的显示方向或隐藏内容，Co（私用区字符）在不同字体/终端下可能与其它字符混淆，
// 两者都不适合出现在日志里，一并去掉。
func sanitizeNodeNameForLog(name string) string {
	cleaned := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Co) {
			return -1
		}
		return r
	}, name)
	cleaned = strings.TrimSpace(cleaned)
	runes := []rune(cleaned)
	if len(runes) > nodeDropLogNameRunes {
		cleaned = string(runes[:nodeDropLogNameRunes]) + "..."
	}
	if cleaned == "" {
		cleaned = "(无名)"
	}
	return cleaned
}

// pickNodeIP 从已通过校验的解析结果中选一个用于固定连接：优先 IPv4，
// 避免探针主机 IPv6 出口不通时节点直接失联（miaospeed 收到字面 IP 后不再做协议回退）。
func pickNodeIP(ips []net.IP) net.IP {
	var fallback net.IP
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			return ip
		}
		if fallback == nil {
			fallback = ip
		}
	}
	return fallback
}

// nodeTLSHostKey 返回该协议在 Clash 风格 payload 中用于指定 TLS 主机名（SNI）的字段名。
// 与 parser.go 各协议生成 payload 时使用的字段保持一致；空字符串表示协议没有 SNI 概念。
// 只列 MiaospeedNode.Protocol 实际会取的值：解析阶段已把 hy/hy2 归一成
// hysteria/hysteria2（parser.go 的 parseProxyURI 与 convertSingBoxOutbound），
// 所以这里不再保留 hy/hy2 分支。
func nodeTLSHostKey(protocol string) string {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "vmess", "vless":
		return "servername"
	// http：mihomo adapter/outbound/http.go:151-154 在 sni 为空时以 server 作为 TLS ServerName，
	// 钉死 IP 后必须补回原域名，否则 HTTPS 代理节点会以 IP 做证书校验而失败。
	case "trojan", "hysteria", "hysteria2", "tuic", "anytls", "http":
		return "sni"
	}
	// socks5：mihomo socks5.go:180 直接用 server 作为 TLS ServerName 且无 sni 选项，
	// 钉死 IP 后 socks5+tls（未开 skip-cert-verify）节点会证书校验失败，属已知取舍。
	return ""
}

// nodeTLSHostKeys 返回该协议用来表达 TLS 主机名/SNI 的键。
// 只包含协议自己的键：ws-opts.headers.Host 只是 HTTP 伪装 Host，不是 TLS SNI，
// 不能因为它存在就跳过去补 SNI，否则钉死 IP 后会用 IP 做 TLS 握手而失败。
// mihomo 的 hysteria/hysteria2 没有 peer 选项，peer 不能当作已设置 SNI，
// 否则钉死 IP 后会漏补 sni，导致证书校验按 IP 进行而失败。
func nodeTLSHostKeys(protocol string) []string {
	key := nodeTLSHostKey(protocol)
	if key == "" {
		return nil
	}
	return []string{key}
}

// pinNodeServerIP 把节点 payload 中的 server 字段改写为已通过 SSRF 校验的 IP，
// 并（原 server 为域名且 payload 未显式设置该协议自己的 SNI 字段时）把原域名
// 补到该协议对应的 TLS 主机名字段，保证证书校验与 REALITY 仍按原域名进行。
// ws-opts.headers.Host 只是 HTTP 伪装 Host，不参与 SNI 判断。
//
// 只改写 payload：MiaospeedNode.Server 仍保留原始域名，供测速报告展示与地理信息查询。
// payload 结构无法可靠定位唯一的顶层 server 字段（重复键、非 YAML 映射等）时返回错误，
// 由调用方按 fail-closed 剔除该节点——绝不能出现“校验的是 A，实际连的是 B”。
func pinNodeServerIP(n MiaospeedNode, ip net.IP) (MiaospeedNode, error) {
	if ip == nil {
		return MiaospeedNode{}, errors.New("缺少可用于固定的服务器地址")
	}
	// 先在原始 payload 上做一次 YAML 语义检查（重复键、合并键、锚点/别名、非 ASCII 键
	// 等文本扫描无法可靠处理的写法，即使后续改写会覆盖 server 行也按 fail-closed 拒绝）。
	// 这次结构解析结果同时用于判断是否需要补 SNI，避免为一个布尔判断再解一遍 yaml.v2。
	rootKeys, err := parseNodePayloadRoot(n.Payload)
	if err != nil {
		return MiaospeedNode{}, err
	}
	originalHost := normalizeNodeHost(n.Server)
	// payload 的 server 字段只放主机（端口由独立的 port 字段承载）。
	payload, flow, indent, err := rewritePayloadServer(n.Payload, ip.String())
	if err != nil {
		return MiaospeedNode{}, err
	}
	// 字面 IP 没有原域名可用作 SNI；此时不补任何 TLS 主机名字段。
	if key := nodeTLSHostKey(n.Protocol); key != "" && originalHost != "" && net.ParseIP(originalHost) == nil &&
		!payloadKeysHaveTLSHostKey(rootKeys, n.Protocol) {
		if flow {
			payload = insertFlowField(payload, key, originalHost)
		} else {
			payload = addBlockField(payload, indent, key, originalHost)
		}
	}
	n.Payload = payload
	return n, nil
}

// nodePayloadView 是单个节点 payload 的最终解析结果：
//   - keys 是根映射键按 mihomo 语义归一化后的视图（归一化键 -> 原始键）；
//   - decoded 是用与 miaospeed 相同版本（gopkg.in/yaml.v2）解码出的根映射。
//
// 每个节点最多跑 2 次 yaml.v3 结构解析（改写前 / 改写后各一次）和 1 次 yaml.v2
// 解码（改写后的 payload），而不是每项检查各解析一遍，避免被用来放大 CPU/内存开销。
type nodePayloadView struct {
	keys    map[string]string
	decoded map[string]interface{}
}

// parseNodePayloadRoot 只做 yaml.v3 结构解析与归一化键校验（不解码 yaml.v2）。
// 改写前用它判断 payload 是否已有 SNI 字段，省掉一次 yaml.v2 解码。
func parseNodePayloadRoot(payload string) (map[string]string, error) {
	if len(payload) > maxNodePayloadBytes {
		return nil, fmt.Errorf("节点配置超过单节点大小上限（%d 字节）", maxNodePayloadBytes)
	}
	mapping, err := parsePayloadRootMapping(payload)
	if err != nil {
		return nil, err
	}
	return validatePayloadRootStructure(mapping)
}

// parseNodePayloadView 解析并校验单个节点 payload 的根映射语义。
func parseNodePayloadView(payload string) (*nodePayloadView, error) {
	keys, err := parseNodePayloadRoot(payload)
	if err != nil {
		return nil, err
	}
	var decoded map[string]interface{}
	if err := yaml2.Unmarshal([]byte(payload), &decoded); err != nil {
		// 不要回显底层错误：yaml.v2 的类型错误会带出 payload 里的值（可能含密码）。
		return nil, errors.New("节点配置无法按 YAML 映射解码")
	}
	if decoded == nil {
		return nil, errors.New("节点配置不是 YAML 映射")
	}
	return &nodePayloadView{keys: keys, decoded: decoded}, nil
}

// payloadKeysHaveTLSHostKey 判断 payload 的顶层是否已经显式设置了该协议的 SNI 字段。
// 用归一化键判断（mihomo 解码字段名时会做 "_"→"-" 与 EqualFold），
// 否则 `SNI:` 这种写法会让闸门以为没设置而再补一个 `sni`，
// 形成两个归一化后相同的键（mihomo 取哪个由 map 遍历顺序决定）。
func payloadKeysHaveTLSHostKey(keys map[string]string, protocol string) bool {
	for _, key := range nodeTLSHostKeys(protocol) {
		if _, ok := keys[normalizePayloadKey(key)]; ok {
			return true
		}
	}
	return false
}

// verifyPinnedNodePayload 是节点下发给 miaospeed 前的最终语义闸门：
//   - 用 yaml.v3 复核改写后的根映射结构（归一化键唯一、server 原文必须是小写 server）；
//   - 用与 miaospeed 相同的 yaml.v2 版本解码，确认顶层 server 正是本次校验并钉死的地址；
//   - 协议必须命中白名单，且顶层/嵌套都不得出现会覆盖拨号地址的字段。
//
// 任一检查失败都返回错误，由调用方剔除节点（fail-closed）。
// 这里返回的错误文本必须是静态中文描述，不能拼接 payload 内容：这些文本会进入日志，
// 而节点配置里有密码等敏感信息。
func verifyPinnedNodePayload(payload string, pinned net.IP) error {
	if pinned == nil {
		return errors.New("缺少已校验的服务器地址")
	}
	view, err := parseNodePayloadView(payload)
	if err != nil {
		return err
	}
	if err := checkNodeProtocolAndFields(view); err != nil {
		return err
	}
	serverKey, ok := view.keys["server"]
	if !ok {
		return errors.New("节点配置缺少顶层 server 字段")
	}
	serverValue, ok := view.decoded[serverKey]
	if !ok {
		return errors.New("节点配置缺少顶层 server 字段")
	}
	// 改写后的 server 一定是带引号的字符串；这里要求严格相等，
	// 避免 `!!binary`/数字等非字符串值在 fmt.Sprint 下凑出同样的文本。
	text, ok := serverValue.(string)
	if !ok || text != pinned.String() {
		return errors.New("节点配置的 server 与已校验地址不一致")
	}
	return nil
}

// allowedNodeProtocols 是“拨号目标唯一来自顶层 server+port”的协议白名单。
// 逐个对照 mihomo v1.19.33-x365-miu.2（github.com/AirportR/mihomo）的
// adapter/outbound/*.go 与 adapter/parser.go:18 的 ParseProxy 分支：
//
//	ss        shadowsocks.go:43-56   addr = JoinHostPort(Server, Port)（shadowsocks.go:302）；
//	                                 plugin/plugin-opts 只做本地混淆（obfs/v2ray/gost/shadow-tls/restls/jls/kcptun），不另拨地址
//	ssr       shadowsocksr.go:28-40  同上（shadowsocksr.go:116，DialContext 用 ssr.addr）
//	socks5    socks5.go:30-44        NewSocks5 用 JoinHostPort(Server, Port)（socks5.go:195），tls/username 不影响目标
//	http      http.go:28-43          NewHttp 同上（http.go:174），headers 只用于 CONNECT 头
//	vmess     vmess.go:53-89         全部传输的拨号函数都用 v.addr（vmess.go:390/402/586/602）；
//	                                 mekya 的 url 只作为连接内的 HTTP 请求目标（transport/mekya/client.go:240），不改变拨号目标
//	vless     vless.go:58-91         同上（vless.go:348/567/671）；xhttp download-settings 的 server 会另拨地址，
//	                                 已由嵌套字段拦截（vless.go:137/724-726）
//	trojan    trojan.go:45-69        addr = JoinHostPort(Server, Port)（trojan.go:284）
//	snell     snell.go:32-43         addr = JoinHostPort(Server, Port)（snell.go:168），obfs-opts 只做混淆
//	hysteria  hysteria.go:101-124    addr = JoinHostPort(Server, Port)（hysteria.go:148）；ports 只做端口跳跃：
//	                                 解析时只取端口，IP 仍来自已钉死的 server（transport/hysteria/conns/udp/hop.go:62-82）
//	hysteria2 hysteria2.go:39-73     同上（hysteria2.go:130）；ports 用 utils.NewUnsignedRanges[uint16] 解析成纯端口
//	                                 （hysteria2.go:239-263）后与 ServerAddress（hysteria2.go:222）组合；
//	                                 realm-opts 的 server-url/stun-servers 会访问任意地址，已由嵌套字段拦截（hysteria2.go:77/80/286）
//	anytls    anytls.go:27-51        addr = JoinHostPort(Server, Port)（anytls.go:95）
//	tuic      tuic.go:34-70          addr = JoinHostPort(Server, Port)（tuic.go:130）；顶层 ip 会覆盖拨号地址，
//	                                 已由禁止字段拦截（tuic.go:42）
//
// wireguard/tailscale/easytier/zerotier/masque/ssh/openvpn/mieru/gost-relay/shadowquic 等
// 协议的拨号地址可能来自 server 以外的字段（ip/ipv6/peers/control-url/endpoint...），
// 或无法逐个核实其全部子传输，一律不放行。
var allowedNodeProtocols = map[string]struct{}{
	"ss":        {},
	"ssr":       {},
	"socks5":    {},
	"http":      {},
	"vmess":     {},
	"vless":     {},
	"trojan":    {},
	"snell":     {},
	"hysteria":  {},
	"hysteria2": {},
	"anytls":    {},
	"tuic":      {},
}

// nodeForbiddenAddressKeys 是所有会改变拨号/查询目标地址的字段名（按 mihomo 的
// "_"→"-" + EqualFold 语义比较）。顶层与任意嵌套深度统一使用这一份表，
// 避免两套列表逐渐漂移（顶层漏掉的字段只要换个层级就能绕过）：
//   - ip：tuic.go:42 的 Ip 会覆盖拨号地址；
//   - ipv6/peers：wireguard.go:77/88（L3 配置与自带 server 的 peer）；
//   - control-url：tailscale.go:59 的控制端地址；
//   - endpoint：同类“自带地址”字段的通用防御；
//   - dialer-proxy：base.go:199 会把拨号改走另一个出站；
//   - server-url / stun-servers：hysteria2 realm-opts（hysteria2.go:77/80）：realm 用独立
//     HTTP 客户端访问该 URL、向 STUN 服务器发包；
//   - url：vmess mekya-opts.url（vmess.go:118）：当前实现仍以 v.addr 拨号（vmess.go:586），
//     但它是外部 URL，按保守策略一并拒绝；顶层同名键同样拒绝；
//   - query-server-name：ech-opts.query-server-name（adapter/outbound/ech.go:33-38）
//     会覆盖 ECH 的 HTTPS 记录查询域名，直接交给 resolver.ProxyServerHostResolver 解析，
//     因此能让探针主机用 SystemResolver 去查攻击者指定的任意域名。
//     ech-opts 的其余字段不联网：enable 只是开关，config 是本地 base64（ech.go:24-31），
//     解码成 ECHConfigList 后不再访问网络，所以没有封禁整个 ech-opts：
//     只带 enable/config 的节点（携带本地 ECH 配置）仍然放行。
//     残余风险：enable 且没有 config 时会按节点自身的 serverName（payload 里的
//     servername/sni）去查 ECH 记录，相当于对该域名做一次 DNS 查询；它只能指向节点
//     自己的 TLS 名字、且本闸门本来就要解析节点域名，故不额外封禁。
//
// 注意 hysteria/hysteria2 的顶层 ports 不在此列：它只换端口、主机仍是 server
// （hysteria2.go:239 用 utils.NewUnsignedRanges[uint16] 解析，无法携带主机）。
var nodeForbiddenAddressKeys = []string{
	"ip", "ipv6", "peers", "control-url", "endpoint",
	"server-url", "stun-servers", "query-server-name", "url", "dialer-proxy",
}

// nodeForbiddenNestedKeys 是任意深度都不允许出现的地址类字段名：
// 公共地址字段表 + server。顶层那唯一一个 server 就是允许的拨号目标
// （由 validatePayloadRootStructure 保证恰好一个且为小写原文），嵌套 server 则在任何层级
// 都可能另拨地址：vless xhttp-opts.download-settings.server（vless.go:137，
// vless.go:724-726 用它生成 downloadAddr 并直接走 v.dialer 拨号）、wireguard peers[].server。
var nodeForbiddenNestedKeys = append(append([]string{}, nodeForbiddenAddressKeys...), "server")

// nodeForbiddenTopLevelKeys 是顶层禁止表（归一化键）：与嵌套表同源，只少一个 server。
var nodeForbiddenTopLevelKeys = func() map[string]struct{} {
	set := make(map[string]struct{}, len(nodeForbiddenAddressKeys))
	for _, field := range nodeForbiddenAddressKeys {
		set[normalizePayloadKey(field)] = struct{}{}
	}
	return set
}()

// checkNodeProtocolAndFields 按 mihomo 的解码语义检查协议白名单与地址覆盖字段。
func checkNodeProtocolAndFields(view *nodePayloadView) error {
	protocol, err := view.protocol()
	if err != nil {
		return err
	}
	if _, ok := allowedNodeProtocols[protocol]; !ok {
		return errors.New("节点协议不在允许的白名单中")
	}
	for norm := range view.keys {
		if _, bad := nodeForbiddenTopLevelKeys[norm]; bad {
			return errors.New("节点配置的顶层字段会覆盖拨号地址")
		}
	}
	for _, value := range view.decoded {
		if err := checkNestedNodeFields(value, 1); err != nil {
			return err
		}
	}
	return nil
}

// protocol 返回 mihomo 实际看到的协议类型。adapter/parser.go:18 用 mapping["type"]
// 精确查表，键必须是原文 `type`；值必须是非空字符串。归一化（去空白 + 小写）后
// 再查白名单，避免大小写差异把已在白名单里的协议误拦。
func (v *nodePayloadView) protocol() (string, error) {
	rawKey, ok := v.keys["type"]
	if !ok {
		return "", errors.New("节点配置缺少顶层 type 字段")
	}
	if rawKey != "type" {
		return "", errors.New(`节点配置的 type 键必须是小写的 "type"`)
	}
	raw, ok := v.decoded[rawKey]
	if !ok {
		return "", errors.New("节点配置缺少顶层 type 字段")
	}
	text, ok := raw.(string)
	if !ok {
		return "", errors.New("节点配置的 type 不是字符串")
	}
	protocol := strings.ToLower(strings.TrimSpace(text))
	if protocol == "" {
		return "", errors.New("节点配置的 type 为空")
	}
	return protocol, nil
}

// checkNestedNodeFields 递归检查嵌套映射/序列里是否出现地址类字段。
// 用 mihomoKeyEqual 而不是小写比较：EqualFold 的 Unicode 折叠同样会把
// `ſerver`（U+017F）折成 `server`，mihomo 解码嵌套结构体时也会命中该字段。
func checkNestedNodeFields(value interface{}, depth int) error {
	if depth > maxNodePayloadDepth {
		return errors.New("节点配置的 YAML 嵌套层级过深")
	}
	switch typed := value.(type) {
	case map[interface{}]interface{}:
		for key, child := range typed {
			if name, ok := key.(string); ok && nodeNestedKeyForbidden(name) {
				return errors.New("节点配置的嵌套字段会改变拨号目标地址")
			}
			if err := checkNestedNodeFields(child, depth+1); err != nil {
				return err
			}
		}
	case map[string]interface{}:
		for key, child := range typed {
			if nodeNestedKeyForbidden(key) {
				return errors.New("节点配置的嵌套字段会改变拨号目标地址")
			}
			if err := checkNestedNodeFields(child, depth+1); err != nil {
				return err
			}
		}
	case []interface{}:
		for _, child := range typed {
			if err := checkNestedNodeFields(child, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func nodeNestedKeyForbidden(key string) bool {
	for _, field := range nodeForbiddenNestedKeys {
		if mihomoKeyEqual(key, field) {
			return true
		}
	}
	return false
}

// normalizePayloadKey 复刻 mihomo common/structure 解码器的键归一化：
// DefaultKeyReplacer（structure.go:22）先把 "_" 换成 "-"，随后用 strings.EqualFold
// 做大小写不敏感匹配（structure.go:498-526）。根映射键已限定为 ASCII，
// 因此 strings.ToLower 与 EqualFold 等价。
func normalizePayloadKey(key string) string {
	return strings.ToLower(strings.ReplaceAll(key, "_", "-"))
}

// mihomoKeyReplacer 与 structure.DefaultKeyReplacer 一致。
var mihomoKeyReplacer = strings.NewReplacer("_", "-")

// mihomoKeyEqual 按 mihomo structure.Decoder 的语义比较键与字段名。
func mihomoKeyEqual(key, field string) bool {
	return strings.EqualFold(mihomoKeyReplacer.Replace(key), mihomoKeyReplacer.Replace(field))
}

// isASCIIPayloadKey 判断键是否只含可打印 ASCII 字符。非 ASCII 字符（ſ、K、全角、
// 零宽等）在 EqualFold 下可能匹配到敏感字段名，而文本改写只认裸 `server:`，
// 两者不一致就会留下“校验 A、实际连 B”的空隙，因此一律剔除；
// 控制字符也不允许出现在键里（会造成日志/展示注入）。
func isASCIIPayloadKey(key string) bool {
	if key == "" {
		return false
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		if c < 0x20 || c == 0x7f || c >= 0x80 {
			return false
		}
	}
	return true
}

// validatePayloadRootStructure 检查 payload 的根 YAML 映射结构，并返回
// “归一化键 -> 原始键”的视图：单文档映射、无合并键、根映射的键与值不使用锚点/别名、
// 顶层键必须是纯 ASCII 字符串且（归一化后）唯一，还必须恰好有一个原文就是小写
// `server` 的键。
//
// 为什么按归一化键去重：mihomo 的 structure.Decoder 先用原始键名精确查表，
// 未命中时再按 DefaultKeyReplacer + strings.EqualFold 逐键匹配，所以 `IP`/`Ip`/`iP`、
// `SERVER`、`Peers` 等写法都会命中 ip/server/peers 字段；yaml.v2 又允许重复键
// （后写覆盖前写），只按原文去重会被绕过。
// 为什么只接受 ASCII 键：EqualFold 的 Unicode 折叠会让 `ſerver` 之类的键匹配到
// ASCII 字段名，而文本改写只认裸 `server:`，两者不一致就会留下空隙。
func validatePayloadRootStructure(mapping *yaml3.Node) (map[string]string, error) {
	if mapping.Anchor != "" || mapping.Alias != nil {
		return nil, errors.New("节点配置根映射不能使用 YAML 锚点或别名")
	}
	if len(mapping.Content)%2 != 0 {
		return nil, errors.New("节点配置的 YAML 映射结构不完整")
	}

	keys := make(map[string]string, len(mapping.Content)/2)
	for i := 0; i < len(mapping.Content); i += 2 {
		key := mapping.Content[i]
		value := mapping.Content[i+1]
		if key == nil || value == nil {
			return nil, errors.New("节点配置的 YAML 映射包含空节点")
		}
		if key.Kind != yaml3.ScalarNode {
			return nil, errors.New("节点配置的顶层键必须是字符串标量")
		}
		// 只接受字符串标签。yaml.v2 会把 !!binary 键解码成解码后的字节串
		// （`!!binary c2VydmVy` 就是 "server"），`<<` 则是 !!merge；
		// 只比较 Node.Value 会漏掉这两类写法。
		if tag := key.Tag; tag != "" && tag != "!!str" {
			return nil, errors.New("节点配置的顶层键只能使用字符串标签")
		}
		if err := rejectYAMLAnchorAlias(key, true); err != nil {
			return nil, err
		}
		if err := rejectYAMLAnchorAlias(value, false); err != nil {
			return nil, err
		}
		if !isASCIIPayloadKey(key.Value) {
			return nil, errors.New("节点配置的顶层键只能使用可打印 ASCII 字符")
		}
		norm := normalizePayloadKey(key.Value)
		if _, exists := keys[norm]; exists {
			return nil, errors.New("节点配置存在规范化后重复的顶层键")
		}
		keys[norm] = key.Value
		if norm != "server" {
			continue
		}
		// 文本改写只覆盖裸 `server:` 行；原文不是小写 server（例如 SERVER、
		// server_）时，改写结果与 mihomo 的解码结果会错位，直接剔除。
		if key.Value != "server" {
			return nil, errors.New(`节点配置的 server 键必须是小写的 "server"`)
		}
		if value.Kind != yaml3.ScalarNode {
			return nil, errors.New("节点配置的顶层 server 必须是标量")
		}
	}
	if _, ok := keys["server"]; !ok {
		return nil, errors.New("节点配置必须恰好包含一个顶层 server 字段")
	}
	return keys, nil
}

// parsePayloadRootMapping 解析单文档 YAML 并返回根映射节点；多文档、空文档、
// 根不是映射（例如序列）或尾随第二个文档都返回错误。
// 错误文本保持静态：底层 YAML 错误可能拼出部分 payload 内容，而这些文本会进日志。
func parsePayloadRootMapping(payload string) (*yaml3.Node, error) {
	decoder := yaml3.NewDecoder(strings.NewReader(payload))
	var document yaml3.Node
	if err := decoder.Decode(&document); err != nil {
		return nil, errors.New("节点配置不是合法的 YAML")
	}
	var extra yaml3.Node
	switch err := decoder.Decode(&extra); {
	case err == nil:
		return nil, errors.New("节点配置包含多个 YAML 文档")
	case !errors.Is(err, io.EOF):
		return nil, errors.New("节点配置不是合法的 YAML")
	}
	if document.Kind != yaml3.DocumentNode || len(document.Content) != 1 || document.Content[0].Kind != yaml3.MappingNode {
		return nil, errors.New("节点配置根必须是单个 YAML 映射")
	}
	return document.Content[0], nil
}

// rejectYAMLAnchorAlias 拒绝根映射键/值上的锚点、别名与合并键。
func rejectYAMLAnchorAlias(node *yaml3.Node, isKey bool) error {
	if node.Anchor != "" {
		return errors.New("节点配置根映射的键或值不能使用 YAML 锚点")
	}
	if node.Alias != nil {
		return errors.New("节点配置根映射的键或值不能使用 YAML 别名")
	}
	if node.Tag == "!!merge" || (isKey && node.Value == "<<") {
		return errors.New("节点配置根映射不能使用 << 合并键")
	}
	return nil
}

// payloadIndent 返回 payload 首个有效行（非空、非注释）的缩进宽度，用于在块式映射中
// 定位与追加顶层字段；流式映射（以 '{' 开头）返回 -1。
func payloadIndent(payload string) int {
	for _, line := range strings.Split(payload, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(line), "{") {
			return -1
		}
		return len(line) - len(strings.TrimLeft(line, " \t"))
	}
	return -1
}

// rewritePayloadServer 把 payload 中的 server 字段值替换为 newServer，
// 返回改写后的 payload、是否为流式映射以及块式映射的顶层缩进。
// 无法唯一定位 server 字段时返回错误（fail-closed）。
func rewritePayloadServer(payload, newServer string) (string, bool, int, error) {
	indent := payloadIndent(payload)
	quoted := quoteYAML(newServer)
	if indent < 0 {
		rewritten, ok, err := replaceFlowField(payload, "server", quoted)
		if err != nil {
			return "", true, indent, err
		}
		if !ok {
			return "", true, indent, fmt.Errorf("节点配置中未找到唯一的 server 字段")
		}
		return rewritten, true, indent, nil
	}

	lines := strings.Split(payload, "\n")
	keyPrefix := strings.Repeat(" ", indent) + "server"
	target := -1
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if len(line)-len(strings.TrimLeft(line, " \t")) != indent {
			continue
		}
		if strings.HasPrefix(line, keyPrefix) && strings.HasPrefix(strings.TrimSpace(line[len(keyPrefix):]), ":") {
			if target != -1 {
				return "", false, indent, fmt.Errorf("节点配置中存在重复的 server 字段")
			}
			target = i
		}
	}
	if target == -1 {
		return "", false, indent, fmt.Errorf("节点配置中未找到唯一的 server 字段")
	}
	lines[target] = strings.Repeat(" ", indent) + "server: " + quoted
	return strings.Join(lines, "\n"), false, indent, nil
}

// addBlockField 在块式映射 payload 末尾追加一个顶层字段。
func addBlockField(payload string, indent int, key, value string) string {
	prefix := strings.Repeat(" ", indent)
	if !strings.HasSuffix(payload, "\n") {
		payload += "\n"
	}
	return payload + prefix + key + ": " + quoteYAML(value) + "\n"
}

// replaceFlowField 在流式映射（{k: v, ...}）中把指定键的值替换为 newValue。
// 重复键同样按 fail-closed 处理。
func replaceFlowField(payload, key, newValue string) (string, bool, error) {
	start, end := flowFieldValueSpan(payload, key)
	if start < 0 {
		return payload, false, nil
	}
	// 确认没有重复键：从已找到的键之后继续扫描。
	if second, _ := flowFieldValueSpan(payload[end:], key); second >= 0 {
		return payload, false, fmt.Errorf("节点配置中存在重复的 %s 字段", key)
	}
	return payload[:start] + newValue + payload[end:], true, nil
}

// insertFlowField 在流式映射的末尾（最后一个 '}' 之前）插入一个字段。
func insertFlowField(payload, key, value string) string {
	idx := strings.LastIndex(payload, "}")
	if idx < 0 {
		return payload
	}
	prev := strings.TrimSpace(payload[:idx])
	sep := ""
	if prev != "" && !strings.HasSuffix(prev, "{") && !strings.HasSuffix(prev, ",") {
		sep = ", "
	}
	return payload[:idx] + sep + key + ": " + quoteYAML(value) + payload[idx:]
}

// flowFieldValueSpan 返回流式映射顶层键对应值的起止下标；未找到返回 (-1, -1)。
// 嵌套映射里的同名键（如 ws-opts: { server: ... }）不会被当成顶层字段。
func flowFieldValueSpan(raw, key string) (int, int) {
	start, end, ok := topLevelFieldValueSpan(raw, key)
	if !ok {
		return -1, -1
	}
	return start, end
}

// topLevelFieldValueSpan 只在 YAML 映射的顶层查找 key 对应的值，
// 跳过引号内容与嵌套的 {}/[] 映射。raw 以 '{' 或 '[' 开头时顶层深度为 1。
// 返回值的起止下标（含引号/嵌套对象），未找到时 ok=false。
func topLevelFieldValueSpan(raw, key string) (int, int, bool) {
	if key == "" || raw == "" {
		return -1, -1, false
	}
	targetDepth := 0
	i := 0
	for i < len(raw) && unicode.IsSpace(rune(raw[i])) {
		i++
	}
	if i < len(raw) && (raw[i] == '{' || raw[i] == '[') {
		targetDepth = 1
	}

	depth := 0
	var quote byte
	escaped := false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if quote != 0 {
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' && quote == '"' {
				escaped = true
				continue
			}
			if c == quote {
				if quote == '\'' && i+1 < len(raw) && raw[i+1] == '\'' {
					i++
					continue
				}
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
			continue
		case '{', '[':
			depth++
			continue
		case '}', ']':
			if depth > 0 {
				depth--
			}
			continue
		}
		if depth != targetDepth {
			continue
		}
		if i > 0 {
			prev := raw[i-1]
			if prev != '{' && prev != '[' && prev != ',' && prev != ' ' && prev != '\t' && prev != '\n' {
				continue
			}
		}
		if !strings.HasPrefix(raw[i:], key) {
			continue
		}
		k := i + len(key)
		for k < len(raw) && (raw[k] == ' ' || raw[k] == '\t') {
			k++
		}
		if k >= len(raw) || raw[k] != ':' {
			continue
		}
		k++
		for k < len(raw) && (raw[k] == ' ' || raw[k] == '\t') {
			k++
		}
		if k >= len(raw) {
			return -1, -1, false
		}
		return k, yamlValueEnd(raw, k), true
	}
	return -1, -1, false
}

// yamlValueEnd 返回从 valStart 开始的 YAML 值的结束下标（不含）。
// 支持引号标量、嵌套 {}/[] 与以逗号/闭合括号结尾的普通标量。
func yamlValueEnd(raw string, valStart int) int {
	rawLen := len(raw)
	if valStart >= rawLen {
		return rawLen
	}
	switch firstChar := raw[valStart]; firstChar {
	case '\'', '"':
		escaped := false
		for i := valStart + 1; i < rawLen; i++ {
			c := raw[i]
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' && firstChar == '"' {
				escaped = true
				continue
			}
			if c == firstChar {
				if firstChar == '\'' && i+1 < rawLen && raw[i+1] == '\'' {
					i++
					continue
				}
				return i + 1
			}
		}
		return rawLen
	case '{', '[':
		open, close := firstChar, byte('}')
		if firstChar == '[' {
			close = ']'
		}
		depth := 0
		var quote byte
		escaped := false
		for i := valStart; i < rawLen; i++ {
			c := raw[i]
			if quote != 0 {
				if escaped {
					escaped = false
					continue
				}
				if c == '\\' && quote == '"' {
					escaped = true
					continue
				}
				if c == quote {
					quote = 0
				}
				continue
			}
			if c == '\'' || c == '"' {
				quote = c
				continue
			}
			if c == open {
				depth++
			} else if c == close {
				depth--
				if depth == 0 {
					return i + 1
				}
			}
		}
		return rawLen
	}
	end := valStart
	for end < rawLen && raw[end] != ',' && raw[end] != '}' && raw[end] != ']' {
		end++
	}
	for end > valStart && (raw[end-1] == ' ' || raw[end-1] == '\t') {
		end--
	}
	return end
}

// normalizeNodeHost 从节点的 Server 字段（通常为 host:port）提取主机部分，去掉 IPv6 方括号并统一小写。
func normalizeNodeHost(server string) string {
	h := strings.TrimSpace(server)
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.TrimPrefix(h, "[")
	h = strings.TrimSuffix(h, "]")
	return strings.ToLower(strings.TrimSuffix(h, "."))
}
