package miaospeed

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/mengnanquq/mnagent/internal/probe"
)

// 节点服务器地址同样受内网拦截约束：否则用户可以提交指向 127.0.0.1、10.x 或云元数据地址的节点，
// 借测速结果探测探针主机所在内网的端口开放情况。

const (
	nodeResolveTimeout     = 3 * time.Second
	nodeResolveConcurrency = 16
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

// filterBlockedNodes 剔除服务器地址指向私有、保留或云元数据地址的节点，返回保留的节点与剔除数量。
// 域名解析失败时按 fail-closed 处理：无法确认目标是否安全就直接剔除，绝不把未经校验的域名
// 交给 miaospeed 去解析连接（否则 DNS 抖动或解析差异都可能绕过 SSRF 守卫）。
// 无法识别服务器地址的节点同样一律剔除，防止借畸形配置绕过检查。
func filterBlockedNodes(ctx context.Context, nodes []MiaospeedNode) ([]MiaospeedNode, int) {
	hostSet := make(map[string]bool)
	for _, n := range nodes {
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
	blocked := make(map[string]bool, len(hosts))
	// 先同步处理字面 IP，再并发解析域名：所有 map 写入都必须持锁，
	// 否则主协程与解析协程会同时写同一张 map（-race 会直接报错）。
	pending := make([]string, 0, len(hosts))
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			blocked[h] = probe.IsBlockedProbeIP(ip)
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
			isBlocked := err != nil || len(ips) == 0
			if !isBlocked {
				for _, ip := range ips {
					if probe.IsBlockedProbeIP(ip) {
						isBlocked = true
						break
					}
				}
			}
			mu.Lock()
			blocked[h] = isBlocked
			mu.Unlock()
		}(h)
	}
	wg.Wait()

	kept := make([]MiaospeedNode, 0, len(nodes))
	removed := 0
	for _, n := range nodes {
		h := normalizeNodeHost(n.Server)
		if h == "" || blocked[h] {
			removed++
			continue
		}
		kept = append(kept, n)
	}
	return kept, removed
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
