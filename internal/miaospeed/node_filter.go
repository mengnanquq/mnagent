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
// 域名无法解析的节点予以保留（miaospeed 自身也会连接失败），避免因 DNS 抖动误杀正常节点；
// 无法识别服务器地址的节点一律剔除，防止借畸形配置绕过检查。
func filterBlockedNodes(ctx context.Context, nodes []MiaospeedNode) ([]MiaospeedNode, int) {
	hosts := make(map[string]bool)
	for _, n := range nodes {
		h := normalizeNodeHost(n.Server)
		if h != "" {
			hosts[h] = false
		}
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, nodeResolveConcurrency)
	for h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			hosts[h] = probe.IsBlockedProbeIP(ip)
			continue
		}
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			rctx, cancel := context.WithTimeout(ctx, nodeResolveTimeout)
			defer cancel()
			ips, err := lookupNodeIPs(rctx, h)
			blocked := false
			if err == nil {
				for _, ip := range ips {
					if probe.IsBlockedProbeIP(ip) {
						blocked = true
						break
					}
				}
			}
			mu.Lock()
			hosts[h] = blocked
			mu.Unlock()
		}(h)
	}
	wg.Wait()

	kept := make([]MiaospeedNode, 0, len(nodes))
	removed := 0
	for _, n := range nodes {
		h := normalizeNodeHost(n.Server)
		if h == "" || hosts[h] {
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
