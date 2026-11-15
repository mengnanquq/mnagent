package miaospeed

import (
	"context"
	"errors"
	"net"
	"testing"
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

	nodes := []MiaospeedNode{
		{Name: "pub-ip", Server: "8.8.8.8:443"},
		{Name: "pub-domain", Server: "public.example:443"},
		{Name: "loopback", Server: "127.0.0.1:22"},
		{Name: "v6-loopback", Server: "[::1]:8080"},
		{Name: "metadata", Server: "169.254.169.254:80"},
		{Name: "internal-domain", Server: "Internal.Example.:443"},
		{Name: "mixed", Server: "mixed.example:443"},
		{Name: "unresolvable", Server: "nx.example:443"},
		{Name: "empty", Server: ""},
	}
	kept, removed := filterBlockedNodes(context.Background(), nodes)
	want := map[string]bool{"pub-ip": true, "pub-domain": true, "unresolvable": true}
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
}
