package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUnlockReportFormat(t *testing.T) {
	rep := UnlockReport{
		IP:       "1.2.3.4",
		Country:  "Japan",
		ISP:      "SoftBank",
		Duration: 1234.5,
		Items: []UnlockItem{
			{Name: "Netflix", Category: "跨国流媒体", Status: "Yes", Region: "JP"},
			{Name: "Disney+", Category: "跨国流媒体", Status: "No"},
			{Name: "YouTube Premium", Category: "跨国流媒体", Status: "Originals Only"},
			{Name: "ChatGPT (OpenAI)", Category: "AI与知识服务", Status: "Yes"},
			{Name: "维基百科 (可编辑性)", Category: "AI与知识服务", Status: "No", Details: "IP 段被封禁"},
		},
	}

	formatted := rep.Format()
	if !strings.Contains(formatted, "RegionRestrictionCheck") {
		t.Fatal("排版应包含标题")
	}
	if !strings.Contains(formatted, "1.2.3.4") || !strings.Contains(formatted, "Japan") {
		t.Fatal("排版应包含出口信息")
	}
	if !strings.Contains(formatted, "已解锁 (Region: JP)") {
		t.Fatal("Netflix 状态展示异常")
	}
	if !strings.Contains(formatted, "仅支持自制剧") {
		t.Fatal("YouTube 状态展示异常")
	}
	if !strings.Contains(formatted, "IP 段被封禁") {
		t.Fatal("维基百科封禁详情展示异常")
	}
}

func TestProbeKindRoutingUnlock(t *testing.T) {
	if !isProbeKind("unlock") {
		t.Fatal("unlock 应该是探针类型")
	}
	if !isProbeKind("media") {
		t.Fatal("media 应该是探针类型")
	}

	outcome, err := runProbe(context.Background(), Job{
		ID:        "test-unlock",
		Kind:      "unlock",
		TimeoutMS: 5000,
	}, true)
	if err != nil {
		t.Fatalf("runProbe unlock 失败: %v", err)
	}
	if len(outcome.Data) == 0 {
		t.Fatal("期望返回结构化 Data")
	}
	if !strings.Contains(outcome.Output, "流媒体与 AI 解锁测试完成") {
		t.Fatalf("摘要输出异常: %q", outcome.Output)
	}
}

func TestFetchBodyAndStatusMock(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") == "" {
			t.Error("缺少 User-Agent")
		}
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte(`{"test":"ok"}`))
	}))
	defer srv.Close()

	body, status := fetchBodyAndStatus(context.Background(), srv.Client(), srv.URL, map[string]string{
		"Custom": "Header",
	})
	if status != http.StatusTeapot {
		t.Fatalf("状态码 = %d, want 418", status)
	}
	if !strings.Contains(body, `"test":"ok"`) {
		t.Fatalf("body 不匹配: %q", body)
	}
}
