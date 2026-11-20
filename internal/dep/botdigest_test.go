package dep

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/mengnanquq/mnagent/internal/updater"
)

// fakeDigestToken 是 updater.TokenProvider 的测试实现。
type fakeDigestToken struct {
	value string
	err   error
}

func (f fakeDigestToken) Get() (string, error) { return f.value, f.err }

// TestFetchAssetDigestPrefersBotDigest 验证依赖优先使用服务端代取的摘要，
// 且命中后不再请求同源 .sha256 与 API（依赖路径不做交叉校验）。
func TestFetchAssetDigestPrefersBotDigest(t *testing.T) {
	botSum := strings.Repeat("a", 64)
	upstreamSum := strings.Repeat("b", 64)
	var botHits, sumHits, apiHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/agent/release-digest":
			botHits.Add(1)
			q := r.URL.Query()
			if q.Get("repo") != "nxtrace/NTrace-core" || q.Get("tag") != "v1.7.4" || q.Get("asset") != "nexttrace_linux_amd64" {
				t.Errorf("代取 query 参数异常：%v", q)
			}
			if got := r.Header.Get("Authorization"); got != "Bearer tok" {
				t.Errorf("Authorization = %q", got)
			}
			fmt.Fprintf(w, `{"ok":true,"sha256":%q,"source":"release-sha256"}`, botSum)
		case strings.HasSuffix(r.URL.Path, ".sha256"):
			sumHits.Add(1)
			fmt.Fprintf(w, "%s  nexttrace_linux_amd64\n", upstreamSum)
		case strings.Contains(r.URL.Path, "/releases/tags/"):
			apiHits.Add(1)
			fmt.Fprintf(w, `{"assets":[{"name":"nexttrace_linux_amd64","digest":"sha256:%s"}]}`, upstreamSum)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dm := newDependencyManager("")
	dm.apiBaseURL = srv.URL
	dm.githubBaseURL = srv.URL
	dm.SetBotDigest(&updater.BotDigestClient{
		BaseURL: srv.URL + "/agent",
		Token:   fakeDigestToken{value: "tok"},
		Client:  srv.Client(),
		Version: "v0.4.2",
	})
	got, err := dm.fetchAssetDigest(context.Background(), "nxtrace/NTrace-core", "v1.7.4", "nexttrace_linux_amd64")
	if err != nil || got != botSum {
		t.Fatalf("应优先采用服务端代取的摘要：got=%q err=%v", got, err)
	}
	if got := botHits.Load(); got != 1 {
		t.Fatalf("服务端代取应只尝试 1 次，实际 %d 次", got)
	}
	if got := sumHits.Load(); got != 0 {
		t.Fatalf("依赖路径不做交叉校验，不应请求同源 .sha256，实际 %d 次", got)
	}
	if got := apiHits.Load(); got != 0 {
		t.Fatalf("代取成功后不应回退 API，实际 %d 次", got)
	}
}

// TestFetchAssetDigestFallsBackWhenBotDigestFails 验证服务端代取失败后回退同源 .sha256。
func TestFetchAssetDigestFallsBackWhenBotDigestFails(t *testing.T) {
	sum := strings.Repeat("c", 64)
	var botHits, sumHits, apiHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/agent/release-digest":
			botHits.Add(1)
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"ok":false,"code":"not_found"}`))
		case strings.HasSuffix(r.URL.Path, ".sha256"):
			sumHits.Add(1)
			fmt.Fprintf(w, "%s  nexttrace_linux_amd64\n", sum)
		case strings.Contains(r.URL.Path, "/releases/tags/"):
			apiHits.Add(1)
			http.Error(w, "should not be called", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dm := newDependencyManager("")
	dm.apiBaseURL = srv.URL
	dm.githubBaseURL = srv.URL
	dm.SetBotDigest(&updater.BotDigestClient{BaseURL: srv.URL + "/agent", Token: fakeDigestToken{value: "tok"}, Client: srv.Client()})
	got, err := dm.fetchAssetDigest(context.Background(), "nxtrace/NTrace-core", "v1.7.4", "nexttrace_linux_amd64")
	if err != nil || got != sum {
		t.Fatalf("代取失败后应回退同源 .sha256：got=%q err=%v", got, err)
	}
	if got := botHits.Load(); got != 1 {
		t.Fatalf("服务端代取应只尝试 1 次，实际 %d 次", got)
	}
	if got := sumHits.Load(); got != 1 {
		t.Fatalf("同源 .sha256 应成功 1 次，实际 %d 次", got)
	}
	if got := apiHits.Load(); got != 0 {
		t.Fatalf(".sha256 成功时不应回退 API，实际 %d 次", got)
	}
}

// TestFetchAssetDigestAllSourcesFailMentionsBot 验证全部来源失败时摘要包含代取与原有提示。
func TestFetchAssetDigestAllSourcesFailMentionsBot(t *testing.T) {
	var botHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/agent/release-digest" {
			botHits.Add(1)
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	dm := newDependencyManager("")
	dm.apiBaseURL = srv.URL
	dm.githubBaseURL = srv.URL
	dm.SetBotDigest(&updater.BotDigestClient{BaseURL: srv.URL + "/agent", Token: fakeDigestToken{value: "tok"}, Client: srv.Client()})
	_, err := dm.fetchAssetDigest(context.Background(), "nxtrace/NTrace-core", "v1.7.4", "nexttrace_linux_amd64")
	if err == nil {
		t.Fatal("全部来源失败时应返回错误")
	}
	for _, want := range []string{"服务端代取（1次：", "同源 .sha256失败（1次", "GitHub API失败（1次", "api.github.com"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("错误摘要 %q 未包含 %q", err.Error(), want)
		}
	}
	if got := botHits.Load(); got != 1 {
		t.Fatalf("服务端代取应只尝试 1 次，实际 %d 次", got)
	}
}

// TestFetchAssetDigestSkipsBotDigestWithoutToken 验证拿不到令牌时不发请求并回退直连来源。
func TestFetchAssetDigestSkipsBotDigestWithoutToken(t *testing.T) {
	sum := strings.Repeat("d", 64)
	var botHits, sumHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/agent/release-digest":
			botHits.Add(1)
			fmt.Fprintf(w, `{"ok":true,"sha256":%q}`, strings.Repeat("e", 64))
		case strings.HasSuffix(r.URL.Path, ".sha256"):
			sumHits.Add(1)
			fmt.Fprintf(w, "%s  nexttrace_linux_amd64\n", sum)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dm := newDependencyManager("")
	dm.apiBaseURL = srv.URL
	dm.githubBaseURL = srv.URL
	dm.SetBotDigest(&updater.BotDigestClient{
		BaseURL: srv.URL + "/agent",
		Token:   fakeDigestToken{err: errors.New("令牌文件缺失")},
		Client:  srv.Client(),
	})
	got, err := dm.fetchAssetDigest(context.Background(), "nxtrace/NTrace-core", "v1.7.4", "nexttrace_linux_amd64")
	if err != nil || got != sum {
		t.Fatalf("拿不到令牌时应回退直连：got=%q err=%v", got, err)
	}
	if got := botHits.Load(); got != 0 {
		t.Fatalf("拿不到令牌时不得发出代取请求，实际 %d 次", got)
	}
	if got := sumHits.Load(); got != 1 {
		t.Fatalf("同源 .sha256 应成功 1 次，实际 %d 次", got)
	}
}
