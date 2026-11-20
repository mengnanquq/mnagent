package dep

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestUpdateDependencyDefaultBudgetTimesOutAndCoolsDown 验证非升级路径使用
// 宽松的自身预算（dependencyUpdateBudget）：预算耗尽时应写入失败冷却，
// 避免弱网下每轮任务都重新下载一遍。
func TestUpdateDependencyDefaultBudgetTimesOutAndCoolsDown(t *testing.T) {
	resetDependencyInstallState()
	t.Cleanup(resetDependencyInstallState)

	origBudget := dependencyUpdateBudget
	dependencyUpdateBudget = 150 * time.Millisecond
	defer func() { dependencyUpdateBudget = origBudget }()

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		<-r.Context().Done() // 一直不返回，直到预算耗尽取消请求
	}))
	defer srv.Close()

	// 配置 gh-proxy 把下载指向本地测试服务，由它一直挂住到预算耗尽。
	dm := newDependencyManager(srv.URL)
	dm.goos = "linux"
	dm.goarch = "amd64"
	target := filepath.Join(t.TempDir(), "bin", "nexttrace")

	_, err := dm.EnsureDependency(context.Background(), "nexttrace", target, "v1.7.4", nil)
	if err == nil {
		t.Fatal("自身预算耗尽时安装应报错")
	}
	if !errors.Is(err, errDependencyBudgetExceeded) {
		t.Fatalf("错误应标记为自身预算耗尽（便于写冷却），实际: %v", err)
	}
	if !strings.Contains(err.Error(), "依赖安装整体预算已用尽") {
		t.Fatalf("错误文案应说明预算耗尽，实际: %v", err)
	}
	firstHits := hits.Load()
	if firstHits == 0 {
		t.Fatal("预算内应至少发出一次下载请求")
	}

	// 第二次调用应命中冷却，而不是重新下载。
	_, err = dm.EnsureDependency(context.Background(), "nexttrace", target, "v1.7.4", nil)
	if err == nil || !strings.Contains(err.Error(), "不会重复下载") {
		t.Fatalf("自身预算超时后应写入冷却，实际: %v", err)
	}
	if got := hits.Load(); got != firstHits {
		t.Fatalf("冷却期内不应再次请求上游，首次 %d 次、现在 %d 次", firstHits, got)
	}
}

// TestUpdateDependencyWithinCallerCancelNotBudget 验证调用方 ctx 取消不会被
// 误判成“自身预算耗尽”，错误链保留 context.Canceled。
func TestUpdateDependencyWithinCallerCancelNotBudget(t *testing.T) {
	origBudget := dependencyUpdateBudget
	dependencyUpdateBudget = 5 * time.Second
	defer func() { dependencyUpdateBudget = origBudget }()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	dm := newDependencyManager("")
	dm.apiBaseURL = srv.URL
	dm.githubBaseURL = srv.URL
	dm.goos = "linux"
	dm.goarch = "amd64"
	target := filepath.Join(t.TempDir(), "bin", "nexttrace")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := dm.UpdateDependencyWithin(ctx, 5*time.Second, "nexttrace", target, "v1.7.4", nil)
	if err == nil {
		t.Fatal("调用方取消时更新应报错")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("调用方取消应保留 context.Canceled，实际: %v", err)
	}
	if errors.Is(err, errDependencyBudgetExceeded) {
		t.Fatalf("调用方取消不应标记为自身预算耗尽: %v", err)
	}
}

// TestDownloadAssetSlowStreamNotAborted 验证归档下载不设整体 Timeout：
// 只要持续有数据，即使总耗时超过响应头/空闲超时（生产上相当于超过旧的 20s
// 整体超时）也不会失败。测试通过缩短空闲超时来模拟弱网慢速分块传输。
func TestDownloadAssetSlowStreamNotAborted(t *testing.T) {
	origIdle := dependencyDownloadIdleTimeout
	origHeader := dependencyResponseHeaderTimeout
	dependencyDownloadIdleTimeout = 250 * time.Millisecond
	dependencyResponseHeaderTimeout = 500 * time.Millisecond
	defer func() {
		dependencyDownloadIdleTimeout = origIdle
		dependencyResponseHeaderTimeout = origHeader
	}()

	content := bytes.Repeat([]byte("slow-stream-"), 8<<10) // 96KB

	chunks := 10
	chunkSize := len(content) / chunks
	var flushes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dl" {
			http.NotFound(w, r)
			return
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Error("测试服务器不支持 Flush")
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(content)))
		for i := 0; i < chunks; i++ {
			end := (i + 1) * chunkSize
			if i == chunks-1 {
				end = len(content)
			}
			_, _ = w.Write(content[i*chunkSize : end])
			flusher.Flush()
			flushes.Add(1)
			select {
			case <-time.After(40 * time.Millisecond): // 持续有数据，但每块间隔远小于空闲超时
			case <-r.Context().Done():
				return
			}
		}
	}))
	defer srv.Close()

	dm := newDependencyManager("")
	dm.downloadClient = nil // 使用按当前（已缩短的）超时变量构建的下载客户端

	tmpPath := filepath.Join(t.TempDir(), "download")
	n, err := dm.downloadAsset(context.Background(), "nexttrace_linux_amd64", srv.URL+"/dl", tmpPath)
	if err != nil {
		t.Fatalf("持续有数据的慢速下载不应失败: %v", err)
	}
	if n != int64(len(content)) {
		t.Fatalf("下载字节数 = %d，期望 %d", n, len(content))
	}
	got, err := os.ReadFile(tmpPath)
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("下载内容不一致: err=%v len=%d", err, len(got))
	}
	if flushes.Load() < int32(chunks) {
		t.Fatalf("应分块传输 %d 次，实际 %d 次", chunks, flushes.Load())
	}
}

// TestDownloadAssetIdleTimeout 验证连续无数据超过空闲读超时会中止下载，
// 而不是无限等待。
func TestDownloadAssetIdleTimeout(t *testing.T) {
	origIdle := dependencyDownloadIdleTimeout
	dependencyDownloadIdleTimeout = 80 * time.Millisecond
	defer func() { dependencyDownloadIdleTimeout = origIdle }()

	content := []byte("idle-timeout-body")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 先发响应头发起传输，再长时间不写数据。
		w.Header().Set("Content-Length", fmt.Sprint(len(content)))
		w.WriteHeader(http.StatusOK)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()

	dm := newDependencyManager("")
	dm.downloadClient = nil

	tmpPath := filepath.Join(t.TempDir(), "download")
	_, err := dm.downloadAsset(context.Background(), "nexttrace_linux_amd64", srv.URL+"/dl", tmpPath)
	if err == nil {
		t.Fatal("连续无数据超过空闲超时应中止下载")
	}
	if !strings.Contains(err.Error(), "未收到数据") {
		t.Fatalf("错误文案应说明空闲超时，实际: %v", err)
	}
	if _, statErr := os.Stat(tmpPath); !os.IsNotExist(statErr) {
		t.Fatalf("空闲超时后应清理半成品文件: %v", statErr)
	}
}

// TestUpdateDependencyCancelBeforeReplace 验证自检后收到取消时不替换目标二进制。
// 覆盖 nexttrace 与 miaospeed 两条替换前检查路径。
func TestUpdateDependencyCancelBeforeReplace(t *testing.T) {
	t.Run("nexttrace", func(t *testing.T) {
		content := bytes.Repeat([]byte("N"), 150*1024)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "releases/download") {
				_, _ = w.Write(content)
				return
			}
			http.NotFound(w, r)
		}))
		defer srv.Close()

		dm := newDependencyManager(srv.URL)
		dm.apiBaseURL = srv.URL
		dm.githubBaseURL = srv.URL
		dm.goos = "linux"
		dm.goarch = "amd64"

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		dm.cmdRunner = func(_ context.Context, _ string, _ ...string) ([]byte, error) {
			cancel() // 自检期间收到取消
			return []byte("NextTrace  v1.7.4\n"), nil
		}

		target := filepath.Join(t.TempDir(), "bin", "nexttrace")
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte("old-binary"), 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := dm.UpdateNextTrace(ctx, target, "v1.7.4", nil); err == nil {
			t.Fatal("取消后更新应报错")
		} else if !strings.Contains(err.Error(), "已取消") {
			t.Fatalf("错误文案应说明已取消，实际: %v", err)
		}
		if got, err := os.ReadFile(target); err != nil || string(got) != "old-binary" {
			t.Fatalf("取消后不得替换二进制: content=%q err=%v", string(got), err)
		}
	})

	t.Run("miaospeed", func(t *testing.T) {
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gw)
		miaoContent := []byte("#!/bin/sh\necho miaospeed\n")
		if err := tw.WriteHeader(&tar.Header{
			Name:     "miaospeed-linux-amd64",
			Mode:     0o755,
			Size:     int64(len(miaoContent)),
			Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		_, _ = tw.Write(miaoContent)
		_ = tw.Close()
		_ = gw.Close()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, ".tar.gz") {
				_, _ = w.Write(buf.Bytes())
				return
			}
			http.NotFound(w, r)
		}))
		defer srv.Close()

		dm := newDependencyManager(srv.URL)
		dm.apiBaseURL = srv.URL
		dm.githubBaseURL = srv.URL
		dm.goos = "linux"
		dm.goarch = "amd64"

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		dm.cmdRunner = func(_ context.Context, _ string, _ ...string) ([]byte, error) {
			cancel() // 自检期间收到取消
			return []byte("version: 4.7.7\n"), nil
		}

		target := filepath.Join(t.TempDir(), "bin", "miaospeed")
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte("old-binary"), 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := dm.UpdateMiaospeed(ctx, target, "4.7.7", nil); err == nil {
			t.Fatal("取消后更新应报错")
		} else if !strings.Contains(err.Error(), "已取消") {
			t.Fatalf("错误文案应说明已取消，实际: %v", err)
		}
		if got, err := os.ReadFile(target); err != nil || string(got) != "old-binary" {
			t.Fatalf("取消后不得替换二进制: content=%q err=%v", string(got), err)
		}
	})
}
