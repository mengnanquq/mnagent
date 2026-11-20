package runner

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mengnanquq/mnagent/internal/client"
	"github.com/mengnanquq/mnagent/internal/config"
	"github.com/mengnanquq/mnagent/internal/dep"
	"github.com/mengnanquq/mnagent/internal/model"
	"github.com/mengnanquq/mnagent/internal/tracker"
)

// TestUpgradeWorkBudget 验证升级预算按 job.TimeoutMS 计算并夹取：
// 缺省 120s-5s=115s；带值时减去回传预留；过小夹到 1s，过大不超过 115s。
func TestUpgradeWorkBudget(t *testing.T) {
	cases := []struct {
		name      string
		timeoutMS int64
		want      time.Duration
	}{
		{"未下发", 0, 115 * time.Second},
		{"典型 120s", 120000, 115 * time.Second},
		{"60s", 60000, 55 * time.Second},
		{"过小夹取", 5000, time.Second},
		{"过大夹取", 600000, 115 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := upgradeWorkBudget(model.Job{TimeoutMS: tc.timeoutMS}); got != tc.want {
				t.Fatalf("upgradeWorkBudget(%d) = %s，期望 %s", tc.timeoutMS, got, tc.want)
			}
		})
	}
}

// TestUpgradeJobBusyWhenUpdateLockHeld 验证 updateMu 被占用时，升级任务在
// 自身预算内回报“忙”，而不是一直阻塞。
func TestUpgradeJobBusyWhenUpdateLockHeld(t *testing.T) {
	results := make(chan model.Result, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/results" {
			var res model.Result
			_ = json.NewDecoder(r.Body).Decode(&res)
			results <- res
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	cfg := &config.Config{
		BotURL:      srv.URL,
		Tokens:      &config.TokenSource{Value: "tok"},
		PollTimeout: time.Second,
	}
	a := &Agent{
		cfg:    cfg,
		logger: testLogger{t},
		client: client.New(cfg),
	}
	skipDependencyCheck(a)

	// 模拟另一轮更新（自动更新或远程升级）正持有 updateMu。
	a.updateMu.Lock()
	defer a.updateMu.Unlock()

	start := time.Now()
	done := make(chan struct{})
	go func() {
		// TimeoutMS=5s 会被夹取为 1s 工作预算。
		a.handleUpgradeJob(context.Background(), model.Job{ID: "busy-upgrade", Kind: "upgrade", Target: "v1.1.0", TimeoutMS: 5000})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("updateMu 被占用时升级任务未在预算内退出")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("升级任务等待锁耗时 %s，超过预算", elapsed)
	}
	select {
	case res := <-results:
		if res.ExitCode != -1 || !strings.Contains(res.Output, "忙") {
			t.Fatalf("锁被占用时应回报“忙”，实际: %+v", res)
		}
	default:
		t.Fatal("锁被占用时应回传结果")
	}
}

// TestUpgradeJobDependencyPhaseTimeoutContinuesSelfUpdate 验证依赖阶段超时后
// 只跳过剩余依赖并继续更新自身，且该紧凑预算只作用于升级路径。
func TestUpgradeJobDependencyPhaseTimeoutContinuesSelfUpdate(t *testing.T) {
	origPhase := upgradeDependencyPhaseTimeout
	upgradeDependencyPhaseTimeout = 120 * time.Millisecond
	defer func() { upgradeDependencyPhaseTimeout = origPhase }()

	payload := []byte("#!/bin/sh\necho \"mnagent v1.1.0 (linux/amd64, go1.26.0)\"\n")
	for len(payload) < 2048 {
		payload = append(payload, '#', '\n')
	}
	sum := fmt.Sprintf("%x", sha256.Sum256(payload))

	var reported model.Result
	var restarted atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ".sha256"):
			fmt.Fprintf(w, "%s  mnagent_linux_amd64\n", sum)
		case strings.HasPrefix(r.URL.Path, "/dl/"):
			_, _ = w.Write(payload)
		case r.URL.Path == "/results":
			_ = json.NewDecoder(r.Body).Decode(&reported)
			w.WriteHeader(http.StatusNoContent)
		case strings.Contains(r.URL.Path, "/releases/latest"):
			// 依赖检查卡住，直到依赖阶段预算耗尽。
			select {
			case <-time.After(10 * time.Second):
			case <-r.Context().Done():
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	origVersion := Version
	Version = "v1.0.0"
	defer func() { Version = origVersion }()

	dir := t.TempDir()
	cfg := &config.Config{
		BotURL:          srv.URL,
		Tokens:          &config.TokenSource{Value: "tok"},
		PollTimeout:     time.Second,
		Binary:          filepath.Join(dir, "nexttrace"),
		MiaospeedBinary: filepath.Join(dir, "miaospeed"),
		GHProxy:         srv.URL, // 防止依赖兜底下载落到真实 GitHub
	}
	exePath := filepath.Join(dir, "mnagent")
	if err := os.WriteFile(exePath, []byte("old-bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	u := newUpdater(cfg, testLogger{t})
	u.Executable = exePath
	u.DownloadClient = srv.Client()
	u.URLForFunc = func(version string) string { return srv.URL + "/dl/" + version + "/" + u.AssetName() }
	u.ChecksumURLFunc = func(version string) string { return srv.URL + "/dl/" + version + "/" + u.AssetName() + ".sha256" }
	u.ChecksumAPIURLFunc = func(version string) string { return srv.URL + "/releases/tags/" + version }
	u.RestartFunc = func() error {
		restarted.Store(true)
		return nil
	}

	a := &Agent{
		cfg:    cfg,
		logger: testLogger{t},
		client: client.New(cfg),
		update: u,
	}
	a.depManagerFactory = func(proxy string) *dep.DependencyManager {
		dm := dep.NewDependencyManager(proxy)
		dm.SetGitHubEndpoints(srv.URL, srv.URL)
		return dm
	}

	start := time.Now()
	a.handleUpgradeJob(context.Background(), model.Job{ID: "dep-timeout", Kind: "upgrade", Target: "v1.1.0", TimeoutMS: 30000})
	elapsed := time.Since(start)

	if !restarted.Load() {
		t.Fatal("依赖阶段超时后应继续更新自身并重启")
	}
	if reported.ExitCode != 0 || !strings.Contains(reported.Output, "成功下载并安装 v1.1.0") {
		t.Fatalf("自身更新结果异常: %+v", reported)
	}
	if !strings.Contains(reported.Output, "依赖更新超过") {
		t.Fatalf("结果中应说明依赖阶段超时，实际: %+v", reported)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("依赖阶段超时后应立即继续自身更新，实际耗时 %s", elapsed)
	}
}

// TestUpgradeJobTrackerCancelAllOrder 锁定成功路径上 Unregister → CancelAll 的顺序：
// 本轮升级自己的 ctx 不能被 CancelAll 取消，否则不会重启；同时其他在途任务应被取消。
func TestUpgradeJobTrackerCancelAllOrder(t *testing.T) {
	payload := []byte("#!/bin/sh\necho \"mnagent v1.1.0 (linux/amd64, go1.26.0)\"\n")
	for len(payload) < 2048 {
		payload = append(payload, '#', '\n')
	}
	sum := fmt.Sprintf("%x", sha256.Sum256(payload))

	var reported model.Result
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ".sha256"):
			fmt.Fprintf(w, "%s  mnagent_linux_amd64\n", sum)
		case strings.HasPrefix(r.URL.Path, "/dl/"):
			_, _ = w.Write(payload)
		case r.URL.Path == "/results":
			_ = json.NewDecoder(r.Body).Decode(&reported)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	origVersion := Version
	Version = "v1.0.0"
	defer func() { Version = origVersion }()

	cfg := &config.Config{
		BotURL:      srv.URL,
		Tokens:      &config.TokenSource{Value: "tok"},
		PollTimeout: time.Second,
	}
	exePath := filepath.Join(t.TempDir(), "mnagent")
	if err := os.WriteFile(exePath, []byte("old-bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	u := newUpdater(cfg, testLogger{t})
	u.Executable = exePath
	u.DownloadClient = srv.Client()
	u.URLForFunc = func(version string) string { return srv.URL + "/dl/" + version + "/" + u.AssetName() }
	u.ChecksumURLFunc = func(version string) string { return srv.URL + "/dl/" + version + "/" + u.AssetName() + ".sha256" }
	u.ChecksumAPIURLFunc = func(version string) string { return srv.URL + "/releases/tags/" + version }
	var restarted atomic.Bool
	u.RestartFunc = func() error {
		restarted.Store(true)
		return nil
	}

	trk := tracker.New()
	fakeCtx, fakeCancel := context.WithCancel(context.Background())
	defer fakeCancel()
	trk.Register("in-flight-task", fakeCancel)
	fakeCancelled := make(chan struct{})
	go func() {
		<-fakeCtx.Done()
		close(fakeCancelled)
	}()

	a := &Agent{
		cfg:     cfg,
		logger:  testLogger{t},
		client:  client.New(cfg),
		update:  u,
		tracker: trk,
	}
	skipDependencyCheck(a)

	a.handleUpgradeJob(context.Background(), model.Job{ID: "order-upgrade", Kind: "upgrade", Target: "v1.1.0"})

	if !restarted.Load() {
		t.Fatal("成功升级后应重启；若 CancelAll 先于 Unregister，本轮升级会被自己取消")
	}
	if reported.ExitCode != 0 {
		t.Fatalf("升级结果异常: %+v", reported)
	}
	select {
	case <-fakeCancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("重启前应 CancelAll 取消其他在途任务")
	}
}

// TestDependencyCheckIgnoresUpgradePhaseBudget 验证 40s 依赖阶段预算只作用于升级任务：
// 缩短 upgradeDependencyPhaseTimeout 后，启动/定期依赖检查仍按 dep 包的宽松预算执行，
// 不会被升级路径的紧凑预算误杀。
func TestDependencyCheckIgnoresUpgradePhaseBudget(t *testing.T) {
	origPhase := upgradeDependencyPhaseTimeout
	upgradeDependencyPhaseTimeout = 80 * time.Millisecond
	defer func() { upgradeDependencyPhaseTimeout = origPhase }()

	body := "#!/bin/sh\ncase \"$1\" in\n  -V|--version) echo \"NextTrace  v1.7.4\" ;;\n  *) echo ok ;;\nesac\n"
	for len(body) < 150*1024 {
		body += "# padding\n"
	}
	content := []byte(body)
	digest := fmt.Sprintf("%x", sha256.Sum256(content))
	asset, err := dep.NexttraceAsset(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}

	var sumHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ".sha256"):
			sumHits.Add(1)
			// 摘要响应比升级路径的 80ms 预算更慢：非升级路径不应被它截断。
			select {
			case <-time.After(250 * time.Millisecond):
			case <-r.Context().Done():
				return
			}
			fmt.Fprintf(w, "%s  %s\n", digest, asset)
		case strings.Contains(r.URL.Path, "/nxtrace/NTrace-core/releases/latest"):
			_, _ = w.Write([]byte(`{"tag_name":"v1.7.4"}`))
		case strings.Contains(r.URL.Path, "/AirportR/miaospeed/releases/latest"):
			_, _ = w.Write([]byte(`{"tag_name":"4.7.7"}`))
		case strings.Contains(r.URL.Path, "releases/download"):
			_, _ = w.Write(content)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	nexttracePath := filepath.Join(dir, "nexttrace")
	miaoPath := filepath.Join(dir, "miaospeed")
	if err := os.WriteFile(miaoPath, []byte("#!/bin/sh\necho \"version: 4.7.7\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Binary:          nexttracePath,
		MiaospeedBinary: miaoPath,
		GHProxy:         srv.URL,
	}
	a := &Agent{cfg: cfg, logger: testLogger{t}}
	a.depManagerFactory = func(proxy string) *dep.DependencyManager {
		dm := dep.NewDependencyManager(proxy)
		dm.SetGitHubEndpoints(srv.URL, srv.URL)
		return dm
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	a.checkAndUpdateDependencies(ctx)
	elapsed := time.Since(start)

	if sumHits.Load() == 0 {
		t.Fatal("依赖检查应请求 .sha256 摘要")
	}
	if elapsed < 200*time.Millisecond {
		t.Fatalf("依赖检查耗时 %s，未真正经过慢速摘要响应", elapsed)
	}
	if _, err := os.Stat(nexttracePath); err != nil {
		t.Fatalf("非升级路径不应受升级阶段 80ms 预算限制，nexttrace 应安装成功: %v", err)
	}
}
