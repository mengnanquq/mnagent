package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestRotatingLogWriterRotatesAtSize 验证日志按大小轮转，并且只保留指定的历史份数。
func TestRotatingLogWriterRotatesAtSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mnagent.log")
	w, err := newRotatingLogWriter(path, 64, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	write := func(s string) {
		t.Helper()
		if _, err := w.Write([]byte(s)); err != nil {
			t.Fatal(err)
		}
	}
	read := func(p string) string {
		t.Helper()
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}

	write(strings.Repeat("a", 50))
	write(strings.Repeat("b", 50)) // 触发轮转：a -> .1
	write(strings.Repeat("c", 50)) // b -> .1，a -> .2
	write(strings.Repeat("d", 50)) // c -> .1，b -> .2，a 被删除

	if got := read(path); got != strings.Repeat("d", 50) {
		t.Fatalf("当前日志内容异常: %q", got)
	}
	if got := read(path + ".1"); got != strings.Repeat("c", 50) {
		t.Fatalf(".1 内容异常: %q", got)
	}
	if got := read(path + ".2"); got != strings.Repeat("b", 50) {
		t.Fatalf(".2 内容异常: %q", got)
	}
	if _, err := os.Stat(path + ".3"); !os.IsNotExist(err) {
		t.Fatalf("不应保留 .3 历史日志: %v", err)
	}
}

// TestRotatingLogWriterAppendsExisting 验证重启后继续追加已有日志，而不是覆盖。
func TestRotatingLogWriterAppendsExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "mnagent.log")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("old\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	w, err := newRotatingLogWriter(path, 1024, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("new\n")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "old\nnew\n" {
		t.Fatalf("日志应追加而非覆盖，实际 %q", string(data))
	}
}

// TestRotatingLogWriterKeepsWritingWhenRotateFails 验证轮转失败时不会静默丢日志：
// 写入仍成功落到旧文件，并向 stderr 输出一次提示。
func TestRotatingLogWriterKeepsWritingWhenRotateFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mnagent.log")
	// 用非空目录占住 .1，使 Remove 与 Rename 都失败（模拟权限/资源异常）。
	blocker := path + ".1"
	if err := os.MkdirAll(filepath.Join(blocker, "keep"), 0o755); err != nil {
		t.Fatal(err)
	}
	w, err := newRotatingLogWriter(path, 32, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	var warn bytes.Buffer
	w.warnWriter = &warn

	if _, err := w.Write([]byte(strings.Repeat("a", 40))); err != nil {
		t.Fatalf("首次写入失败: %v", err)
	}
	// 第二次写入超过上限，触发轮转并失败。
	if _, err := w.Write([]byte("b")); err != nil {
		t.Fatalf("轮转失败时不应向调用方返回错误（日志应继续写入旧文件）: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != strings.Repeat("a", 40)+"b" {
		t.Fatalf("轮转失败后应继续写旧文件，实际内容长度 %d", len(data))
	}
	if !strings.Contains(warn.String(), "日志轮转失败") {
		t.Fatalf("轮转失败应输出提示，实际告警: %q", warn.String())
	}

	// 同一次故障不应在每次写入都刷告警。
	if _, err := w.Write([]byte("c")); err != nil {
		t.Fatalf("持续写入应保持成功: %v", err)
	}
	if got := strings.Count(warn.String(), "日志轮转失败"); got != 1 {
		t.Fatalf("轮转失败告警应只输出一次，实际 %d 次", got)
	}
}

// TestRotatingLogWriterRetriesReopenWithoutStderrFallback 验证轮转后重新打开失败时
// 不再回退 stderr（main 已用 MultiWriter 写 stderr，回退会让每行日志重复），
// 而是按 reopenInterval 节流重试；失败告警只输出一次，恢复后输出一条恢复日志。
func TestRotatingLogWriterRetriesReopenWithoutStderrFallback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mnagent.log")
	w, err := newRotatingLogWriter(path, 16, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	var warn bytes.Buffer
	w.warnWriter = &warn
	w.reopenInterval = 50 * time.Millisecond
	attempts := 0
	w.openFile = func(p string) (*os.File, error) {
		attempts++
		if attempts <= 2 {
			return nil, errors.New("reopen denied")
		}
		return os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	}

	if _, err := w.Write([]byte(strings.Repeat("a", 20))); err != nil {
		t.Fatalf("首次写入失败: %v", err)
	}
	// 触发轮转：关闭旧文件后第一次重新打开失败，本条日志只留在 stderr（由 main 写）。
	const droppedLine = "stderr-fallback-should-not-appear"
	if n, err := w.Write([]byte(droppedLine)); err != nil || n != len(droppedLine) {
		t.Fatalf("重开失败时不应向调用方返回错误，n=%d err=%v", n, err)
	}
	if !strings.Contains(warn.String(), "重新打开失败") {
		t.Fatalf("应提示重新打开失败，实际: %q", warn.String())
	}
	if !strings.Contains(warn.String(), "每 50ms 重试一次") {
		t.Fatalf("应提示重试间隔，实际: %q", warn.String())
	}
	if strings.Contains(warn.String(), "已回退到 stderr") {
		t.Fatalf("不应再回退到 stderr（会与 main 的 stderr 输出重复），实际: %q", warn.String())
	}
	if strings.Contains(warn.String(), droppedLine) {
		t.Fatalf("不应把日志内容回退写入 stderr，实际: %q", warn.String())
	}

	// 未到重试间隔：不应再次调用 openFile。
	if _, err := w.Write([]byte("c")); err != nil {
		t.Fatalf("节流期间写入不应报错: %v", err)
	}
	if attempts != 1 {
		t.Fatalf("重试应受间隔限制，实际打开 %d 次", attempts)
	}

	// 到点后再次重试仍失败：告警不得重复输出。
	time.Sleep(60 * time.Millisecond)
	if _, err := w.Write([]byte("d")); err != nil {
		t.Fatalf("重试失败时写入不应报错: %v", err)
	}
	if attempts != 2 {
		t.Fatalf("到点后应重试一次，实际打开 %d 次", attempts)
	}
	if got := strings.Count(warn.String(), "重新打开失败"); got != 1 {
		t.Fatalf("重开失败告警应只输出一次，实际 %d 次: %q", got, warn.String())
	}

	// 第三次重试成功：输出恢复日志，后续内容写入文件。
	time.Sleep(60 * time.Millisecond)
	if n, err := w.Write([]byte("e")); err != nil || n != 1 {
		t.Fatalf("恢复后应正常写入文件，n=%d err=%v", n, err)
	}
	if !strings.Contains(warn.String(), "已恢复写入") {
		t.Fatalf("恢复后应输出恢复日志，实际: %q", warn.String())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "e" {
		t.Fatalf("恢复后应继续写日志文件，实际: %q", data)
	}
	rotated, err := os.ReadFile(path + ".1")
	if err != nil {
		t.Fatal(err)
	}
	if string(rotated) != strings.Repeat("a", 20) {
		t.Fatalf("轮转文件内容异常: %q", rotated)
	}
}

// TestRotatingLogWriterRejectsSymlink 验证日志文件路径是符号链接时拒绝打开，
// 防止以 root 运行的 agent 被诱导向任意目标文件追加日志。
func TestRotatingLogWriterRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows 无 O_NOFOLLOW，符号链接防护由 Unix 平台提供")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target.log")
	if err := os.WriteFile(target, []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "mnagent.log")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("当前环境无法创建符号链接: %v", err)
	}
	if _, err := newRotatingLogWriter(link, 1024, 2); err == nil {
		t.Fatal("日志路径为符号链接时应拒绝打开")
	} else if !strings.Contains(err.Error(), "日志路径是符号链接，已被拒绝") {
		t.Fatalf("符号链接错误应包含中文提示，实际: %v", err)
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "keep\n" {
		t.Fatalf("目标文件不应被写入，实际: %q", data)
	}
}
