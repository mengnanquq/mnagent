package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
