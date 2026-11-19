package main

import (
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
