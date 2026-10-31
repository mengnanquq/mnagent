package config

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func TestParseLogLevel(t *testing.T) {
	cases := []struct {
		input string
		want  slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"DEBUG", slog.LevelDebug},
		{"warn", slog.LevelWarn},
		{"warning", slog.LevelWarn},
		{"error", slog.LevelError},
		{"info", slog.LevelInfo},
		{"unknown", slog.LevelInfo},
		{"", slog.LevelInfo},
	}
	for _, c := range cases {
		got := ParseLogLevel(c.input)
		if got != c.want {
			t.Errorf("ParseLogLevel(%q) = %v, want %v", c.input, got, c.want)
		}
	}
}

func TestTokenSourceHandlesUTF8BOM(t *testing.T) {
	tmpDir := t.TempDir()
	tokFile := filepath.Join(tmpDir, "token")
	content := []byte("\xef\xbb\xbfmy-secret-token-12345\r\n")
	if err := os.WriteFile(tokFile, content, 0600); err != nil {
		t.Fatalf("写入测试文件失败: %v", err)
	}

	ts, err := NewTokenSource("", tokFile)
	if err != nil {
		t.Fatalf("NewTokenSource 失败: %v", err)
	}

	val, err := ts.Get()
	if err != nil {
		t.Fatalf("ts.Get() 失败: %v", err)
	}
	if val != "my-secret-token-12345" {
		t.Fatalf("未能正确剔除 UTF-8 BOM，期望 'my-secret-token-12345'，得到 %q (len=%d)", val, len(val))
	}
}

func TestDefaultTokenFile(t *testing.T) {
	tok := DefaultTokenFile()
	if tok == "" {
		t.Fatal("DefaultTokenFile 不应为空")
	}
}

func TestTokenSourceReadsFileEachTime(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte("first\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tokens, err := NewTokenSource("", path)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := tokens.Get(); got != "first" {
		t.Fatalf("令牌 = %q", got)
	}
	if err := os.WriteFile(path, []byte("second\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, _ := tokens.Get(); got != "second" {
		t.Fatalf("轮换后令牌 = %q，期望 second", got)
	}
}

func TestNewTokenSourcePrefersExplicitValue(t *testing.T) {
	t.Setenv("MNAGENT_TOKEN", "from-env")
	tokens, err := NewTokenSource("explicit", "")
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := tokens.Get(); got != "explicit" {
		t.Fatalf("令牌 = %q，期望 explicit（-token 优先）", got)
	}

	tokens, err = NewTokenSource("", "")
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := tokens.Get(); got != "from-env" {
		t.Fatalf("令牌 = %q，期望 from-env", got)
	}

	t.Setenv("MNAGENT_TOKEN", "")
	if _, err := NewTokenSource("", filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("令牌文件缺失应报错")
	}
}

func TestParseConfig(t *testing.T) {
	if _, err := ParseConfig([]string{"-token", "t"}, "dev"); err == nil {
		t.Fatal("缺少 -bot 应报错")
	}
	if _, err := ParseConfig([]string{"-bot", "not-a-url", "-token", "t"}, "dev"); err == nil {
		t.Fatal("非法 -bot 应报错")
	}
	if _, err := ParseConfig([]string{"-bot", "https://x/agent", "-token", "t", "-nexttrace", "/nonexistent/nexttrace"}, "dev"); err == nil {
		t.Fatal("找不到的 nexttrace 应报错")
	}

	cfg, err := ParseConfig([]string{"-bot", "https://x/agent/", "-token", "t", "-nexttrace", "/bin/echo"}, "dev")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BotURL != "https://x/agent" {
		t.Fatalf("BotURL 未去除末尾斜杠: %q", cfg.BotURL)
	}
	if cfg.Tokens == nil {
		t.Fatal("令牌来源应已解析")
	}

	cfgMissingNT, err := ParseConfig([]string{"-bot", "https://x/agent", "-token", "t", "-nexttrace", "nonexistent-cmd-nt"}, "dev")
	if err != nil {
		t.Fatalf("默认命令未安装时应当允许启动降级: %v", err)
	}
	if cfgMissingNT.Binary != "nonexistent-cmd-nt" {
		t.Fatalf("Binary 不匹配: %s", cfgMissingNT.Binary)
	}
}

func TestParseConfigRejectsHostFlag(t *testing.T) {
	if _, err := ParseConfig([]string{"-bot", "https://x/agent", "-token", "t", "-host", "hk", "-nexttrace", "/bin/echo"}, "dev"); err == nil {
		t.Fatal("-host 已移除，传了应当报错（未知参数）")
	}
	cfg, err := ParseConfig([]string{"-bot", "https://x/agent", "-token", "t", "-nexttrace", "/bin/echo"}, "dev")
	if err != nil {
		t.Fatalf("只给 --bot/--token 应当合法：%v", err)
	}
	if cfg.BotURL != "https://x/agent" {
		t.Fatalf("BotURL = %q", cfg.BotURL)
	}
}
