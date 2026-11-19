package config

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
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
	if _, err := ParseConfig([]string{"-bot", "https://x/agent", "-token", "t", "-nexttrace", "/bin/echo", "-result-timeout", "1s"}, "dev"); err == nil {
		t.Fatal("过短的 -result-timeout 应报错")
	}

	cfg, err := ParseConfig([]string{"-bot", "https://x/agent/", "-token", "t", "-nexttrace", "/bin/echo"}, "dev")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ResultTimeout != DefaultResultTimeout {
		t.Fatalf("默认结果回传超时 = %s，期望 %s", cfg.ResultTimeout, DefaultResultTimeout)
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

// TestParseConfigAllowRemoteDowngrade 验证远程降级开关默认关闭、显式传入时开启。
func TestParseConfigAllowRemoteDowngrade(t *testing.T) {
	cfg, err := ParseConfig([]string{"-bot", "https://x/agent", "-token", "t", "-nexttrace", "/bin/echo"}, "dev")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AllowRemoteDowngrade {
		t.Fatal("默认不允许远程降级")
	}
	cfg, err = ParseConfig([]string{"-bot", "https://x/agent", "-token", "t", "-nexttrace", "/bin/echo", "-allow-remote-downgrade"}, "dev")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.AllowRemoteDowngrade {
		t.Fatal("-allow-remote-downgrade 应开启远程降级")
	}
}

// TestParseConfigRejectsInsecureHTTPAndUnsafeChars 验证 -bot 的明文 HTTP 策略与严格字符校验。
func TestParseConfigRejectsInsecureHTTPAndUnsafeChars(t *testing.T) {
	base := []string{"-token", "t", "-nexttrace", "/bin/echo"}

	// 明文 HTTP 连接公网地址默认拒绝；显式开关后允许并打印警告。
	if _, err := ParseConfig(append([]string{"-bot", "http://bot.example.com/agent"}, base...), "dev"); err == nil || !strings.Contains(err.Error(), "allow-insecure-http") {
		t.Fatalf("公网明文 HTTP 应被拒绝并提示开关，实际: %v", err)
	}
	if _, err := ParseConfig(append([]string{"-bot", "http://bot.example.com/agent", "-allow-insecure-http"}, base...), "dev"); err != nil {
		t.Fatalf("显式 -allow-insecure-http 后应允许: %v", err)
	}

	// 回环与内网地址使用明文 HTTP 始终允许。
	for _, endpoint := range []string{
		"http://127.0.0.1:8080/agent",
		"http://[::1]:8080/agent",
		"http://localhost:8080/agent",
		"http://192.168.1.10:8080/agent",
		"http://10.0.0.5/agent",
	} {
		if _, err := ParseConfig(append([]string{"-bot", endpoint}, base...), "dev"); err != nil {
			t.Errorf("回环/内网明文 HTTP 应允许 %q: %v", endpoint, err)
		}
	}

	// 空白、换行、引号、反斜杠、反引号与控制字符一律拒绝（即使是 HTTPS）。
	for _, endpoint := range []string{
		"https://bot.example.com/agent path",
		"https://bot.example.com/agent\n",
		"https://bot.example.com/a\"b",
		"https://bot.example.com/a'b",
		"https://bot.example.com/a`b",
		"https://bot.example.com/a\\b",
		"https://bot.example.com/a\x01b",
		"https://bot.example.com/a\tb",
	} {
		if _, err := ParseConfig(append([]string{"-bot", endpoint}, base...), "dev"); err == nil {
			t.Errorf("非法 -bot 应被拒绝: %q", endpoint)
		}
	}
}
