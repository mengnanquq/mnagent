package config

import (
	"path/filepath"
	"testing"
)

// TestParseConfigBotChecksumTrust 验证服务端代取校验值的端点信任判定：
// https 可信；http 仅回环/内网可信；公网明文即使 -allow-insecure-http 也不可信；
// -no-bot-checksum 一律禁用。
func TestParseConfigBotChecksumTrust(t *testing.T) {
	base := []string{"-token", "t", "-nexttrace", "/bin/echo"}
	cases := []struct {
		name         string
		args         []string
		wantTrusted  bool
		wantDisabled bool
	}{
		{"https", []string{"-bot", "https://bot.example.com/agent"}, true, false},
		{"http 回环", []string{"-bot", "http://127.0.0.1:8080/agent"}, true, false},
		{"http IPv6 回环", []string{"-bot", "http://[::1]:8080/agent"}, true, false},
		{"http 内网", []string{"-bot", "http://192.168.1.10:8080/agent"}, true, false},
		{"公网 http 加开关仍不可信", []string{"-bot", "http://bot.example.com/agent", "-allow-insecure-http"}, false, false},
		{"显式禁用", []string{"-bot", "https://bot.example.com/agent", "-no-bot-checksum"}, false, true},
		{"回环加显式禁用", []string{"-bot", "http://127.0.0.1:8080/agent", "-no-bot-checksum"}, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ParseConfig(append(append([]string(nil), tc.args...), base...), "dev")
			if err != nil {
				t.Fatalf("解析失败: %v", err)
			}
			if cfg.BotChecksumTrusted != tc.wantTrusted {
				t.Fatalf("BotChecksumTrusted = %v，期望 %v", cfg.BotChecksumTrusted, tc.wantTrusted)
			}
			if cfg.NoBotChecksum != tc.wantDisabled {
				t.Fatalf("NoBotChecksum = %v，期望 %v", cfg.NoBotChecksum, tc.wantDisabled)
			}
		})
	}

	// 更新 CLI 模式没有 -bot 时不可启用代取。
	cfg, err := ParseConfig([]string{"-check-update", "-nexttrace", "/bin/echo"}, "dev")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BotChecksumTrusted {
		t.Fatal("没有 -bot 时不应信任服务端代取")
	}
}

// TestBotEndpointTrusted 直接覆盖端点信任判定的边界输入。
func TestBotEndpointTrusted(t *testing.T) {
	cases := map[string]bool{
		"https://bot.example.com/agent": true,
		"HTTPS://BOT.example.com":       true,
		"http://localhost:8080/agent":   true,
		"http://10.0.0.5/agent":         true,
		"http://bot.example.com/agent":  false,
		"http://10.example.com/agent":   false,
		"ftp://bot.example.com/agent":   false,
		"not-a-url":                     false,
		"":                              false,
	}
	for raw, want := range cases {
		if got := botEndpointTrusted(raw); got != want {
			t.Errorf("botEndpointTrusted(%q) = %v，期望 %v", raw, got, want)
		}
	}
}

// TestParseConfigUpdateCLITokenSource 验证更新类 CLI 带 -bot 与令牌时会构造令牌源，
// 让服务端代取校验值在 CLI 路径同样可用；没有令牌时静默忽略（Tokens 为 nil），
// 不能让 CLI 因为缺令牌直接报错退出。
func TestParseConfigUpdateCLITokenSource(t *testing.T) {
	t.Run("带 -token", func(t *testing.T) {
		cfg, err := ParseConfig([]string{"-apply-update", "latest", "-bot", "https://x/agent", "-token", "t"}, "dev")
		if err != nil {
			t.Fatalf("解析失败: %v", err)
		}
		if cfg.Tokens == nil {
			t.Fatal("更新类 CLI 带 -token 时应构造令牌源（代取不能恒为 nil）")
		}
		if got, err := cfg.Tokens.Get(); err != nil || got != "t" {
			t.Fatalf("令牌读取异常: got=%q err=%v", got, err)
		}
		if !cfg.BotChecksumTrusted {
			t.Fatal("https 端点 + 令牌时 BotChecksumTrusted 应为 true")
		}
	})

	t.Run("环境变量令牌", func(t *testing.T) {
		t.Setenv("MNAGENT_TOKEN", "env-tok")
		cfg, err := ParseConfig([]string{"-check-update", "-bot", "https://x/agent"}, "dev")
		if err != nil {
			t.Fatalf("解析失败: %v", err)
		}
		if cfg.Tokens == nil {
			t.Fatal("更新类 CLI 带环境变量令牌时应构造令牌源")
		}
		if got, err := cfg.Tokens.Get(); err != nil || got != "env-tok" {
			t.Fatalf("令牌读取异常: got=%q err=%v", got, err)
		}
	})

	t.Run("没有令牌不报错", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "missing-token")
		cfg, err := ParseConfig([]string{"-apply-update", "latest", "-bot", "https://x/agent", "-token-file", missing}, "dev")
		if err != nil {
			t.Fatalf("更新类 CLI 缺少令牌时不应报错: %v", err)
		}
		if cfg.Tokens != nil {
			t.Fatalf("没有可用令牌时 Tokens 应为 nil，实际 %+v", cfg.Tokens)
		}
		if !cfg.BotChecksumTrusted {
			t.Fatal("端点信任判定不应受令牌是否可用影响")
		}
	})

	t.Run("无 -bot 不尝试令牌", func(t *testing.T) {
		cfg, err := ParseConfig([]string{"-apply-update", "latest"}, "dev")
		if err != nil {
			t.Fatalf("解析失败: %v", err)
		}
		if cfg.Tokens != nil {
			t.Fatalf("没有 -bot 时不应构造令牌源，实际 %+v", cfg.Tokens)
		}
		if cfg.BotChecksumTrusted {
			t.Fatal("没有 -bot 时不应信任服务端代取")
		}
	})
}
