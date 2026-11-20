package updater

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// TokenProvider 提供接入令牌；*config.TokenSource 直接满足该接口。
// 用接口而不是 *config.TokenSource 是为了避免 updater 反向依赖 config
// （config → updater 已存在，直接引用会形成依赖环）。
type TokenProvider interface {
	Get() (string, error)
}

// botDigestTimeout 是单次服务端代取校验值的超时。
// 服务端可能正在回源 GitHub，比普通 API 略宽；变量便于测试缩短。
var botDigestTimeout = 10 * time.Second

// crossCheckTimeout 是服务端代取成功后，单次直连 .sha256 做交叉校验的窗口。
var crossCheckTimeout = 5 * time.Second

// maxBotDigestBody 限制服务端代取响应体大小：响应只有一份 SHA-256，8KiB 足够。
const maxBotDigestBody = 8 << 10

// errChecksumMismatch 表示服务端代取的校验值与直连 .sha256 不一致。
// 这是 fail-closed 的终止条件：既不能采用任一来源，也不能继续走后续兜底。
var errChecksumMismatch = errors.New("服务端代取校验值与直连 .sha256 不一致")

// BotDigestClient 调用 mengnanbot 的 /agent/release-digest 接口代取 Release
// 资产的 SHA-256。服务端部署在可稳定访问 GitHub 的海外主机上，国内探针据此
// 绕开直连 github.com/api.github.com 的失败或限流。
//
// 只尝试一次（不做重试），由调用方决定回退到直连来源。
type BotDigestClient struct {
	// BaseURL 是 agent 端点基地址，例如 https://mnbot.example.org/agent。
	BaseURL string
	// Token 提供接入令牌；为 nil 时视为跳过代取。
	Token TokenProvider
	// Client 是可选的 HTTP 客户端；为 nil 时使用 http.DefaultClient。
	Client *http.Client
	// Version 用于 User-Agent / X-Agent-Version，与 client.doWith 保持一致。
	Version string
}

// Fetch 请求服务端代取 repo 的 tag 版本中 asset 的 SHA-256。
// 返回 64 位小写 hex；任何失败（含拿不到令牌）都返回错误，由调用方静默回退。
func (c *BotDigestClient) Fetch(ctx context.Context, repo, tag, asset string) (string, error) {
	if c == nil {
		return "", errors.New("未配置服务端代取客户端")
	}
	base := strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")
	if base == "" {
		return "", errors.New("服务端代取客户端缺少端点地址")
	}
	if c.Token == nil {
		return "", errors.New("缺少令牌，跳过服务端代取")
	}
	token, err := c.Token.Get()
	if err != nil {
		return "", fmt.Errorf("读取令牌失败，跳过服务端代取：%w", err)
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return "", errors.New("令牌为空，跳过服务端代取")
	}

	ctx, cancel := context.WithTimeout(ctx, botDigestTimeout)
	defer cancel()

	query := url.Values{}
	query.Set("repo", repo)
	query.Set("tag", tag)
	query.Set("asset", asset)
	// 令牌只放 Authorization 头：服务端明确不接受 query 中的 token，
	// 避免令牌出现在代理/访问日志里。
	endpoint := base + "/release-digest?" + query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "mnagent/"+c.Version)
	req.Header.Set("X-Agent-Version", c.Version)

	cli := c.Client
	if cli == nil {
		cli = http.DefaultClient
	}
	resp, err := cli.Do(req)
	if err != nil {
		return "", fmt.Errorf("请求服务端代取接口失败：%w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBotDigestBody+1))
	if err != nil {
		return "", fmt.Errorf("读取服务端代取响应失败：%w", err)
	}
	if len(body) > maxBotDigestBody {
		return "", fmt.Errorf("服务端代取响应体超过 %d 字节（HTTP %d）", maxBotDigestBody, resp.StatusCode)
	}

	var data struct {
		OK     bool   `json:"ok"`
		SHA256 string `json:"sha256"`
		Code   string `json:"code"`
		Error  string `json:"error"`
	}
	parseErr := json.Unmarshal(body, &data)

	if resp.StatusCode != http.StatusOK {
		code := strings.TrimSpace(data.Code)
		if code == "" {
			code = "http_" + strconv.Itoa(resp.StatusCode)
		}
		msg := strings.TrimSpace(data.Error)
		if msg == "" {
			msg = strings.TrimSpace(string(body))
			if len(msg) > 120 {
				msg = msg[:120] + "…"
			}
		}
		return "", fmt.Errorf("服务端代取返回 HTTP %d（code=%s）：%s", resp.StatusCode, code, msg)
	}
	if parseErr != nil {
		return "", fmt.Errorf("解析服务端代取响应失败（HTTP %d）：%w", resp.StatusCode, parseErr)
	}
	if !data.OK {
		code := strings.TrimSpace(data.Code)
		if code == "" {
			code = "unknown"
		}
		return "", fmt.Errorf("服务端代取失败（HTTP %d，code=%s）：%s", resp.StatusCode, code, strings.TrimSpace(data.Error))
	}
	sum := strings.ToLower(strings.TrimSpace(data.SHA256))
	if !sha256HexPattern.MatchString(sum) {
		return "", fmt.Errorf("服务端代取返回的 SHA-256 非法（HTTP %d）：%q", resp.StatusCode, data.SHA256)
	}
	return sum, nil
}
