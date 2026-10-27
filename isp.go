package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

// defaultISPProbeURLs 探测出口公网 IP 与 ISP 的端点列表（按顺序尝试）。
var defaultISPProbeURLs = []string{
	"http://ip-api.com/json/?lang=zh-CN",
	"https://myip.ipip.net/json",
	"https://ipwho.is/",
	"https://ipv4.ipleak.net/json/",
}

// detectOutboundISP 使用提供的 HTTP 客户端向公网接口查询本地出站的 ISP 运营商信息。
// 单个端点超时控制在 2.5 秒以内，探测成功立即返回；全部失败返回空字符串。
func detectOutboundISP(ctx context.Context, client *http.Client) string {
	if client == nil {
		client = &http.Client{Timeout: 3 * time.Second}
	}
	for _, rawURL := range defaultISPProbeURLs {
		if ctx.Err() != nil {
			return ""
		}
		isp := queryISPFromURL(ctx, client, rawURL)
		if isp != "" {
			return isp
		}
	}
	return ""
}

// queryISPFromURL 向单个探测源发起请求并解析 ISP。
func queryISPFromURL(ctx context.Context, client *http.Client, targetURL string) string {
	reqCtx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, targetURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (mnagent-isp-probe)")
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil || len(body) == 0 {
		return ""
	}

	// 1. ip-api.com
	if strings.Contains(targetURL, "ip-api.com") {
		var res struct {
			Status string `json:"status"`
			ISP    string `json:"isp"`
			Org    string `json:"org"`
		}
		if err := json.Unmarshal(body, &res); err == nil && res.Status == "success" {
			val := strings.TrimSpace(res.ISP)
			if val == "" {
				val = strings.TrimSpace(res.Org)
			}
			if val != "" {
				return cleanISPName(val)
			}
		}
	}

	// 2. myip.ipip.net
	if strings.Contains(targetURL, "myip.ipip.net") {
		var res struct {
			Ret  string `json:"ret"`
			Data struct {
				Location []string `json:"location"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &res); err == nil && res.Ret == "ok" {
			loc := res.Data.Location
			if len(loc) >= 5 && strings.TrimSpace(loc[4]) != "" {
				return cleanISPName(loc[4])
			}
		}
	}

	// 3. ipwho.is
	if strings.Contains(targetURL, "ipwho.is") {
		var res struct {
			Success    bool `json:"success"`
			Connection struct {
				ISP string `json:"isp"`
				Org string `json:"org"`
			} `json:"connection"`
		}
		if err := json.Unmarshal(body, &res); err == nil && res.Success {
			val := strings.TrimSpace(res.Connection.ISP)
			if val == "" {
				val = strings.TrimSpace(res.Connection.Org)
			}
			if val != "" {
				return cleanISPName(val)
			}
		}
	}

	// 4. ipleak.net
	if strings.Contains(targetURL, "ipleak.net") {
		var res struct {
			ISPName string `json:"isp_name"`
			Org     string `json:"organization"`
		}
		if err := json.Unmarshal(body, &res); err == nil {
			val := strings.TrimSpace(res.ISPName)
			if val == "" {
				val = strings.TrimSpace(res.Org)
			}
			if val != "" {
				return cleanISPName(val)
			}
		}
	}

	return ""
}

// cleanISPName 清洗规范化 ISP 名称：去除多余空白、换行与特殊字符，截断过长字符。
func cleanISPName(val string) string {
	val = strings.ReplaceAll(val, "\r", " ")
	val = strings.ReplaceAll(val, "\n", " ")
	val = strings.ReplaceAll(val, "\t", " ")
	val = strings.Join(strings.Fields(val), " ")
	runes := []rune(val)
	if len(runes) > 64 {
		val = string(runes[:64])
	}
	return strings.TrimSpace(val)
}
