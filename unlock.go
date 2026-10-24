package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	defaultBrowserUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
)

var (
	reNetflixCountry = regexp.MustCompile(`"(?:countryName|id)":"([^"]+)"`)
	reYouTubeRegion  = regexp.MustCompile(`"(?:INNERTUBE_CONTEXT_GL|countryCode)":"([A-Z]{2})"`)
	reGeminiRegion   = regexp.MustCompile(`,2,1,200,"([A-Z]{3})"`)
	reBahamutGeo     = regexp.MustCompile(`data-geo="([^"]+)"`)
)

// UnlockItem 记录单个平台或服务的解锁测试结果。
type UnlockItem struct {
	Name     string `json:"name"`
	Category string `json:"category"` // "跨国流媒体" | "AI与知识服务" | "华语流媒体"
	Status   string `json:"status"`   // "Yes" | "No" | "Originals Only" | "Failed"
	Region   string `json:"region,omitempty"`
	Details  string `json:"details,omitempty"`
}

// UnlockReport 是全量流媒体与 AI 服务解锁的结构化结果。
type UnlockReport struct {
	IP       string       `json:"ip,omitempty"`
	Country  string       `json:"country,omitempty"`
	ISP      string       `json:"isp,omitempty"`
	Items    []UnlockItem `json:"items"`
	Duration float64      `json:"duration_ms"`
}

// Format 将解锁报告格式化为适合 Telegram 机器人和终端展示的高对比度排版文本。
func (r UnlockReport) Format() string {
	var b strings.Builder
	b.WriteString("⚡ 流媒体与 AI 解锁检测报告 (RegionRestrictionCheck)\n")
	if r.IP != "" || r.Country != "" || r.ISP != "" {
		parts := make([]string, 0, 3)
		if r.IP != "" {
			parts = append(parts, r.IP)
		}
		if r.Country != "" {
			parts = append(parts, r.Country)
		}
		if r.ISP != "" {
			parts = append(parts, r.ISP)
		}
		b.WriteString(fmt.Sprintf("• 出口网络: %s\n", strings.Join(parts, " · ")))
	}
	b.WriteString("----------------------------------------------------------------\n")

	categories := []string{"跨国流媒体", "华语流媒体", "AI与知识服务"}
	for _, cat := range categories {
		var catItems []UnlockItem
		for _, it := range r.Items {
			if it.Category == cat {
				catItems = append(catItems, it)
			}
		}
		if len(catItems) == 0 {
			continue
		}
		b.WriteString(fmt.Sprintf("[%s]\n", cat))
		for _, it := range catItems {
			icon := "⚪️"
			statusText := it.Status
			switch it.Status {
			case "Yes":
				icon = "🟢"
				statusText = "已解锁"
				if it.Region != "" {
					statusText = fmt.Sprintf("已解锁 (Region: %s)", it.Region)
				}
			case "Originals Only":
				icon = "🟡"
				statusText = "仅支持自制剧"
			case "No":
				icon = "🔴"
				statusText = "未解锁 / 不支持"
			case "Failed":
				icon = "⚠️"
				statusText = "检测受阻 (网络超时或风控拦截)"
			}
			if it.Details != "" && it.Status != "Yes" {
				statusText += fmt.Sprintf(" (%s)", it.Details)
			}
			b.WriteString(fmt.Sprintf("  • %-20s %s %s\n", it.Name+":", icon, statusText))
		}
		b.WriteString("\n")
	}

	if r.Duration > 0 {
		b.WriteString(fmt.Sprintf("• 总计耗时: %.2f 秒\n", r.Duration/1000))
	}
	b.WriteString("================================================================")
	return strings.TrimSpace(b.String())
}

// checkRegionRestrictions 并发执行基于 RegionRestrictionCheck 规则的解锁检测。
func checkRegionRestrictions(ctx context.Context) (UnlockReport, error) {
	start := time.Now()
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	var report UnlockReport
	var mu sync.Mutex
	var wg sync.WaitGroup

	// 出口 IP 与归属查询
	wg.Add(1)
	go func() {
		defer wg.Done()
		if ip, geo := queryIPGeo(""); ip != "" {
			mu.Lock()
			report.IP = ip
			report.ISP = geo
			mu.Unlock()
		}
	}()

	addItem := func(item UnlockItem) {
		mu.Lock()
		defer mu.Unlock()
		report.Items = append(report.Items, item)
	}

	tests := []func(context.Context, *http.Client) UnlockItem{
		checkNetflix,
		checkDisneyPlus,
		checkYouTubePremium,
		checkSpotify,
		checkChatGPT,
		checkClaude,
		checkGemini,
		checkBahamut,
		checkBilibiliHKMO,
		checkBilibiliTW,
		checkWikipedia,
	}

	for _, fn := range tests {
		wg.Add(1)
		go func(testFn func(context.Context, *http.Client) UnlockItem) {
			defer wg.Done()
			addItem(testFn(ctx, client))
		}(fn)
	}

	wg.Wait()
	report.Duration = float64(time.Since(start).Microseconds()) / 1000

	// 保持相对固定的排版顺序
	order := map[string]int{
		"Netflix":            1,
		"Disney+":            2,
		"YouTube Premium":    3,
		"Spotify 注册":         4,
		"动画疯 (巴哈姆特)":         5,
		"哔哩哔哩 (港澳台限定)":       6,
		"哔哩哔哩 (台湾限定)":        7,
		"ChatGPT (OpenAI)":   8,
		"Claude (Anthropic)": 9,
		"Google Gemini":      10,
		"维基百科 (可编辑性)":        11,
	}
	mu.Lock()
	sorted := make([]UnlockItem, len(report.Items))
	copy(sorted, report.Items)
	for i := 0; i < len(sorted)-1; i++ {
		for j := i + 1; j < len(sorted); j++ {
			if order[sorted[i].Name] > order[sorted[j].Name] {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	report.Items = sorted
	mu.Unlock()

	return report, nil
}

// 1. Netflix
func checkNetflix(ctx context.Context, client *http.Client) UnlockItem {
	item := UnlockItem{Name: "Netflix", Category: "跨国流媒体"}
	// 乐高幻影忍者 (81280792) + 绝命毒师 (70143836)
	body1, code1 := fetchBodyAndStatus(ctx, client, "https://www.netflix.com/title/81280792", nil)
	body2, _ := fetchBodyAndStatus(ctx, client, "https://www.netflix.com/title/70143836", nil)

	if code1 == 0 {
		item.Status = "Failed"
		return item
	}

	hasOhNo1 := strings.Contains(body1, "Oh no!") || strings.Contains(body1, "Page Not Found")
	hasOhNo2 := strings.Contains(body2, "Oh no!") || strings.Contains(body2, "Page Not Found")

	if hasOhNo1 && hasOhNo2 {
		if strings.Contains(body1, "netflix.com") {
			item.Status = "Originals Only"
			return item
		}
		item.Status = "No"
		return item
	}

	if !hasOhNo1 || !hasOhNo2 {
		item.Status = "Yes"
		if m := reNetflixCountry.FindStringSubmatch(body1); len(m) >= 2 {
			item.Region = m[1]
		}
		return item
	}

	item.Status = "No"
	return item
}

// 2. Disney+
func checkDisneyPlus(ctx context.Context, client *http.Client) UnlockItem {
	item := UnlockItem{Name: "Disney+", Category: "跨国流媒体"}
	noRedirClient := &http.Client{
		Timeout: 4 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.disneyplus.com/", nil)
	if err != nil {
		item.Status = "Failed"
		return item
	}
	req.Header.Set("User-Agent", defaultBrowserUA)
	resp, err := noRedirClient.Do(req)
	if err != nil {
		item.Status = "Failed"
		return item
	}
	defer resp.Body.Close()

	loc := resp.Header.Get("Location")
	if strings.Contains(loc, "preview") || strings.Contains(loc, "unavailable") {
		item.Status = "No"
		return item
	}
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently {
		item.Status = "Yes"
		if loc != "" {
			parts := strings.Split(strings.Trim(loc, "/"), "/")
			if len(parts) > 0 {
				last := parts[len(parts)-1]
				if len(last) == 2 {
					item.Region = strings.ToUpper(last)
				}
			}
		}
		return item
	}

	item.Status = "No"
	return item
}

// 3. YouTube Premium
func checkYouTubePremium(ctx context.Context, client *http.Client) UnlockItem {
	item := UnlockItem{Name: "YouTube Premium", Category: "跨国流媒体"}
	body, code := fetchBodyAndStatus(ctx, client, "https://www.youtube.com/premium", map[string]string{
		"Accept-Language": "en-US,en;q=0.9",
	})
	if code == 0 {
		item.Status = "Failed"
		return item
	}

	if strings.Contains(body, "Premium is not available in your country") || strings.Contains(body, "www.google.cn") {
		item.Status = "No"
		return item
	}

	if m := reYouTubeRegion.FindStringSubmatch(body); len(m) >= 2 {
		item.Region = m[1]
	}

	if strings.Contains(body, "ad-free") || strings.Contains(body, "Try it free") || strings.Contains(body, "Sign up") || item.Region != "" {
		item.Status = "Yes"
		return item
	}

	item.Status = "No"
	return item
}

// 4. Spotify 注册
func checkSpotify(ctx context.Context, client *http.Client) UnlockItem {
	item := UnlockItem{Name: "Spotify 注册", Category: "跨国流媒体"}
	formData := url.Values{
		"birth_day":   {"11"},
		"birth_month": {"11"},
		"birth_year":  {"2000"},
		"gender":      {"male"},
		"iagree":      {"1"},
		"key":         {"a1e486e2729f46d6bb368d6b2bcda326"},
		"platform":    {"www"},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://spclient.wg.spotify.com/signup/public/v1/account", strings.NewReader(formData.Encode()))
	if err != nil {
		item.Status = "Failed"
		return item
	}
	req.Header.Set("User-Agent", defaultBrowserUA)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept-Language", "en")

	resp, err := client.Do(req)
	if err != nil {
		item.Status = "Failed"
		return item
	}
	defer resp.Body.Close()

	var data struct {
		Status            int    `json:"status"`
		Country           string `json:"country"`
		IsCountryLaunched bool   `json:"is_country_launched"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&data); err != nil {
		item.Status = "Failed"
		return item
	}

	if data.Status == 311 || (data.IsCountryLaunched && data.Country != "") {
		item.Status = "Yes"
		item.Region = data.Country
		return item
	}
	if data.Status == 320 || data.Status == 120 || !data.IsCountryLaunched {
		item.Status = "No"
		return item
	}

	item.Status = "No"
	return item
}

// 5. ChatGPT (OpenAI)
func checkChatGPT(ctx context.Context, client *http.Client) UnlockItem {
	item := UnlockItem{Name: "ChatGPT (OpenAI)", Category: "AI与知识服务"}
	body1, code1 := fetchBodyAndStatus(ctx, client, "https://api.openai.com/compliance/cookie_requirements", map[string]string{
		"Authority": "api.openai.com",
		"Referer":   "https://platform.openai.com/",
	})
	body2, code2 := fetchBodyAndStatus(ctx, client, "https://ios.chat.openai.com/", nil)

	if code1 == 0 && code2 == 0 {
		item.Status = "Failed"
		return item
	}

	if strings.Contains(body1, "unsupported_country") || strings.Contains(body2, "VPN") {
		item.Status = "No"
		return item
	}

	if code1 == 200 || code2 == 200 || code1 == 404 || code2 == 404 {
		item.Status = "Yes"
		return item
	}

	item.Status = "No"
	return item
}

// 6. Claude (Anthropic)
func checkClaude(ctx context.Context, client *http.Client) UnlockItem {
	item := UnlockItem{Name: "Claude (Anthropic)", Category: "AI与知识服务"}
	noRedirClient := &http.Client{
		Timeout: 4 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://claude.ai/login", nil)
	if err != nil {
		item.Status = "Failed"
		return item
	}
	req.Header.Set("User-Agent", defaultBrowserUA)
	resp, err := noRedirClient.Do(req)
	if err != nil {
		item.Status = "Failed"
		return item
	}
	defer resp.Body.Close()

	loc := resp.Header.Get("Location")
	if strings.Contains(loc, "app-unavailable-in-region") || strings.Contains(loc, "unavailable") {
		item.Status = "No"
		return item
	}

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusForbidden {
		// 403 常见于 Cloudflare WAF 质询，并不表示区域不可用；只有重定向至 unavailable 才是区域封锁
		item.Status = "Yes"
		return item
	}

	item.Status = "No"
	return item
}

// 7. Google Gemini
func checkGemini(ctx context.Context, client *http.Client) UnlockItem {
	item := UnlockItem{Name: "Google Gemini", Category: "AI与知识服务"}
	body, code := fetchBodyAndStatus(ctx, client, "https://gemini.google.com/", nil)
	if code == 0 {
		item.Status = "Failed"
		return item
	}

	if m := reGeminiRegion.FindStringSubmatch(body); len(m) >= 2 {
		item.Region = m[1]
	}

	if strings.Contains(body, "45631641,null,true") || strings.Contains(body, "Bard") || item.Region != "" {
		item.Status = "Yes"
		return item
	}

	item.Status = "No"
	return item
}

// 8. Bahamut Anime (巴哈姆特动画疯)
func checkBahamut(ctx context.Context, client *http.Client) UnlockItem {
	item := UnlockItem{Name: "动画疯 (巴哈姆特)", Category: "华语流媒体"}
	bodyDev, _ := fetchBodyAndStatus(ctx, client, "https://ani.gamer.com.tw/ajax/getdeviceid.php", nil)
	var devObj struct {
		DeviceID string `json:"deviceid"`
	}
	_ = json.Unmarshal([]byte(bodyDev), &devObj)

	tokenURL := fmt.Sprintf("https://ani.gamer.com.tw/ajax/token.php?adID=89422&sn=37783&device=%s", devObj.DeviceID)
	bodyToken, _ := fetchBodyAndStatus(ctx, client, tokenURL, nil)

	if strings.Contains(bodyToken, "animeSn") {
		item.Status = "Yes"
		item.Region = "TW"
		return item
	}

	bodyHome, _ := fetchBodyAndStatus(ctx, client, "https://ani.gamer.com.tw/", nil)
	if m := reBahamutGeo.FindStringSubmatch(bodyHome); len(m) >= 2 {
		item.Region = m[1]
		if m[1] == "TW" {
			item.Status = "Yes"
			return item
		}
	}

	item.Status = "No"
	return item
}

// 9. Bilibili (港澳台限定)
func checkBilibiliHKMO(ctx context.Context, client *http.Client) UnlockItem {
	item := UnlockItem{Name: "哔哩哔哩 (港澳台限定)", Category: "华语流媒体"}
	apiURL := "https://api.bilibili.com/pgc/player/web/playurl?avid=18281381&cid=29892777&qn=0&type=&otype=json&ep_id=183799&fourk=1"
	body, code := fetchBodyAndStatus(ctx, client, apiURL, nil)
	if code == 0 {
		item.Status = "Failed"
		return item
	}

	var res struct {
		Code int `json:"code"`
	}
	if err := json.Unmarshal([]byte(body), &res); err == nil {
		if res.Code == 0 {
			item.Status = "Yes"
			return item
		}
		if res.Code == -10403 {
			item.Status = "No"
			return item
		}
	}

	item.Status = "No"
	return item
}

// 10. Bilibili (台湾限定)
func checkBilibiliTW(ctx context.Context, client *http.Client) UnlockItem {
	item := UnlockItem{Name: "哔哩哔哩 (台湾限定)", Category: "华语流媒体"}
	apiURL := "https://api.bilibili.com/pgc/player/web/playurl?avid=50762638&cid=100279344&qn=0&type=&otype=json&ep_id=268176&fourk=1"
	body, code := fetchBodyAndStatus(ctx, client, apiURL, nil)
	if code == 0 {
		item.Status = "Failed"
		return item
	}

	var res struct {
		Code int `json:"code"`
	}
	if err := json.Unmarshal([]byte(body), &res); err == nil {
		if res.Code == 0 {
			item.Status = "Yes"
			item.Region = "TW"
			return item
		}
		if res.Code == -10403 {
			item.Status = "No"
			return item
		}
	}

	item.Status = "No"
	return item
}

// 11. Wikipedia
func checkWikipedia(ctx context.Context, client *http.Client) UnlockItem {
	item := UnlockItem{Name: "维基百科 (可编辑性)", Category: "AI与知识服务"}
	body, code := fetchBodyAndStatus(ctx, client, "https://zh.wikipedia.org/w/index.php?title=Wikipedia%3A%E6%B2%99%E7%9B%92&action=edit", nil)
	if code == 0 {
		item.Status = "Failed"
		return item
	}

	if strings.Contains(body, "This IP address has been blocked") || strings.Contains(body, "Banned") || strings.Contains(body, "禁止编辑") {
		item.Status = "No"
		item.Details = "IP 段被维基百科列入封禁名单"
		return item
	}

	if strings.Contains(body, "action=\"submit\"") || strings.Contains(body, "wpSave") || code == http.StatusOK {
		item.Status = "Yes"
		return item
	}

	item.Status = "No"
	return item
}

// fetchBodyAndStatus 辅助函数：快速获取页面正文与 HTTP 响应状态码。
func fetchBodyAndStatus(ctx context.Context, client *http.Client, targetURL string, headers map[string]string) (string, int) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return "", 0
	}
	req.Header.Set("User-Agent", defaultBrowserUA)
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", 0
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	return string(data), resp.StatusCode
}
