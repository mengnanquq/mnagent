package main

import "strings"

// buildDefaultMediaScripts 返回基于 RegionRestrictionCheck 规则优化的主流流媒体与 AI 解锁轻量 JS 脚本集。
// 该脚本集在每一个代理节点建立的网络连接隧道中运行，为每个节点生成精确的解锁与拓扑矩阵。
func buildDefaultMediaScripts() []slaveScript {
	return []slaveScript{
		{
			// 快速双栈出口 IP 与 Geo 探测（优先 IPv4，纯 IPv6 快速回退，单次超时收敛为 1500ms）
			ID:   "ip_fast",
			Type: "ip",
			Content: `function ip_resolve() {
    var urls = ["https://1.1.1.1/cdn-cgi/trace", "https://[2606:4700:4700::1111]/cdn-cgi/trace"];
    for (var i = 0; i < urls.length; i++) {
        var content = (get(fetch(urls[i], {
            headers: {'User-Agent': 'Mozilla/5.0'},
            retry: 1,
            timeout: 1500
        }), "body") || "").trim();
        var m = content.match(/ip=(\S+)/);
        if (m && m[1]) return [m[1].trim()];
    }
    return [];
}
function handler(ip) {
    var isv6 = ip.indexOf(":") >= 0;
    var url = isv6 ? ("https://ipv6.ipleak.net/json/" + ip) : ("https://ipv4.ipleak.net/json/" + ip);
    var content = fetch(url, {
        headers: {'User-Agent': 'Mozilla/5.0'},
        retry: 1,
        timeout: 2000
    });
    var ret = safeParse(get(content, "body"));
    return {
        "ip": get(ret, "ip", ""),
        "isp": get(ret, "isp_name", ""),
        "organization": get(ret, "isp_name", ""),
        "latitude": get(ret, "latitude", 0),
        "longitude": get(ret, "longitude", 0),
        "asn": parseInt(get(ret, "as_number", 0), 10) || 0,
        "asn_organization": get(ret, "isp_name", ""),
        "timezone": get(ret, "time_zone", ""),
        "region": get(ret, "region_name", ""),
        "city": get(ret, "city_name", ""),
        "country": get(ret, "country_name", ""),
        "country_code": get(ret, "country_code", "")
    };
}`,
			TimeoutMillis: 2500,
		},
		{
			// 1. YouTube Premium (对齐 check.sh: MediaUnlockTest_YouTube_Premium)
			ID:   "youtube",
			Type: "media",
			Content: `function handler() {
    var res = fetch("https://www.youtube.com/premium", {
        headers: {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125.0.0.0 Safari/537.36', 'Accept-Language':'en-US,en;q=0.9'},
        timeout: 2500
    });
    if (!res || !res.body) return { text: "超时", color: "#f87171" };
    if (res.body.indexOf("www.google.cn") >= 0) return { text: "送中 (CN)", color: "#f87171" };
    if (res.body.indexOf("Premium is not available in your country") >= 0) return { text: "不支持", color: "#f87171" };
    var m = res.body.match(/"INNERTUBE_CONTEXT_GL"\s*:\s*"([A-Z]{2})"/);
    if (!m) m = res.body.match(/"countryCode"\s*:\s*"([A-Z]{2})"/);
    if (m && m[1]) return { text: "支持 (" + m[1] + ")", color: "#34d399" };
    if (res.body.indexOf("ad-free") >= 0 || res.body.indexOf("Try it free") >= 0) return { text: "支持", color: "#34d399" };
    return { text: "支持", color: "#34d399" };
}`,
			TimeoutMillis: 3000,
		},
		{
			// 2. Netflix (对齐 check.sh: MediaUnlockTest_Netflix)
			ID:   "netflix",
			Type: "media",
			Content: `function handler() {
    var h = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125.0.0.0 Safari/537.36', 'Accept-Language':'en-US,en;q=0.9'};
    var res1 = fetch("https://www.netflix.com/title/81280792", { headers: h, noRedir: true, timeout: 2500 });
    var res2 = fetch("https://www.netflix.com/title/70143836", { headers: h, noRedir: true, timeout: 2500 });
    if (!res1 && !res2) return { text: "超时", color: "#f87171" };
    var b1 = (res1 && res1.body) || "";
    var b2 = (res2 && res2.body) || "";
    var ohNo1 = b1.indexOf("Oh no!") >= 0 || (res1 && res1.statusCode === 404);
    var ohNo2 = b2.indexOf("Oh no!") >= 0 || (res2 && res2.statusCode === 404);
    if (ohNo1 && ohNo2) {
        if (b1.indexOf("netflix.com") >= 0 || (res1 && res1.statusCode === 200)) return { text: "仅自制剧", color: "#fbbf24" };
        return { text: "不可用", color: "#f87171" };
    }
    var m = b1.match(/"countryName"\s*:\s*"([^"]+)"/);
    if (!m) m = b1.match(/"id"\s*:\s*"([A-Z]{2})"/);
    if (m && m[1]) return { text: "原生解锁 (" + m[1] + ")", color: "#34d399" };
    return { text: "原生解锁", color: "#34d399" };
}`,
			TimeoutMillis: 3000,
		},
		{
			// 3. Disney+ (对齐 check.sh: MediaUnlockTest_DisneyPlus)
			ID:   "disney",
			Type: "media",
			Content: `function handler() {
    var res = fetch("https://www.disneyplus.com/", {
        headers: {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125.0.0.0 Safari/537.36'},
        noRedir: true,
        timeout: 2500
    });
    if (!res) return { text: "超时", color: "#f87171" };
    var loc = get(res, "headers.Location", "");
    if (loc.indexOf("preview") >= 0 || loc.indexOf("unavailable") >= 0) return { text: "不可用", color: "#f87171" };
    var m = loc.match(/\/([a-z]{2})-/i);
    if (m && m[1]) return { text: "解锁 (" + m[1].toUpperCase() + ")", color: "#34d399" };
    if (res.statusCode === 200 || res.statusCode === 301 || res.statusCode === 302) return { text: "解锁", color: "#34d399" };
    return { text: "不可用", color: "#f87171" };
}`,
			TimeoutMillis: 3000,
		},
		{
			// 4. Amazon Prime Video (对齐 check.sh: MediaUnlockTest_PrimeVideo)
			ID:   "primevideo",
			Type: "media",
			Content: `function handler() {
    var res = fetch("https://www.primevideo.com", {
        headers: {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125.0.0.0 Safari/537.36'},
        timeout: 2500
    });
    if (!res || !res.body) return { text: "超时", color: "#f87171" };
    if (res.body.indexOf("isServiceRestricted") >= 0) return { text: "不可用", color: "#f87171" };
    var m = res.body.match(/"currentTerritory"\s*:\s*"([^"]+)"/);
    if (m && m[1]) return { text: "支持 (" + m[1] + ")", color: "#34d399" };
    return { text: "支持", color: "#34d399" };
}`,
			TimeoutMillis: 3000,
		},
		{
			// 5. Spotify 注册支持 (对齐 check.sh: MediaUnlockTest_Spotify)
			ID:   "spotify",
			Type: "media",
			Content: `function handler() {
    var res = fetch("https://spclient.wg.spotify.com/signup/public/v1/account", {
        method: 'POST',
        headers: {
            'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125.0.0.0 Safari/537.36',
            'Accept-Language':'en',
            'Content-Type':'application/x-www-form-urlencoded'
        },
        body: "birth_day=11&birth_month=11&birth_year=2000&gender=male&iagree=1&key=a1e486e2729f46d6bb368d6b2bcda326&platform=www",
        timeout: 2500
    });
    if (!res || !res.body) return { text: "超时", color: "#f87171" };
    var d = safeParse(res.body);
    if (d && (d.status === 311 || (d.is_country_launched && d.country))) return { text: "支持 (" + (d.country || "") + ")", color: "#34d399" };
    if (d && (d.status === 320 || d.status === 120 || d.is_country_launched === false)) return { text: "不可用", color: "#f87171" };
    return { text: "不可用", color: "#f87171" };
}`,
			TimeoutMillis: 3000,
		},
		{
			// 6. ChatGPT (OpenAI) (对齐 check.sh: WebTest_OpenAI)
			ID:   "openai",
			Type: "media",
			Content: `function handler() {
    var res1 = fetch("https://api.openai.com/compliance/cookie_requirements", { timeout: 2000 });
    if (res1 && res1.body && res1.body.indexOf("unsupported_country") >= 0) return { text: "地区受限", color: "#f87171" };
    var res2 = fetch("https://ios.chat.openai.com/", { timeout: 2500 });
    if (!res2) return { text: "超时", color: "#f87171" };
    if (res2.body && res2.body.indexOf("VPN") >= 0) return { text: "IP封锁(VPN)", color: "#f87171" };
    if (res2.statusCode === 200 || res2.statusCode === 404 || res2.statusCode === 403) return { text: "支持", color: "#34d399" };
    return { text: "支持", color: "#34d399" };
}`,
			TimeoutMillis: 3000,
		},
		{
			// 7. Claude (Anthropic) (对齐 check.sh: WebTest_Claude)
			ID:   "claude",
			Type: "media",
			Content: `function handler() {
    var res = fetch("https://claude.ai/login", {
        headers: {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125.0.0.0 Safari/537.36'},
        noRedir: true,
        timeout: 2500
    });
    if (!res) return { text: "超时", color: "#f87171" };
    var loc = get(res, "headers.Location", "");
    if (loc.indexOf("app-unavailable-in-region") >= 0 || loc.indexOf("unavailable") >= 0) return { text: "不可用", color: "#f87171" };
    return { text: "支持", color: "#34d399" };
}`,
			TimeoutMillis: 3000,
		},
		{
			// 8. Google Gemini (对齐 check.sh: WebTest_Gemini)
			ID:   "gemini",
			Type: "media",
			Content: `function handler() {
    var res = fetch("https://gemini.google.com/", {
        headers: {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125.0.0.0 Safari/537.36'},
        timeout: 2500
    });
    if (!res || !res.body) return { text: "超时", color: "#f87171" };
    var m = res.body.match(/,2,1,200,"([A-Z]{3})"/);
    if (m && m[1]) return { text: "支持 (" + m[1] + ")", color: "#34d399" };
    if (res.body.indexOf("45631641,null,true") >= 0) return { text: "支持", color: "#34d399" };
    return { text: "不可用", color: "#f87171" };
}`,
			TimeoutMillis: 3000,
		},
		{
			// 9. 巴哈姆特动画疯 (对齐 check.sh: MediaUnlockTest_BahamutAnime)
			ID:   "bahamut",
			Type: "media",
			Content: `function handler() {
    var resDev = fetch("https://ani.gamer.com.tw/ajax/getdeviceid.php", { timeout: 2000 });
    var devObj = safeParse(get(resDev, "body", ""));
    var devId = get(devObj, "deviceid", "");
    var res = fetch("https://ani.gamer.com.tw/ajax/token.php?adID=89422&sn=37783&device=" + devId, { timeout: 2500 });
    if (res && res.body && res.body.indexOf("animeSn") >= 0) return { text: "解锁 (TW)", color: "#34d399" };
    var resHome = fetch("https://ani.gamer.com.tw/", { timeout: 2000 });
    var m = (get(resHome, "body", "")).match(/data-geo="([^"]+)"/);
    if (m && m[1] === "TW") return { text: "解锁 (TW)", color: "#34d399" };
    return { text: "不可用", color: "#f87171" };
}`,
			TimeoutMillis: 3000,
		},
		{
			// 10. 哔哩哔哩港澳台与台湾限定 (对齐 check.sh: MediaUnlockTest_BilibiliHKMCTW & TW)
			ID:   "bilibili",
			Type: "media",
			Content: `function handler() {
    var res1 = fetch("https://api.bilibili.com/pgc/player/web/playurl?avid=18281381&cid=29892777&qn=0&type=&otype=json&ep_id=183799&fourk=1", { timeout: 2500 });
    var d1 = safeParse(get(res1, "body", ""));
    if (d1 && d1.code === 0) return { text: "解锁 (港澳台)", color: "#34d399" };
    var res2 = fetch("https://api.bilibili.com/pgc/player/web/playurl?avid=50762638&cid=100279344&qn=0&type=&otype=json&ep_id=268176&fourk=1", { timeout: 2500 });
    var d2 = safeParse(get(res2, "body", ""));
    if (d2 && d2.code === 0) return { text: "解锁 (台湾)", color: "#34d399" };
    return { text: "大陆受限", color: "#fbbf24" };
}`,
			TimeoutMillis: 3000,
		},
		{
			// 11. TikTok
			ID:   "tiktok",
			Type: "media",
			Content: `function handler() {
    var res = fetch("https://www.tiktok.com", { headers: {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125.0.0.0 Safari/537.36'}, timeout: 2500 });
    if (!res || !res.body) return { text: "超时", color: "#f87171" };
    if (res.statusCode === 200) {
        var idx = res.body.indexOf('"region":');
        if (idx > 0) {
            var r = res.body.substring(idx).split('"')[3];
            if (r) return { text: "解锁 (" + r + ")", color: "#34d399" };
        }
        return { text: "解锁", color: "#34d399" };
    }
    return { text: "失败", color: "#f87171" };
}`,
			TimeoutMillis: 3000,
		},
		{
			// 12. 维基百科可编辑性 (对齐 check.sh: WebTest_Wikipedia_Editable)
			ID:   "wikipedia",
			Type: "media",
			Content: `function handler() {
    var res = fetch("https://zh.wikipedia.org/w/index.php?title=Wikipedia:WikiProject_on_open_proxies&action=edit", { headers: {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125.0.0.0 Safari/537.36'}, timeout: 2500 });
    if (!res || !res.body) return { text: "超时", color: "#f87171" };
    if (res.body.indexOf("This IP address has been") > 0) return { text: "禁止编辑", color: "#f87171" };
    if (res.statusCode === 200) return { text: "允许编辑", color: "#34d399" };
    return { text: "不可用", color: "#f87171" };
}`,
			TimeoutMillis: 3000,
		},
	}
}

// mapScriptKey 将测试脚本名称映射为标准显示名称。
func mapScriptKey(key string) string {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "youtube":
		return "YouTube"
	case "netflix":
		return "Netflix"
	case "disney":
		return "Disney+"
	case "primevideo", "prime_video":
		return "Prime Video"
	case "openai":
		return "OpenAI"
	case "claude":
		return "Claude"
	case "gemini", "google_gemini":
		return "Google Gemini"
	case "spotify":
		return "Spotify"
	case "bahamut":
		return "动画疯"
	case "bilibili":
		return "Bilibili"
	case "tiktok":
		return "TikTok"
	case "wikipedia":
		return "维基百科"
	default:
		return key
	}
}
