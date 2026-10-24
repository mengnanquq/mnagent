package main

import "strings"

// buildDefaultMediaScripts 返回主流流媒体检测与快速 GeoIP 探测的轻量 JavaScript 脚本集。
func buildDefaultMediaScripts() []slaveScript {
	return []slaveScript{
		{
			// 覆盖 miaospeed 默认的 default_ip.js 与 default_geoip.js：
			// 优化为轻量双栈顺序探测（先取 IPv4，纯 IPv6 节点快速回退至 IPv6 Cloudflare trace），
			// 且单次超时收敛为 1500ms，既支持 IPv6 落地检测，又杜绝死节点漫长等待。
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
			ID:   "youtube",
			Type: "media",
			Content: `function handler() {
    var res = fetch("https://www.youtube.com/premium", { headers: {'User-Agent':'Mozilla/5.0'}, timeout: 2500 });
    if (!res || !res.body) return { text: "超时", color: "#f87171" };
    if (res.body.indexOf("Premium is not available in your country") > 0) return { text: "不支持", color: "#f87171" };
    var m = res.body.match(/"countryCode":"([A-Z]{2})"/);
    if (m && m[1]) return { text: "支持 (" + m[1] + ")", color: "#34d399" };
    return { text: "支持", color: "#34d399" };
}`,
			TimeoutMillis: 3000,
		},
		{
			ID:   "netflix",
			Type: "media",
			Content: `function handler() {
    var res1 = fetch("https://www.netflix.com/title/80018499", { headers: {'User-Agent':'Mozilla/5.0'}, noRedir: true, timeout: 2500 });
    if (!res1) return { text: "超时", color: "#f87171" };
    if (res1.statusCode === 200) return { text: "原生解锁", color: "#34d399" };
    var res2 = fetch("https://www.netflix.com/title/70143836", { headers: {'User-Agent':'Mozilla/5.0'}, noRedir: true, timeout: 2500 });
    if (res2 && res2.statusCode === 200) return { text: "仅自制剧", color: "#fbbf24" };
    return { text: "不可用", color: "#f87171" };
}`,
			TimeoutMillis: 3000,
		},
		{
			ID:   "disney",
			Type: "media",
			Content: `function handler() {
    var res = fetch("https://www.disneyplus.com/", { headers: {'User-Agent':'Mozilla/5.0'}, noRedir: true, timeout: 2500 });
    if (!res) return { text: "超时", color: "#f87171" };
    var loc = get(res, "headers.Location", "");
    if (loc.indexOf("preview") > 0 || loc.indexOf("unavailable") > 0) return { text: "不可用", color: "#f87171" };
    if (res.statusCode === 200 || res.statusCode === 301 || res.statusCode === 302) return { text: "解锁", color: "#34d399" };
    return { text: "不可用", color: "#f87171" };
}`,
			TimeoutMillis: 3000,
		},
		{
			ID:   "openai",
			Type: "media",
			Content: `function handler() {
    var res = fetch("https://ios.chat.openai.com/public-api/mobile/server_status/v1", { timeout: 2500 });
    if (!res) return { text: "超时", color: "#f87171" };
    if (res.statusCode === 200) return { text: "支持", color: "#34d399" };
    if (res.statusCode === 403) return { text: "封锁", color: "#f87171" };
    if (res.body && res.body.indexOf("unsupported_country") > 0) return { text: "地区受限", color: "#f87171" };
    return { text: "支持", color: "#34d399" };
}`,
			TimeoutMillis: 3000,
		},
		{
			ID:   "spotify",
			Type: "media",
			Content: `function handler() {
    var res = fetch("https://spclient.wg.spotify.com/signup/public/v1/account", { headers: {'User-Agent':'Mozilla/5.0'}, timeout: 2500 });
    if (!res) return { text: "超时", color: "#f87171" };
    if (res.statusCode === 200 || res.statusCode === 400) return { text: "支持", color: "#34d399" };
    return { text: "不可用", color: "#f87171" };
}`,
			TimeoutMillis: 3000,
		},
		{
			ID:   "claude",
			Type: "media",
			Content: `function handler() {
    var res = fetch("https://claude.ai/login", { headers: {'User-Agent':'Mozilla/5.0'}, noRedir: true, timeout: 2500 });
    if (!res) return { text: "超时", color: "#f87171" };
    var loc = get(res, "headers.Location", "");
    if (loc.indexOf("unavailable") > 0) return { text: "不可用", color: "#f87171" };
    if (res.statusCode === 200) return { text: "支持", color: "#34d399" };
    return { text: "不可用", color: "#f87171" };
}`,
			TimeoutMillis: 3000,
		},
		{
			ID:   "tiktok",
			Type: "media",
			Content: `function handler() {
    var res = fetch("https://www.tiktok.com", { headers: {'User-Agent':'Mozilla/5.0'}, timeout: 2500 });
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
			ID:   "bilibili",
			Type: "media",
			Content: `function handler() {
    var res = fetch("https://api.bilibili.com/pgc/player/web/playurl?avid=50762638&cid=100279344&qn=0&type=&otype=json&ep_id=268176", { headers: {'User-Agent':'Mozilla/5.0'}, timeout: 2500 });
    if (!res || !res.body) return { text: "超时", color: "#f87171" };
    var d = safeParse(res.body);
    if (d.code === 0 || d.message === "success") return { text: "解锁 (台湾)", color: "#34d399" };
    var res2 = fetch("https://api.bilibili.com/pgc/player/web/playurl?avid=18281381&cid=29892777&qn=0&type=&otype=json&ep_id=183799", { headers: {'User-Agent':'Mozilla/5.0'}, timeout: 2500 });
    if (res2 && res2.body) {
        var d2 = safeParse(res2.body);
        if (d2.code === 0 || d2.message === "success") return { text: "解锁 (港澳台)", color: "#34d399" };
    }
    return { text: "大陆受限", color: "#fbbf24" };
}`,
			TimeoutMillis: 3000,
		},
		{
			ID:   "wikipedia",
			Type: "media",
			Content: `function handler() {
    var res = fetch("https://en.wikipedia.org/w/index.php?title=Wikipedia:WikiProject_on_open_proxies&action=edit", { headers: {'User-Agent':'Mozilla/5.0'}, timeout: 2500 });
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
	case "openai":
		return "OpenAI"
	case "claude":
		return "Claude"
	case "spotify":
		return "Spotify"
	case "tiktok":
		return "TikTok"
	case "bilibili":
		return "Bilibili"
	case "wikipedia":
		return "维基百科"
	default:
		return key
	}
}
