package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCleanISPName(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"  中国电信  ", "中国电信"},
		{"HKT\n\rLimited", "HKT Limited"},
		{"", ""},
		{"   \t  ", ""},
	}
	for _, tc := range cases {
		got := cleanISPName(tc.input)
		if got != tc.want {
			t.Errorf("cleanISPName(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestQueryISPFromURL(t *testing.T) {
	// 1. 测试 ip-api.com 解析
	tsIPAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"success","isp":"China Telecom","org":"Chinanet"}`))
	}))
	defer tsIPAPI.Close()

	isp := queryISPFromURL(context.Background(), tsIPAPI.Client(), tsIPAPI.URL+"/ip-api.com/json")
	if isp != "China Telecom" {
		t.Errorf("ip-api.com query got %q, want China Telecom", isp)
	}

	// 2. 测试 myip.ipip.net 解析
	tsIPIP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ret":"ok","data":{"location":["中国","四川","德阳","","中国移动"]}}`))
	}))
	defer tsIPIP.Close()

	isp = queryISPFromURL(context.Background(), tsIPIP.Client(), tsIPIP.URL+"/myip.ipip.net/json")
	if isp != "中国移动" {
		t.Errorf("myip.ipip.net query got %q, want 中国移动", isp)
	}

	// 3. 测试 ipwho.is 解析
	tsIPWho := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success":true,"connection":{"isp":"Cloudflare, Inc."}}`))
	}))
	defer tsIPWho.Close()

	isp = queryISPFromURL(context.Background(), tsIPWho.Client(), tsIPWho.URL+"/ipwho.is/")
	if isp != "Cloudflare, Inc." {
		t.Errorf("ipwho.is query got %q, want Cloudflare, Inc.", isp)
	}

	// 4. 测试 ipleak.net 解析
	tsIPLeak := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"isp_name":"SoftBank Corp."}`))
	}))
	defer tsIPLeak.Close()

	isp = queryISPFromURL(context.Background(), tsIPLeak.Client(), tsIPLeak.URL+"/ipleak.net/json")
	if isp != "SoftBank Corp." {
		t.Errorf("ipleak.net query got %q, want SoftBank Corp.", isp)
	}
}

func TestDetectOutboundISPFallback(t *testing.T) {
	origURLs := defaultISPProbeURLs
	defer func() { defaultISPProbeURLs = origURLs }()

	// 模拟第一个端点失败，第二个端点成功返回 ISP
	tsFail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	defer tsFail.Close()

	tsOK := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"success","isp":"HKT Limited"}`))
	}))
	defer tsOK.Close()

	defaultISPProbeURLs = []string{
		tsFail.URL + "/ip-api.com/err",
		tsOK.URL + "/ip-api.com/ok",
	}

	isp := detectOutboundISP(context.Background(), tsOK.Client())
	if isp != "HKT Limited" {
		t.Errorf("detectOutboundISP got %q, want HKT Limited", isp)
	}
}
