package model

import (
	"encoding/json"
	"errors"
	"time"
)

var (
	// ErrUnauthorized 表示机器人拒绝了令牌，通常意味着配置错误或令牌已轮换。
	ErrUnauthorized = errors.New("接入令牌被拒绝（请检查 /host 配置与本机令牌是否一致）")

	// ErrUpdating 表示正在应用自动更新，暂停轮询。
	ErrUpdating = errors.New("正在应用更新")
)

// Job 是机器人下发的探测任务，字段与机器人侧 internal/agent 的 Job 保持一致。
//
// Kind 决定执行方式：空/"trace" 走 nexttrace；"miaospeed" 走 miaospeed 代理测速；
// "ping"/"tcping"/"http"/"dns" 由本进程内的探针实现（不依赖外部二进制）。
type Job struct {
	ID        string `json:"id"`
	Kind      string `json:"kind,omitempty"`
	Target    string `json:"target"`
	Hops      int    `json:"hops,omitempty"`
	Port      int    `json:"port,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
	Count     int    `json:"count,omitempty"`
	Query     string `json:"query,omitempty"`
	TimeoutMS int64  `json:"timeout_ms"`
}

// 任务超时的夹取区间。
var (
	JobMinTimeout          = 5 * time.Second
	JobMaxTimeout          = 10 * time.Minute
	JobMiaospeedMaxTimeout = 3 * time.Hour
)

// Timeout 返回任务执行超时，并夹在合理区间内，避免异常值让进程挂死或秒退。
func (j Job) Timeout() time.Duration {
	timeout := time.Duration(j.TimeoutMS) * time.Millisecond
	if timeout < JobMinTimeout {
		timeout = JobMinTimeout
	}
	maxTimeout := JobMaxTimeout
	if j.Kind == "miaospeed" {
		maxTimeout = JobMiaospeedMaxTimeout
	}
	if timeout > maxTimeout {
		timeout = maxTimeout
	}
	return timeout
}

// Result 是回传给机器人的执行结果，字段与机器人侧 internal/agent 的 Result 保持一致。
// Data 携带结构化探针结果（ping/tcping/http/dns），由机器人负责排版展示。
type Result struct {
	ID       string          `json:"id"`
	Kind     string          `json:"kind,omitempty"`
	Output   string          `json:"output"`
	ExitCode int             `json:"exit_code"`
	Error    string          `json:"error,omitempty"`
	Data     json.RawMessage `json:"data,omitempty"`
}

// Progress 表示长时间任务（如 miaospeed 节点测速）的实时执行进度。
type Progress struct {
	ID       string          `json:"id"`
	Current  int             `json:"current"`
	Total    int             `json:"total"`
	NodeName string          `json:"node_name,omitempty"`
	Stage    string          `json:"stage,omitempty"`
	NodeData json.RawMessage `json:"node_data,omitempty"`
}

// ProgressResponse 是服务端对进度上报的响应。
type ProgressResponse struct {
	Cancel bool `json:"cancel,omitempty"`
}
