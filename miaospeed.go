package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/net/websocket"
)

// 常量定义：MiaoSpeed 任务类型与官方通用构建凭证。
const (
	kindMiaospeed = "miaospeed"

	// defaultBuildToken 是 AirportR/miaospeed 官方发布的默认嵌入凭证，
	// 与主流客户端（FullTclash、miaolib、Koipy 等）保持完全一致。
	defaultBuildToken = "MIAOKO4|580JxAo049R|GEnERAl|1X571R930|T0kEN"

	defaultSTUNServer = "udp://stunserver2025.stunprotocol.org:3478"
	defaultSpeedFile  = "https://speed.cloudflare.com/__down?bytes=50000000"
	defaultPingURL    = "https://cp.cloudflare.com/generate_204"
)

// 7 种测试类型与全量模式常量。
const (
	ModeConnectivity = "connectivity" // 代理连通性测试
	ModeTopology     = "topology"     // 拓扑测试
	ModeMultiSpeed   = "multithread"  // 多线程测速 (下行)
	ModeSingleSpeed  = "singlethread" // 单线程测速 (下行)
	ModeFull         = "full"         // 全量测试
	ModeLatency      = "latency"      // 延迟测试
	ModeUDP          = "udp"          // UDP 类型测试
	ModeMedia        = "media"        // 流媒体专测
)

// MiaoSpeed 官方测试项 Matrix 常量。
const (
	matrixRTTPing       = "TEST_PING_RTT"
	matrixHTTPPing      = "TEST_PING_CONN"
	matrixPacketLoss    = "TEST_PING_PACKET_LOSS"
	matrixMaxRTTPing    = "TEST_PING_MAX_RTT"
	matrixSDRTTPing     = "TEST_PING_SD_RTT"
	matrixHTTPCode      = "TEST_HTTP_CODE"
	matrixInboundGeoIP  = "GEOIP_INBOUND"
	matrixOutboundGeoIP = "GEOIP_OUTBOUND"
	matrixHijack        = "TEST_HIJACK_DETECTION"
	matrixUDPType       = "UDP_TYPE"
	matrixAverageSpeed  = "SPEED_AVERAGE"
	matrixMaxSpeed      = "SPEED_MAX"
)

// --- MiaoSpeed API 请求与协议结构定义 ---

type slaveRequestMatrixEntry struct {
	Type   string
	Params string
}

type slaveRequestOptions struct {
	Filter   string
	Matrices []slaveRequestMatrixEntry
}

type slaveRequestBasics struct {
	ID        string
	Slave     string
	SlaveName string
	Invoker   string
	Version   string
}

type slaveRequestNode struct {
	Name    string
	Payload string
}

type slaveScript struct {
	ID            string
	Type          string
	Content       string
	TimeoutMillis uint64
}

type slaveRequestConfigs struct {
	STUNURL           string
	DownloadURL       string
	DownloadDuration  int64
	DownloadThreading uint

	PingAverageOver uint16
	PingAddress     string

	TaskRetry  uint
	DNSServers []string

	TaskTimeout uint
	Scripts     []slaveScript
}

type slaveRequest struct {
	Basics         slaveRequestBasics
	Options        slaveRequestOptions
	Configs        slaveRequestConfigs
	Vendor         string
	Nodes          []slaveRequestNode
	RandomSequence string
	Challenge      string
}

type matrixResponse struct {
	Type    string `json:"Type"`
	Payload string `json:"Payload"`
}

type slaveEntrySlot struct {
	Grouping       string           `json:"Grouping"`
	InvokeDuration int64            `json:"InvokeDuration"`
	Matrices       []matrixResponse `json:"Matrices"`
}

type slaveTask struct {
	Results []slaveEntrySlot `json:"Results"`
}

type slaveProgress struct {
	Index  int             `json:"Index"`
	Record *slaveEntrySlot `json:"Record"`
}

type slaveResponse struct {
	ID       string         `json:"ID"`
	Error    string         `json:"Error"`
	Result   *slaveTask     `json:"Result"`
	Progress *slaveProgress `json:"Progress"`
}

// signMiaoSpeedRequest 计算 MiaoSpeed 请求的 Challenge 签名。
// 算法与 AirportR/miaospeed 完全一致：
// 服务端反序列化后以 Clone() 副本计算签名；Clone() 会将 Challenge 置空且未复制 Vendor（置空）。
// 对深拷贝副本进行 json.Marshal 后计算 SHA512(request + token + buildToken)。
func signMiaoSpeedRequest(token, buildToken string, req slaveRequest) (string, error) {
	awaitSigned := req
	awaitSigned.Challenge = ""
	awaitSigned.Vendor = "" // miaospeed Clone() 漏拷 Vendor，服务端校验时此字段为空

	raw, err := json.Marshal(&awaitSigned)
	if err != nil {
		return "", err
	}
	reqJSON := strings.TrimSpace(string(raw))

	buildTokens := append([]string{token}, strings.Split(strings.TrimSpace(buildToken), "|")...)

	hasher := sha512.New()
	hasher.Write([]byte(reqJSON))

	for _, t := range buildTokens {
		if t == "" {
			t = "SOME_TOKEN"
		}
		hasher.Write(hasher.Sum([]byte(t)))
	}

	return base64.URLEncoding.EncodeToString(hasher.Sum(nil)), nil
}

// --- MiaoSpeed 临时进程与单次任务执行引擎 ---

// CalcMiaospeedTimeout 根据测速节点数量动态计算任务超时：
// 基础准备时间 60s + 每个节点 12s 预算，单节点保底 90s。
func CalcMiaospeedTimeout(nodeCount int) time.Duration {
	if nodeCount <= 0 {
		nodeCount = 1
	}
	timeout := 60*time.Second + time.Duration(nodeCount)*12*time.Second
	if timeout < 90*time.Second {
		timeout = 90 * time.Second
	}
	return timeout
}

// runMiaospeedJob 执行一次 MiaoSpeed 测速任务：按需拉起进程 -> WebSocket 交互 -> 收集结果 -> 退出清理。
func runMiaospeedJob(ctx context.Context, binary, ghProxy string, job Job, log logger, onProgress func(Progress), allowPrivate ...bool) (string, json.RawMessage, error) {
	if binary == "" {
		binary = "miaospeed"
	}

	binPath := binary
	if p, ok := resolveBinaryPath(binary); ok {
		binPath = p
	} else if _, err := os.Stat(binary); err != nil {
		// 未找到可执行文件，若配置为 miaospeed 标准文件名则尝试从 AirportR/miaospeed 自动下载安装
		baseName := strings.ToLower(filepath.Base(binary))
		if baseName == "miaospeed" || baseName == "miaospeed.exe" {
			if installed, err := autoInstallMiaospeed(ctx, binary, ghProxy, log); err == nil && installed != "" {
				binPath = installed
			}
		}
	}

	allowPriv := len(allowPrivate) > 0 && allowPrivate[0]
	// 1. 解析目标节点
	allNodes, err := parseProxyTarget(ctx, job.Target, allowPriv)
	if err != nil {
		return "", nil, fmt.Errorf("解析测速目标失败: %s", redactProxyError(err.Error(), job.Target))
	}

	totalNodes := len(allNodes)
	nodes := selectJobNodes(allNodes, job.Count)

	// 根据节点数量动态计算本次测速的超时时间限制
	dynamicTimeout := CalcMiaospeedTimeout(len(nodes))
	if reqTimeout := time.Duration(job.TimeoutMS) * time.Millisecond; reqTimeout > dynamicTimeout {
		dynamicTimeout = reqTimeout
	}
	if dynamicTimeout > jobMiaospeedMaxTimeout {
		dynamicTimeout = jobMiaospeedMaxTimeout
	}

	taskCtx, cancelTask := context.WithTimeout(ctx, dynamicTimeout)
	defer cancelTask()

	// 立即发送首包进度，告知上游总节点数与准备状态
	if onProgress != nil {
		onProgress(Progress{
			ID:      job.ID,
			Current: 0,
			Total:   len(nodes),
			Stage:   "准备测速",
		})
	}

	// 2. 分配随机本地端口与 Token
	port, err := getFreeLocalPort()
	if err != nil {
		return "", nil, fmt.Errorf("申请本地端口失败: %w", err)
	}
	token := generateRandomHex(16)

	// 3. 启动临时 miaospeed server 进程（开启 -ipv6 支持全场景 IPv6 节点直连与 AAAA 域名解析）
	cmd := exec.CommandContext(taskCtx, binPath, "server",
		"-bind", fmt.Sprintf("127.0.0.1:%d", port),
		"-token", token,
		"-ipv6",
	)
	setupCmdProcessGroup(cmd)
	cmd.WaitDelay = 3 * time.Second
	serverOut := &cappedBuffer{max: maxOutputBytes}
	cmd.Stdout = serverOut
	cmd.Stderr = serverOut

	if log != nil {
		log.Debug("启动 miaospeed 服务", "binary", binPath, "port", port, "timeout", dynamicTimeout, "nodes", len(nodes))
	}

	if err := cmd.Start(); err != nil {
		return "", nil, fmt.Errorf("启动 miaospeed 失败: %w", err)
	}

	// 确保退出时终止进程
	defer func() {
		killProcessGroup(cmd)
		_ = cmd.Wait()
	}()

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	if err := waitForPortReady(taskCtx, addr, 4*time.Second); err != nil {
		return "", nil, fmt.Errorf("等待 miaospeed 就绪超时: %w\n%s", err, serverOut.String())
	}

	// 4. 发起 WebSocket 请求并执行测速
	wsURL := fmt.Sprintf("ws://%s/", addr)
	origin := fmt.Sprintf("http://%s/", addr)

	report, err := executeMiaospeedTask(taskCtx, wsURL, origin, token, nodes, totalNodes, job, log, onProgress)
	if err != nil {
		return "", nil, err
	}

	// 探测并记录 miaospeed 引擎版本
	if miaoVer := getMiaospeedVersion(taskCtx, binPath, serverOut.String()); miaoVer != "" {
		report.MiaospeedVersion = miaoVer
		for i := range report.SubReports {
			report.SubReports[i].MiaospeedVersion = miaoVer
		}
	}

	data, err := json.Marshal(report)
	if err != nil {
		return "", nil, fmt.Errorf("序列化结果数据失败: %w", err)
	}

	// 数据直接返回 JSON 供机器人端解析与排版展示
	return string(data), data, nil
}

type miaospeedTestPlan struct {
	ModeDescription   string
	Matrices          []slaveRequestMatrixEntry
	Scripts           []slaveScript
	DownloadThreading uint
	DownloadDuration  int64
	UploadThreading   uint
	UploadDuration    int64
	STUNURL           string
}

// buildMiaospeedTestPlan 根据任务参数解析期望执行的测速矩阵。
// 支持 8 种测试类型：连通性、拓扑、多线程测速、单线程测速、上行速度、延迟、UDP类型、全量测试。
func buildMiaospeedTestPlan(job Job, nodeCount ...int) miaospeedTestPlan {
	raw := strings.ToLower(strings.TrimSpace(job.Query))
	if raw == "" {
		raw = strings.ToLower(strings.TrimSpace(job.Protocol))
	}
	if raw == "" {
		kind := strings.ToLower(strings.TrimSpace(job.Kind))
		if strings.HasPrefix(kind, "miaospeed_") {
			raw = strings.TrimPrefix(kind, "miaospeed_")
		} else if strings.HasPrefix(kind, "speed_") {
			raw = strings.TrimPrefix(kind, "speed_")
		}
	}

	tokens := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '|' || r == '/'
	})

	modes := make(map[string]bool)
	for _, tok := range tokens {
		switch tok {
		case "conn", "connectivity", "connect", "http", "连通", "连通性", "代理连通性", "连通性测试", "代理连通性测试":
			modes[ModeConnectivity] = true
		case "topo", "topology", "geo", "geoip", "hijack", "拓扑", "拓扑测试":
			modes[ModeTopology] = true
		case "multi", "multithread", "multispeed", "多线程", "多线程测速", "下载", "下行":
			modes[ModeMultiSpeed] = true
		case "single", "singlethread", "singlespeed", "单线程", "单线程测速":
			modes[ModeSingleSpeed] = true
		case "latency", "ping", "rtt", "delay", "延迟", "延迟测试":
			modes[ModeLatency] = true
		case "udp", "nat", "stun", "udp类型", "udp类型测试":
			modes[ModeUDP] = true
		case "media", "unlock", "流媒体", "流媒体测试", "流媒体专测":
			modes[ModeMedia] = true
		case "full", "all", "total", "全量", "全量测试":
			modes[ModeFull] = true
		}
	}

	count := 1
	if len(nodeCount) > 0 && nodeCount[0] > 0 {
		count = nodeCount[0]
	}
	// 多节点测试时将单节点下行测速时长收敛为 3s，兼顾精准度与整批耗时
	downloadDuration := int64(5)
	if count > 1 {
		downloadDuration = 3
	}

	// 默认或明确指定为全量测试
	if len(modes) == 0 || modes[ModeFull] {
		matrices := []slaveRequestMatrixEntry{
			{Type: matrixRTTPing},
			{Type: matrixHTTPPing},
			{Type: matrixPacketLoss},
			{Type: matrixHTTPCode},
			{Type: matrixInboundGeoIP},
			{Type: matrixOutboundGeoIP},
		}
		// 单节点测速包含防劫持检测；多节点批量测速跳过 matrixHijack
		//（miaospeed 内部 checkHijack 硬编码 2×3×7s=42s 超时且无视 TaskTimeout，会导致死节点卡住 42s，而多节点表格不展示该项）
		if count <= 1 {
			matrices = append(matrices, slaveRequestMatrixEntry{Type: matrixHijack})
		}
		matrices = append(matrices,
			slaveRequestMatrixEntry{Type: matrixUDPType},
			slaveRequestMatrixEntry{Type: matrixAverageSpeed},
			slaveRequestMatrixEntry{Type: matrixMaxSpeed},
			slaveRequestMatrixEntry{Type: "TEST_SCRIPT", Params: "youtube"},
			slaveRequestMatrixEntry{Type: "TEST_SCRIPT", Params: "netflix"},
			slaveRequestMatrixEntry{Type: "TEST_SCRIPT", Params: "disney"},
			slaveRequestMatrixEntry{Type: "TEST_SCRIPT", Params: "primevideo"},
			slaveRequestMatrixEntry{Type: "TEST_SCRIPT", Params: "spotify"},
			slaveRequestMatrixEntry{Type: "TEST_SCRIPT", Params: "openai"},
			slaveRequestMatrixEntry{Type: "TEST_SCRIPT", Params: "claude"},
			slaveRequestMatrixEntry{Type: "TEST_SCRIPT", Params: "gemini"},
			slaveRequestMatrixEntry{Type: "TEST_SCRIPT", Params: "bahamut"},
			slaveRequestMatrixEntry{Type: "TEST_SCRIPT", Params: "bilibili"},
			slaveRequestMatrixEntry{Type: "TEST_SCRIPT", Params: "tiktok"},
			slaveRequestMatrixEntry{Type: "TEST_SCRIPT", Params: "wikipedia"},
		)
		return miaospeedTestPlan{
			ModeDescription:   "全量测试",
			Matrices:          matrices,
			Scripts:           buildDefaultMediaScripts(),
			DownloadThreading: 4,
			DownloadDuration:  downloadDuration,
			STUNURL:           defaultSTUNServer,
		}
	}

	matrixSet := make(map[string]bool)
	var descriptions []string
	plan := miaospeedTestPlan{
		DownloadDuration: downloadDuration,
	}

	if modes[ModeConnectivity] {
		descriptions = append(descriptions, "连通性测试")
		matrixSet[matrixHTTPPing] = true
		matrixSet[matrixRTTPing] = true
		matrixSet[matrixMaxRTTPing] = true
		matrixSet[matrixPacketLoss] = true
		matrixSet[matrixHTTPCode] = true
		matrixSet[matrixOutboundGeoIP] = true
	}
	if modes[ModeTopology] {
		descriptions = append(descriptions, "拓扑测试")
		matrixSet[matrixInboundGeoIP] = true
		matrixSet[matrixOutboundGeoIP] = true
		matrixSet[matrixHijack] = true
		matrixSet[matrixRTTPing] = true
		matrixSet[matrixHTTPPing] = true
		matrixSet[matrixUDPType] = true
		plan.STUNURL = defaultSTUNServer
	}
	if modes[ModeLatency] {
		descriptions = append(descriptions, "延迟测试")
		matrixSet[matrixRTTPing] = true
		matrixSet[matrixHTTPPing] = true
		matrixSet[matrixPacketLoss] = true
		matrixSet[matrixMaxRTTPing] = true
		matrixSet[matrixHTTPCode] = true
		matrixSet[matrixOutboundGeoIP] = true
	}
	if modes[ModeUDP] {
		descriptions = append(descriptions, "UDP类型测试")
		matrixSet[matrixUDPType] = true
		matrixSet[matrixRTTPing] = true
		matrixSet[matrixHTTPPing] = true
		matrixSet[matrixPacketLoss] = true
		matrixSet[matrixHTTPCode] = true
		matrixSet[matrixOutboundGeoIP] = true
		plan.STUNURL = defaultSTUNServer
	}
	if modes[ModeMedia] {
		descriptions = append(descriptions, "流媒体测试")
		matrixSet[matrixRTTPing] = true
		matrixSet[matrixHTTPPing] = true
		matrixSet[matrixPacketLoss] = true
		matrixSet[matrixHTTPCode] = true
		matrixSet[matrixInboundGeoIP] = true
		matrixSet[matrixOutboundGeoIP] = true
		plan.Scripts = buildDefaultMediaScripts()
	}
	if modes[ModeSingleSpeed] {
		descriptions = append(descriptions, "单线程测速")
		matrixSet[matrixAverageSpeed] = true
		matrixSet[matrixMaxSpeed] = true
		matrixSet[matrixRTTPing] = true
		matrixSet[matrixHTTPPing] = true
		matrixSet[matrixPacketLoss] = true
		matrixSet[matrixHTTPCode] = true
		matrixSet[matrixOutboundGeoIP] = true
		plan.DownloadThreading = 1
	}
	if modes[ModeMultiSpeed] {
		descriptions = append(descriptions, "多线程测速")
		matrixSet[matrixAverageSpeed] = true
		matrixSet[matrixMaxSpeed] = true
		matrixSet[matrixRTTPing] = true
		matrixSet[matrixHTTPPing] = true
		matrixSet[matrixPacketLoss] = true
		matrixSet[matrixHTTPCode] = true
		matrixSet[matrixOutboundGeoIP] = true
		th := uint(4)
		if job.Count > 1 && job.Count <= 16 {
			th = uint(job.Count)
		}
		plan.DownloadThreading = th
	}
	orderedMatrixKeys := []string{
		matrixRTTPing, matrixHTTPPing, matrixPacketLoss, matrixMaxRTTPing, matrixHTTPCode,
		matrixInboundGeoIP, matrixOutboundGeoIP, matrixHijack,
		matrixUDPType,
		matrixAverageSpeed, matrixMaxSpeed,
	}
	for _, key := range orderedMatrixKeys {
		if matrixSet[key] {
			plan.Matrices = append(plan.Matrices, slaveRequestMatrixEntry{Type: key})
		}
	}

	// 流媒体测试脚本追加在基础连通性与 GeoIP 探测之后，确保各节点优先获取出站 IP 与地理位置
	if modes[ModeMedia] {
		for _, platform := range []string{
			"youtube", "netflix", "disney", "primevideo", "spotify", "openai", "claude", "gemini", "bahamut", "bilibili", "tiktok", "wikipedia",
		} {
			plan.Matrices = append(plan.Matrices, slaveRequestMatrixEntry{Type: "TEST_SCRIPT", Params: platform})
		}
	}
	plan.ModeDescription = strings.Join(descriptions, " + ")
	return plan
}

// executeMiaospeedTask 连接 WebSocket、发送任务并读取结果。
func executeMiaospeedTask(ctx context.Context, wsURL, origin, token string, nodes []MiaospeedNode, totalNodes int, job Job, log logger, onProgress func(Progress)) (*MiaospeedReport, error) {
	wsCfg, err := websocket.NewConfig(wsURL, origin)
	if err != nil {
		return nil, fmt.Errorf("配置 websocket 失败: %w", err)
	}

	type dialResult struct {
		conn *websocket.Conn
		err  error
	}
	dialCh := make(chan dialResult, 1)
	go func() {
		conn, err := websocket.DialConfig(wsCfg)
		dialCh <- dialResult{conn: conn, err: err}
	}()

	var ws *websocket.Conn
	select {
	case <-ctx.Done():
		go func() {
			if res := <-dialCh; res.conn != nil {
				_ = res.conn.Close()
			}
		}()
		return nil, ctx.Err()
	case res := <-dialCh:
		if res.err != nil {
			return nil, fmt.Errorf("连接 miaospeed 服务失败: %w", res.err)
		}
		ws = res.conn
	}
	defer ws.Close()

	plan := buildMiaospeedTestPlan(job, len(nodes))

	// 构造节点
	reqNodes := make([]slaveRequestNode, 0, len(nodes))
	for _, n := range nodes {
		reqNodes = append(reqNodes, slaveRequestNode{
			Name:    n.Name,
			Payload: n.Payload,
		})
	}

	stunURL := plan.STUNURL
	if stunURL == "" {
		stunURL = defaultSTUNServer
	}

	scripts := plan.Scripts
	if scripts == nil {
		scripts = make([]slaveScript, 0)
	}

	// 批量测速时若节点超时或阻断，不重试（TaskRetry=0）并将单次超时收紧为 3500ms，避免死节点阻塞整批进度
	taskRetry := uint(2)
	taskTimeout := uint(5000)
	if len(nodes) > 1 {
		taskRetry = 0
		taskTimeout = 3500
		if len(plan.Scripts) > 5 {
			taskTimeout = 4500
		}
	}

	req := slaveRequest{
		Basics: slaveRequestBasics{
			ID:        job.ID,
			Slave:     "mnagent",
			SlaveName: "mnagent-local",
			Invoker:   "mnagent",
			Version:   "1.0",
		},
		Options: slaveRequestOptions{
			Matrices: plan.Matrices,
		},
		Configs: slaveRequestConfigs{
			STUNURL:           stunURL,
			DownloadURL:       defaultSpeedFile,
			DownloadDuration:  plan.DownloadDuration,
			DownloadThreading: plan.DownloadThreading,
			PingAddress:       defaultPingURL,
			PingAverageOver:   2,
			TaskRetry:         taskRetry,
			TaskTimeout:       taskTimeout,
			DNSServers:        make([]string, 0),
			Scripts:           scripts,
		},
		Vendor:         "Clash",
		Nodes:          reqNodes,
		RandomSequence: generateRandomHex(8),
	}

	// 签名
	sig, err := signMiaoSpeedRequest(token, defaultBuildToken, req)
	if err != nil {
		return nil, fmt.Errorf("签名任务请求失败: %w", err)
	}
	req.Challenge = sig

	// 发送任务
	if err := websocket.JSON.Send(ws, req); err != nil {
		return nil, fmt.Errorf("向 miaospeed 发送任务失败: %w", err)
	}

	// 接收结果
	startTime := time.Now()
	var progressSlots []slaveEntrySlot
	for {
		select {
		case <-ctx.Done():
			if len(progressSlots) > 0 {
				resTask := &slaveTask{Results: progressSlots}
				return parseSlaveTaskResult(resTask, nodes, totalNodes, plan, time.Since(startTime)), nil
			}
			return nil, ctx.Err()
		default:
		}

		var resp slaveResponse
		if err := readNextSlaveJSON(ctx, ws, &resp); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
				break
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			if len(progressSlots) > 0 {
				break
			}
			return nil, fmt.Errorf("读取 miaospeed 响应失败: %w", err)
		}
		if log != nil {
			log.Debug("收到 miaospeed 响应", "has_result", resp.Result != nil, "has_progress", resp.Progress != nil, "error", resp.Error)
		}

		if resp.Error != "" {
			return nil, fmt.Errorf("miaospeed 任务执行报错: %s", resp.Error)
		}

		if resp.Progress != nil && resp.Progress.Record != nil {
			progressSlots = append(progressSlots, *resp.Progress.Record)
			if onProgress != nil {
				curIdx := len(progressSlots)
				if curIdx > len(nodes) {
					curIdx = len(nodes)
				}
				curName := ""
				var curNode *MiaospeedNode
				if resp.Progress.Index >= 0 && resp.Progress.Index < len(nodes) {
					curNode = &nodes[resp.Progress.Index]
					curName = curNode.Name
				}
				singleReport := parseSingleSlot(*resp.Progress.Record, curNode, plan)
				nodeRawBytes, _ := json.Marshal(singleReport)

				stageDesc := "测速中"
				if plan.ModeDescription != "" {
					stageDesc = plan.ModeDescription + "中"
				}

				onProgress(Progress{
					ID:       job.ID,
					Current:  curIdx,
					Total:    len(nodes),
					NodeName: curName,
					Stage:    stageDesc,
					NodeData: nodeRawBytes,
				})
			}
		}

		if resp.Result != nil {
			report := parseSlaveTaskResult(resp.Result, nodes, totalNodes, plan, time.Since(startTime))
			return report, nil
		}
	}

	if len(progressSlots) > 0 {
		resTask := &slaveTask{Results: progressSlots}
		report := parseSlaveTaskResult(resTask, nodes, totalNodes, plan, time.Since(startTime))
		return report, nil
	}

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return nil, errors.New("miaospeed 连接已关闭，但未收到结果数据")
}

func getFreeLocalPort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func waitForPortReady(ctx context.Context, addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errors.New("端口未就绪")
}

func generateRandomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// readNextSlaveJSON 从 ws 连接中读取下一条完整的 JSON 响应并反序列化。
// 内部处理 5s ReadDeadline 超时并在 ctx 未结束时继续累积读取，防止跨读取周期拆帧丢失半包数据。
func readNextSlaveJSON(ctx context.Context, ws *websocket.Conn, dest any) error {
	var buf bytes.Buffer
	chunk := make([]byte, 32*1024)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		_ = ws.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := ws.Read(chunk)
		if n > 0 {
			buf.Write(chunk[:n])
			b := bytes.TrimSpace(buf.Bytes())
			if len(b) > 0 && b[0] == '{' && b[len(b)-1] == '}' {
				if json.Valid(b) {
					if jsonErr := json.Unmarshal(b, dest); jsonErr == nil {
						return nil
					}
				}
			}
		}
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				continue
			}
			if buf.Len() > 0 {
				b := bytes.TrimSpace(buf.Bytes())
				if len(b) > 0 && json.Valid(b) {
					if jsonErr := json.Unmarshal(b, dest); jsonErr == nil {
						return nil
					}
				}
			}
			return err
		}
	}
}
