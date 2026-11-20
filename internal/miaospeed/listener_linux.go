//go:build linux

package miaospeed

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// procRoot 是 procfs 挂载点；测试可指向临时目录伪造 /proc 结构。
var procRoot = "/proc"

// errProcUnverifiable 表示 procfs 不可读（权限受限、被卸载、解析失败等），
// 此时无法完成归属校验，应降级放行而不是把子进程当成被抢占。
var errProcUnverifiable = errors.New("procfs 不可读，无法校验监听套接字归属")

// listenerWarnOnce/listenerWarnf 保证“无法校验”的告警在进程内只输出一次，
// 避免每次拉起 miaospeed 都刷日志。测试可重置这两个变量。
var (
	listenerWarnOnce sync.Once
	listenerWarnf    = func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "WARN [miaospeed] "+format+"\n", args...)
	}
)

// verifyMiaospeedListener 确认 127.0.0.1:<port> 上处于 LISTEN 的套接字确实属于
// 刚启动的子进程（或其进程组）。
//
// getFreeLocalPort 先 Listen 拿到空闲端口再关闭，随后才让子进程 -bind 同一端口，
// 中间存在 TOCTOU 窗口：本机其他用户可以先抢占端口并冒充 miaospeed。由于请求里
// 携带节点凭据且 WebSocket 是明文，仅靠每次随机的 -token 无法阻止对方读取请求
// （token 只用于服务端校验客户端签名，响应没有签名），因此在这里做进程归属校验。
//
// Linux 上通过 /proc/net/tcp{,6} 找到监听端口的 socket inode，再到子进程及其
// 进程组（子进程以 Setpgid 启动，见 process.SetupCmdProcessGroup）的 /proc/<pid>/fd
// 中确认该 inode 属于它们。
//
// 三类结果：
//   - 归属匹配：返回 nil；
//   - 确实读到监听套接字，但 inode 不属于子进程及其进程组：判定被抢占，返回错误
//     （调用方据此换端口重试）；
//   - procfs 不可读（EACCES/解析失败等）：无法校验，降级放行并在进程内告警一次。
func verifyMiaospeedListener(pid, port int) error {
	inodes, err := listeningSocketInodes(port)
	if err != nil {
		if errors.Is(err, errProcUnverifiable) {
			return degradeUnverifiable(err)
		}
		return err
	}
	if len(inodes) == 0 {
		return fmt.Errorf("未在 /proc/net/tcp{,6} 找到 127.0.0.1:%d 的 LISTEN 套接字", port)
	}

	pgid, err := readProcPgid(pid)
	if err != nil {
		return degradeUnverifiable(unverifiablef("读取子进程 %d 的 /proc stat 失败：%v", pid, err))
	}
	members, err := processGroupMembers(pgid)
	if err != nil {
		return degradeUnverifiable(unverifiablef("枚举进程组 %d 失败：%v", pgid, err))
	}
	owned := make(map[string]struct{})
	for _, member := range members {
		sockets, err := socketInodesForPID(member)
		if err != nil {
			if os.IsNotExist(err) {
				// 枚举期间进程退出，忽略（套接字也随之释放）。
				continue
			}
			return degradeUnverifiable(unverifiablef("读取进程 %d 的套接字失败（pgid=%d）：%v", member, pgid, err))
		}
		for inode := range sockets {
			owned[inode] = struct{}{}
		}
	}
	for inode := range inodes {
		if _, ok := owned[inode]; ok {
			return nil
		}
	}
	return fmt.Errorf("127.0.0.1:%d 的监听套接字不属于子进程 %d 及其进程组 %d（可能被本机进程抢占）", port, pid, pgid)
}

func unverifiablef(format string, args ...any) error {
	return fmt.Errorf("%w：%s", errProcUnverifiable, fmt.Sprintf(format, args...))
}

// degradeUnverifiable 把“无法校验”降级为放行，并保证整个进程只告警一次。
func degradeUnverifiable(err error) error {
	listenerWarnOnce.Do(func() {
		listenerWarnf("无法读取 procfs 校验 miaospeed 监听套接字归属，已降级放行（仅提示一次）：%v", err)
	})
	return nil
}

// listeningSocketInodes 返回本机所有监听指定端口的 TCP 套接字 inode。
// 只接受回环地址（127.0.0.1 / ::1 / ::ffff:127.0.0.1），避免把 0.0.0.0 上
// 其它进程的同端口监听误认为我们的服务。
func listeningSocketInodes(port int) (map[string]struct{}, error) {
	portHex := fmt.Sprintf("%04X", port)
	inodes := make(map[string]struct{})
	for _, name := range []string{"tcp", "tcp6"} {
		path := filepath.Join(procRoot, "net", name)
		f, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, unverifiablef("读取 %s 失败：%v", path, err)
		}
		scanner := bufio.NewScanner(f)
		first := true
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if first {
				first = false
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 10 {
				continue
			}
			local := fields[1]
			state := fields[3]
			inode := fields[9]
			if !strings.EqualFold(state, "0A") { // TCP_LISTEN
				continue
			}
			addr, p, ok := strings.Cut(local, ":")
			if !ok || !strings.EqualFold(p, portHex) {
				continue
			}
			if !isLoopbackProcAddr(addr) {
				continue
			}
			if inode != "" && inode != "0" {
				inodes[inode] = struct{}{}
			}
		}
		scanErr := scanner.Err()
		_ = f.Close()
		if scanErr != nil {
			return nil, unverifiablef("解析 %s 失败：%v", path, scanErr)
		}
	}
	return inodes, nil
}

// isLoopbackProcAddr 判断 /proc/net/tcp{,6} 中十六进制 local_address 是否为回环地址。
//
// procfs 按主机字节序打印 32 位分组：小端主机上 127.0.0.1 为 0100007F、::1 为
// 00000000000000000000000001000000；大端主机（s390x、部分 MIPS/PPC 等）上则分别
// 为 7F000001 与 00000000000000000000000000000001。两种形式都接受。
func isLoopbackProcAddr(addr string) bool {
	addr = strings.ToUpper(strings.TrimSpace(addr))
	switch len(addr) {
	case 8, 32:
	default:
		return false
	}
	for _, candidate := range []string{addr, reverseProcAddrWords(addr)} {
		switch candidate {
		case "7F000001", // 127.0.0.1（按字节序规范化为网络序后）
			"00000000000000000000000000000001", // ::1
			"00000000000000000000FFFF7F000001": // ::ffff:127.0.0.1
			return true
		}
	}
	return false
}

// reverseProcAddrWords 逐 32 位字反转字节序，把另一种主机字节序的打印形式
// 归一到网络序。输入长度必须是 8 或 32 个十六进制字符（调用方保证）。
func reverseProcAddrWords(addr string) string {
	var b strings.Builder
	b.Grow(len(addr))
	for i := 0; i+8 <= len(addr); i += 8 {
		word := addr[i : i+8]
		for j := 6; j >= 0; j -= 2 {
			b.WriteString(word[j : j+2])
		}
	}
	return b.String()
}

// readProcPgid 读取 /proc/<pid>/stat 中的进程组 ID（第 5 个字段）。
// comm 字段（第 2 个）可能包含空格与括号，因此从最后一个 ')' 之后开始解析。
func readProcPgid(pid int) (int, error) {
	data, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, err
	}
	text := string(data)
	idx := strings.LastIndexByte(text, ')')
	if idx < 0 || idx+1 >= len(text) {
		return 0, fmt.Errorf("解析 /proc/%d/stat 失败：缺少 comm 字段结束符", pid)
	}
	fields := strings.Fields(text[idx+1:])
	if len(fields) < 3 { // state ppid pgrp
		return 0, fmt.Errorf("/proc/%d/stat 字段不足：%q", pid, text)
	}
	pgid, err := strconv.Atoi(fields[2])
	if err != nil {
		return 0, fmt.Errorf("解析 /proc/%d/stat 的 pgrp 失败：%w", pid, err)
	}
	return pgid, nil
}

// processGroupMembers 返回与 targetPgid 同进程组的所有进程 PID。
// 子进程以 Setpgid 启动，其进程组内还可能包含它自己拉起的孙进程（例如
// miaospeed 的辅助进程），监听套接字可能由组内任意进程持有。
func processGroupMembers(targetPgid int) ([]int, error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, err
	}
	var members []int
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		pgid, err := readProcPgid(pid)
		if err != nil {
			if os.IsNotExist(err) || errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, err
		}
		if pgid == targetPgid {
			members = append(members, pid)
		}
	}
	return members, nil
}

// socketInodesForPID 返回进程持有的 socket inode 集合。
func socketInodesForPID(pid int) (map[string]struct{}, error) {
	fdDir := filepath.Join(procRoot, strconv.Itoa(pid), "fd")
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return nil, err
	}
	owned := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join(fdDir, entry.Name()))
		if err != nil {
			// fd 可能在枚举期间被关闭，忽略即可。
			continue
		}
		if inode, ok := strings.CutPrefix(target, "socket:["); ok {
			if inode, ok = strings.CutSuffix(inode, "]"); ok {
				owned[inode] = struct{}{}
			}
		}
	}
	return owned, nil
}
