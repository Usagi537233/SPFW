package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	whitelistIPs       = make(map[string]struct{})
	whitelistCIDRs     []*net.IPNet
	whitelistMu        sync.RWMutex
	localWhitelistPath string
	useProtocol        bool
	debug              bool
)

// JSON 配置结构
type ConfigJSON struct {
	Debug   bool `json:"debug"`
	Proxies []struct {
		ListenAddr     string `json:"listen_addr"`
		TargetAddr     string `json:"target_addr"`
		UseProtocol    bool   `json:"use_protocol"`
		LocalWhitelist string `json:"local_whitelist,omitempty"`
		WhitelistURL   string `json:"whitelist_url,omitempty"`
		UpdateInterval int    `json:"update_interval,omitempty"`
	} `json:"proxies"`
}

// 获取当前时间字符串
func getCurrentTime() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

// 解析白名单内容
func parseWhitelist(content string) (map[string]struct{}, []*net.IPNet) {
	newIPs := make(map[string]struct{})
	var newCIDRs []*net.IPNet
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		entry := strings.TrimSpace(line)
		if entry == "" {
			continue
		}
		if ip := net.ParseIP(entry); ip != nil {
			newIPs[entry] = struct{}{}
			continue
		}
		if _, ipNet, err := net.ParseCIDR(entry); err == nil {
			newCIDRs = append(newCIDRs, ipNet)
			continue
		}
		if debug {
			fmt.Printf("[%s] [WARNING] 无效白名单项: %s\n", getCurrentTime(), entry)
		}
	}
	return newIPs, newCIDRs
}

// 使用本地白名单
func useFallbackWhitelist() {
	if localWhitelistPath == "" {
		if debug {
			fmt.Printf("[%s] [WARNING] 没有本地白名单路径\n", getCurrentTime())
		}
		return
	}
	data, err := os.ReadFile(localWhitelistPath)
	if err != nil {
		if debug {
			fmt.Printf("[%s] [ERROR] 读取本地白名单失败: %v\n", getCurrentTime(), err)
		}
		return
	}
	newIPs, newCIDRs := parseWhitelist(string(data))
	whitelistMu.Lock()
	whitelistIPs = newIPs
	whitelistCIDRs = newCIDRs
	whitelistMu.Unlock()
	if debug {
		fmt.Printf("[%s] 使用本地白名单: %d IP, %d CIDR\n", getCurrentTime(), len(newIPs), len(newCIDRs))
	}
}

// 更新远程白名单
func updateWhitelist(url string) {
	if url == "" {
		useFallbackWhitelist()
		return
	}
	resp, err := http.Get(url)
	if err != nil || resp.StatusCode != 200 {
		if debug {
			fmt.Printf("[%s] [ERROR] 无法获取远程白名单: %v\n", getCurrentTime(), err)
		}
		useFallbackWhitelist()
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		if debug {
			fmt.Printf("[%s] [ERROR] 读取远程白名单失败: %v\n", getCurrentTime(), err)
		}
		useFallbackWhitelist()
		return
	}

	newIPs, newCIDRs := parseWhitelist(string(body))
	whitelistMu.Lock()
	whitelistIPs = newIPs
	whitelistCIDRs = newCIDRs
	whitelistMu.Unlock()

	if localWhitelistPath != "" {
		_ = ioutil.WriteFile(localWhitelistPath, body, 0644)
	}
	if debug {
		fmt.Printf("[%s] 白名单更新成功: %d IP, %d CIDR\n", getCurrentTime(), len(newIPs), len(newCIDRs))
	}
}

// 检查 IP 是否允许
func isAllowed(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	whitelistMu.RLock()
	defer whitelistMu.RUnlock()
	if _, ok := whitelistIPs[ipStr]; ok {
		return true
	}
	for _, cidr := range whitelistCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// 提取 PROXY v1 协议中的客户端 IP
func extractProxyHeaderIP(data []byte) (string, bool) {
	if !bytes.HasPrefix(data, []byte("PROXY ")) {
		return "", false
	}
	reader := bufio.NewReader(bytes.NewReader(data))
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", false
	}
	parts := strings.Fields(line)
	if len(parts) >= 6 {
		ip := parts[2] // PROXY TCP4 真实IP 目标IP 真实端口 目标端口
		if net.ParseIP(ip) != nil {
			return ip, true
		}
	}
	return "", false
}

// 从 HTTP Header 获取客户端 IP
func extractClientIPFromHTTP(data []byte) string {
	reader := bufio.NewReader(bytes.NewReader(data))
	req, err := http.ReadRequest(reader)
	if err != nil {
		if debug {
			fmt.Printf("[%s] [DEBUG] 解析 HTTP Header 失败: %v\n", getCurrentTime(), err)
		}
		return ""
	}
	header := req.Header
	candidates := []string{
		header.Get("X-Forwarded-For"),
		header.Get("CF-Connecting-IP"),
		header.Get("X-Real-IP"),
		header.Get("Forwarded"),
	}
	for _, v := range candidates {
		if v == "" {
			continue
		}
		parts := strings.Split(v, ",")
		ip := strings.TrimSpace(strings.Split(parts[0], "=")[0])
		if net.ParseIP(ip) != nil {
			return ip
		}
	}
	if debug {
		fmt.Printf("[%s] [DEBUG] HTTP Header 中未找到有效客户端 IP\n", getCurrentTime())
	}
	return ""
}

// 检测协议类型
func detectProtocol(data []byte) string {
	if bytes.HasPrefix(data, []byte("PROXY ")) {
		return "PROXY"
	}
	if bytes.HasPrefix(data, []byte("GET ")) || bytes.HasPrefix(data, []byte("POST ")) ||
		bytes.HasPrefix(data, []byte("HEAD ")) || bytes.HasPrefix(data, []byte("PUT ")) ||
		bytes.HasPrefix(data, []byte("DELETE ")) {
		return "HTTP"
	}
	return "TCP"
}

func getBackendIP(backend string) string {
	host, _, err := net.SplitHostPort(backend)
	if err != nil {
		return backend
	}
	return host
}

func getBackendPortInt(backend string) int {
	_, port, err := net.SplitHostPort(backend)
	if err != nil {
		return 80
	}
	var p int
	fmt.Sscanf(port, "%d", &p)
	return p
}

// 核心代理逻辑
func handleConnection(client net.Conn, target string, useProtocolOut bool) {
	defer client.Close()
	remoteAddr := client.RemoteAddr().(*net.TCPAddr)
	clientIP := remoteAddr.IP.String()
	clientPort := remoteAddr.Port

	client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 4096)
	n, _ := client.Read(buf)
	client.SetReadDeadline(time.Time{})
	data := buf[:n]

	// 自动检测客户端协议
	proto := detectProtocol(data)

	if proto == "PROXY" {
		if hdrIP, ok := extractProxyHeaderIP(data); ok {
			clientIP = hdrIP
			if debug {
				fmt.Printf("[%s] [DEBUG][PROXY] 客户端 IP: %s\n", getCurrentTime(), clientIP)
			}
			// 去掉 PROXY header
			idx := bytes.IndexByte(data, '\n')
			if idx >= 0 {
				data = data[idx+1:]
			}
		}
	} else if proto == "HTTP" {
		if hdrIP := extractClientIPFromHTTP(data); hdrIP != "" {
			clientIP = hdrIP
			if debug {
				fmt.Printf("[%s] [DEBUG][HTTP] 客户端 IP: %s\n", getCurrentTime(), clientIP)
			}
		}
	}

	fmt.Printf("[%s] 客户端连接: %s\n", getCurrentTime(), clientIP)
	if !isAllowed(clientIP) {
		fmt.Printf("[%s] [WARNING] 拒绝连接: %s\n", getCurrentTime(), clientIP)
		return
	}

	bodyReader := io.MultiReader(bytes.NewReader(data), client)

	// 根据配置决定是否转发 PROXY 协议
	server, err := net.Dial("tcp", target)
	if err != nil {
		fmt.Printf("[%s] [ERROR] 无法连接目标: %v\n", getCurrentTime(), err)
		return
	}
	defer server.Close()

	if useProtocolOut {
		proxyLine := fmt.Sprintf("PROXY TCP4 %s %s %d %d\r\n",
			clientIP, getBackendIP(target), clientPort, getBackendPortInt(target))
		if debug {
			fmt.Printf("[%s] [DEBUG] 发送 PROXY Protocol v1: %s", getCurrentTime(), proxyLine)
		}
		server.Write([]byte(proxyLine))
	}

	go io.Copy(server, bodyReader)
	io.Copy(client, server)
}

// 启动单个代理
func startProxy(listenAddr, targetAddr, whitelistURL string, updateInterval time.Duration, useProtocolOut bool, localWhitelist string) {
	localWhitelistPath = localWhitelist
	if whitelistURL != "" {
		updateWhitelist(whitelistURL)
	} else {
		useFallbackWhitelist()
	}

	go func() {
		for {
			time.Sleep(updateInterval)
			if whitelistURL != "" {
				updateWhitelist(whitelistURL)
			} else {
				useFallbackWhitelist()
			}
		}
	}()

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		fmt.Printf("[%s] [FATAL] 无法监听 %s: %v\n", getCurrentTime(), listenAddr, err)
		return
	}
	defer listener.Close()

	fmt.Printf("[%s] 启动代理: %s -> %s (use-protocol-out=%v)\n", getCurrentTime(), listenAddr, targetAddr, useProtocolOut)
	for {
		client, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleConnection(client, targetAddr, useProtocolOut)
	}
}

// 主入口
func main() {
	L := flag.String("L", "", "格式: tcp://:端口/目标 (必填)")
	whitelistURL := flag.String("url", "", "白名单 URL")
	updateInterval := flag.Int("t", 60, "更新间隔(秒)")
	local := flag.String("local", "", "本地白名单文件路径")
	flag.BoolVar(&useProtocol, "use-protocol", false, "是否使用 PROXY 协议转发目标")
	flag.BoolVar(&debug, "D", false, "显示调试日志")
	flag.BoolVar(&debug, "debug", false, "显示调试日志")
	configPath := flag.String("C", "", "JSON 配置文件路径")
	flag.Parse()

	if *configPath != "" {
		// JSON 配置模式
		data, err := os.ReadFile(*configPath)
		if err != nil {
			fmt.Printf("读取配置文件失败: %v\n", err)
			return
		}
		var cfg ConfigJSON
		if err := json.Unmarshal(data, &cfg); err != nil {
			fmt.Printf("解析配置文件失败: %v\n", err)
			return
		}
		debug = cfg.Debug
		for _, p := range cfg.Proxies {
			go func(proxy struct {
				ListenAddr     string `json:"listen_addr"`
				TargetAddr     string `json:"target_addr"`
				UseProtocol    bool   `json:"use_protocol"`
				LocalWhitelist string `json:"local_whitelist,omitempty"`
				WhitelistURL   string `json:"whitelist_url,omitempty"`
				UpdateInterval int    `json:"update_interval,omitempty"`
			}) {
				startProxy(proxy.ListenAddr, proxy.TargetAddr, proxy.WhitelistURL, time.Duration(proxy.UpdateInterval)*time.Second, proxy.UseProtocol, proxy.LocalWhitelist)
			}(p)
		}
		select {}
	}

	// 命令行模式
	if *L == "" || (*whitelistURL == "" && *local == "") {
		fmt.Println("参数错误: 必须指定 -L 以及 -url 或 -local")
		flag.Usage()
		return
	}

	parts := strings.SplitN(strings.TrimPrefix(*L, "tcp://"), "/", 2)
	if len(parts) != 2 {
		fmt.Println("参数格式错误，应为: -L tcp://:监听端口/目标地址")
		return
	}

	listenAddr := parts[0]
	targetAddr := parts[1]
	startProxy(listenAddr, targetAddr, *whitelistURL, time.Duration(*updateInterval)*time.Second, useProtocol, *local)
}
