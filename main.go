package main

import (
	"bufio"
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
	debug          bool
	useProtocol    bool
	whitelistIPs   = make(map[string]struct{})
	whitelistCIDRs []*net.IPNet
	whitelistMu    sync.RWMutex
)

// JSON 配置
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

// 当前时间
func getCurrentTime() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

// 白名单解析
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
func useFallbackWhitelist(path string) {
	data, err := os.ReadFile(path)
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
func updateRemoteWhitelist(url string) {
	if url == "" {
		return
	}
	resp, err := http.Get(url)
	if err != nil {
		if debug {
			fmt.Printf("[%s] [ERROR] 获取远程白名单失败: %v\n", getCurrentTime(), err)
		}
		return
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	newIPs, newCIDRs := parseWhitelist(string(body))
	whitelistMu.Lock()
	whitelistIPs = newIPs
	whitelistCIDRs = newCIDRs
	whitelistMu.Unlock()
	if debug {
		fmt.Printf("[%s] 远程白名单更新成功: %d IP, %d CIDR\n", getCurrentTime(), len(newIPs), len(newCIDRs))
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
	for _, c := range whitelistCIDRs {
		if c.Contains(ip) {
			return true
		}
	}
	return false
}

// 从 HTTP Header 获取客户端 IP
func extractClientIPFromHTTP(data []byte) string {
	reader := bufio.NewReader(strings.NewReader(string(data)))
	req, err := http.ReadRequest(reader)
	if err != nil {
		if debug {
			fmt.Printf("[%s] [DEBUG] 解析 HTTP Header 获取客户端 IP 失败: %v\n", getCurrentTime(), err)
		}
		return ""
	}
	candidates := []string{
		req.Header.Get("X-Forwarded-For"),
		req.Header.Get("CF-Connecting-IP"),
		req.Header.Get("X-Real-IP"),
		req.Header.Get("Forwarded"),
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

// 协议检测
func detectProtocol(data []byte) string {
	s := string(data)
	if strings.HasPrefix(s, "GET ") || strings.HasPrefix(s, "POST ") || strings.HasPrefix(s, "HEAD ") {
		return "HTTP"
	}
	if strings.HasPrefix(s, "PROXY ") {
		return "PROTOCOL"
	}
	return "TCP"
}

// 核心代理
func handleConnection(client net.Conn, target string, useProto bool) {
	defer client.Close()
	clientIP := client.RemoteAddr().(*net.TCPAddr).IP.String()
	clientPort := client.RemoteAddr().(*net.TCPAddr).Port

	client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	peekBuf := make([]byte, 1024)
	n, _ := client.Read(peekBuf)
	client.SetReadDeadline(time.Time{})
	data := peekBuf[:n]

	proto := detectProtocol(data)
	headerIP := ""
	if proto == "HTTP" {
		headerIP = extractClientIPFromHTTP(data)
		if headerIP != "" {
			clientIP = headerIP
		}
	}

	// **始终显示客户端连接，不管 debug 是否开**
	if headerIP != "" && headerIP != clientIP {
		fmt.Printf("[%s] 客户端连接: %s (HTTP Header IP: %s)\n", getCurrentTime(), client.RemoteAddr().(*net.TCPAddr).IP.String(), headerIP)
	} else {
		fmt.Printf("[%s] 客户端连接: %s\n", getCurrentTime(), client.RemoteAddr().(*net.TCPAddr).IP.String())
	}

	// 下面还是用 debug 控制其他日志
	if !isAllowed(clientIP) {
		if debug {
			fmt.Printf("[%s] [WARNING] 拒绝连接: %s\n", getCurrentTime(), clientIP)
		}
		return
	}

	conn, err := net.Dial("tcp", target)
	if err != nil {
		if debug {
			fmt.Printf("[%s] [ERROR] 连接目标失败: %v\n", getCurrentTime(), err)
		}
		return
	}
	defer conn.Close()

	bodyReader := io.MultiReader(strings.NewReader(string(data)), client)

	if useProto {
		proxyLine := fmt.Sprintf("PROXY TCP4 %s %s %d %d\r\n",
			clientIP, conn.RemoteAddr().(*net.TCPAddr).IP.String(), clientPort, conn.RemoteAddr().(*net.TCPAddr).Port)
		if debug {
			fmt.Printf("[%s] [DEBUG] 发送 PROXY Protocol v1: %s", getCurrentTime(), proxyLine)
		}
		conn.Write([]byte(proxyLine))
	}

	go io.Copy(conn, bodyReader)
	io.Copy(client, conn)
}


// 启动代理
func startProxy(listen, target, whitelistURL, local string, useProto bool, interval int) {
	if whitelistURL != "" {
		go func() {
			for {
				updateRemoteWhitelist(whitelistURL)
				time.Sleep(time.Duration(interval) * time.Second)
			}
		}()
	} else if local != "" {
		go func() {
			for {
				useFallbackWhitelist(local)
				time.Sleep(time.Duration(interval) * time.Second)
			}
		}()
	}

	listener, err := net.Listen("tcp", listen)
	if err != nil {
		if debug {
			fmt.Printf("[%s] [FATAL] 无法监听 %s: %v\n", getCurrentTime(), listen, err)
		}
		return
	}
	defer listener.Close()

	fmt.Printf("[%s] 启动代理: %s -> %s (use-protocol=%v)\n", getCurrentTime(), listen, target, useProto)

	for {
		client, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleConnection(client, target, useProto)
	}
}

func main() {
	L := flag.String("L", "", "格式: tcp://:端口/目标")
	whitelistURL := flag.String("url", "", "远程白名单URL")
	local := flag.String("local", "", "本地白名单路径")
	updateInterval := flag.Int("t", 60, "白名单更新间隔(秒)")
	configPath := flag.String("C", "", "JSON 配置文件路径")
	flag.BoolVar(&useProtocol, "use-protocol", false, "是否使用 PROXY 协议转发")
	debugCLI := flag.Bool("debug", false, "命令行模式下显示调试日志")
	flag.Parse()

	// -C 模式
	if *configPath != "" {
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

		// JSON 配置决定全局 debug
		debug = cfg.Debug

		for _, p := range cfg.Proxies {
			go startProxy(p.ListenAddr, p.TargetAddr, p.WhitelistURL, p.LocalWhitelist, p.UseProtocol, p.UpdateInterval)
		}
		select {}
	}

	// 命令行模式
	debug = *debugCLI

	if *L == "" {
		fmt.Println("参数错误: 必须指定监听与目标地址 -L")
		flag.Usage()
		return
	}

	if *whitelistURL == "" && *local == "" {
		fmt.Println("参数错误: 必须指定远程白名单或本地白名单")
		flag.Usage()
		return
	}

	parts := strings.SplitN(strings.TrimPrefix(*L, "tcp://"), "/", 2)
	if len(parts) != 2 {
		fmt.Println("参数错误: -L 格式为 tcp://:端口/目标地址")
		return
	}
	listenAddr := parts[0]
	targetAddr := parts[1]

	startProxy(listenAddr, targetAddr, *whitelistURL, *local, useProtocol, *updateInterval)
}
