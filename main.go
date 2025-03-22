package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	whitelist   = make(map[string]struct{})
	whitelistMu sync.RWMutex
)

// 获取当前时间的字符串格式
func getCurrentTime() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

// 更新白名单
func updateWhitelist(url string) {
	resp, err := http.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}

	// 白名单每行一个 IP
	ips := strings.Split(string(body), "\n")
	newWhitelist := make(map[string]struct{})
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		// 仅添加有效 IP 地址
		if ip != "" {
			newWhitelist[ip] = struct{}{}
		}
	}

	// 更新白名单
	whitelistMu.Lock()
	whitelist = newWhitelist
	whitelistMu.Unlock()
}

// 监听并转发连接
func handleConnection(client net.Conn, target string) {
	defer client.Close()

	// 获取客户端 IP 地址
	clientAddr := client.RemoteAddr().(*net.TCPAddr).IP.String()

	// 白名单检查
	whitelistMu.RLock()
	_, allowed := whitelist[clientAddr]
	whitelistMu.RUnlock()

	// 输出客户端 IP 地址和时间戳
	fmt.Printf("[%s] 客户端连接: %s\n", getCurrentTime(), clientAddr)

	if !allowed {
		// 显示拒绝连接的信息和时间戳
		fmt.Printf("[%s] [WARNING] 拒绝连接: %s\n", getCurrentTime(), clientAddr)
		return
	}

	// 连接目标并开始转发
	server, err := net.Dial("tcp", target)
	if err != nil {
		return
	}
	defer server.Close()

	// 数据转发
	go func() { io.Copy(server, client) }()
	io.Copy(client, server)
}

func startProxy(listenAddr, targetAddr, whitelistURL string, updateInterval time.Duration) {
	// 定时更新白名单
	go func() {
		for {
			updateWhitelist(whitelistURL)
			time.Sleep(updateInterval)
		}
	}()

	// 启动监听
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return
	}
	defer listener.Close()

	for {
		client, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleConnection(client, targetAddr)
	}
}

func main() {
	L := flag.String("L", "", "格式: tcp://:端口/目标 (必填)")
	whitelistURL := flag.String("url", "", "白名单URL (必填)")
	updateInterval := flag.Int("t", 0, "更新间隔(秒) (必填)")

	flag.Parse()

	// 检查参数
	if *L == "" || *whitelistURL == "" || *updateInterval == 0 {
		flag.Usage()
		return
	}

	// 解析 -L 参数
	parts := strings.SplitN(strings.TrimPrefix(*L, "tcp://"), "/", 2)
	if len(parts) != 2 {
		return
	}

	listenAddr := parts[0]
	targetAddr := parts[1]

	// 启动端口转发服务
	startProxy(listenAddr, targetAddr, *whitelistURL, time.Duration(*updateInterval)*time.Second)
}
