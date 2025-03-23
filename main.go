package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	whitelist   = make(map[string]struct{})
	whitelistMu sync.RWMutex
)

// 获取当前时间字符串
func getCurrentTime() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

// 更新白名单
func updateWhitelist(url string) {
	resp, err := http.Get(url)
	if err != nil {
		fmt.Printf("[%s] [ERROR] 获取白名单失败: %v\n", getCurrentTime(), err)
		return
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("[%s] [ERROR] 读取白名单失败: %v\n", getCurrentTime(), err)
		return
	}

	ips := strings.Split(string(data), "\n")
	newWhitelist := make(map[string]struct{})
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip != "" {
			newWhitelist[ip] = struct{}{}
		}
	}

	whitelistMu.Lock()
	whitelist = newWhitelist
	whitelistMu.Unlock()

	fmt.Printf("[%s] [INFO] 白名单更新成功, 共 %d 个 IP\n", getCurrentTime(), len(newWhitelist))
}

// 处理连接并转发数据
func handleConnection(client net.Conn, target string) {
	defer client.Close()
	clientAddr := client.RemoteAddr().(*net.TCPAddr).IP.String()

	whitelistMu.RLock()
	_, allowed := whitelist[clientAddr]
	whitelistMu.RUnlock()

	fmt.Printf("[%s] [INFO] 客户端连接: %s\n", getCurrentTime(), clientAddr)

	if !allowed {
		fmt.Printf("[%s] [WARNING] 拒绝连接: %s\n", getCurrentTime(), clientAddr)
		return
	}

	server, err := net.Dial("tcp", target)
	if err != nil {
		fmt.Printf("[%s] [ERROR] 无法连接目标: %s (%v)\n", getCurrentTime(), target, err)
		return
	}
	defer server.Close()

	go io.Copy(server, client)
	io.Copy(client, server)
}

// 启动代理服务器
func startProxy(listenAddr, targetAddr, whitelistURL string, updateInterval time.Duration) {
	go func() {
		for {
			updateWhitelist(whitelistURL)
			time.Sleep(updateInterval)
		}
	}()

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		fmt.Printf("[%s] [ERROR] 监听端口失败: %s (%v)\n", getCurrentTime(), listenAddr, err)
		os.Exit(1)
	}
	defer listener.Close()

	fmt.Printf("[%s] [INFO] 代理服务器已启动: %s -> %s\n", getCurrentTime(), listenAddr, targetAddr)

	for {
		client, err := listener.Accept()
		if err != nil {
			fmt.Printf("[%s] [WARNING] 客户端连接失败: %v\n", getCurrentTime(), err)
			continue
		}
		go handleConnection(client, targetAddr)
	}
}

func main() {
	L := flag.String("L", "", "格式: tcp://:端口/目标 (必填)")
	whitelistURL := flag.String("url", "", "白名单URL (必填)")
	updateInterval := flag.Int("t", 60, "更新间隔(秒) (默认 60 秒)")

	flag.Parse()

	if *L == "" || *whitelistURL == "" {
		fmt.Println("用法: ./proxy -L tcp://:端口/目标 -url 白名单URL [-t 更新间隔]")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// 解析 -L 参数
	LStr := *L
	if strings.HasPrefix(LStr, "tcp://") {
		LStr = LStr[len("tcp://"):]
	}
	parts := strings.SplitN(LStr, "/", 2)
	if len(parts) != 2 {
		fmt.Println("错误: -L 格式错误，应为 tcp://:端口/目标")
		os.Exit(1)
	}

	listenAddr := parts[0]
	targetAddr := parts[1]

	startProxy(listenAddr, targetAddr, *whitelistURL, time.Duration(*updateInterval)*time.Second)
}
