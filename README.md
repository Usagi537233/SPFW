# Secure Port Forward (SPFW)

**Secure Port Forward (SPFW)** 是一个轻量级的代理服务器，支持 **TCP、HTTP 和 PROXY 协议**，具备客户端 IP 白名单管理和可选 PROXY 协议转发功能。适用于内网访问控制、流量转发和远程服务保护等场景。

## 功能特点

- 自动识别 TCP、HTTP 和 PROXY 协议
- 支持客户端 IP 白名单：
  - 本地文件
  - 远程 URL 自动更新
  - 支持 IP 段（CIDR）
- 可选 PROXY 协议 v1 转发到后端服务
- 日志显示真实客户端 IP
- 支持 JSON 配置文件模式，可同时启动多个代理
- 调试模式可显示连接、白名单加载和协议解析日志

## 运行
~~~
Usage of ./spfw:
  -C string
        JSON 配置文件路径
  -D    显示调试日志
  -L string
        格式: tcp://:端口/目标 (必填)
  -debug
        显示调试日志
  -local string
        本地白名单文件路径
  -t int
        更新间隔(秒) (default 60)
  -url string
        白名单 URL
  -use-protocol
        是否使用 PROXY 协议转发目标
~~~
单端口运行
~~~
./spfw -L tcp://:监听端口/目标地址 -url 白名单URL -local 本地白名单文件 -use-protocol -D
~~~
or配置文件
~~~
./spfw -C config.json
~~~
