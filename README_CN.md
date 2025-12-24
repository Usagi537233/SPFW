# Secure Port Forward (SPFW)

**Secure Port Forward (SPFW)** 是一个轻量级代理服务器，支持 **TCP、HTTP 和 PROXY 协议**，具备客户端 IP 白名单/黑名单管理和可选 PROXY 协议转发功能。适用于内网访问控制、流量转发和远程服务保护等场景。

[ENG](https://github.com/Usagi537233/SPFW/blob/main/README.md) [中文](https://github.com/Usagi537233/SPFW/blob/main/README_CN.md)
## 功能特点

- 自动识别 TCP、HTTP 和 PROXY 协议  
- 支持客户端 IP 白名单/黑名单：
  - 本地文件
  - 远程 URL 自动更新，下载失败或非 200 状态不覆写备用文件
  - 支持 IP 段（CIDR）
  - 每个端口独立维护列表，避免多实例覆盖
  - 单端口多IP列表（可多URL）
  - 批量端口转发
- 可选 PROXY 协议 v1 转发到后端服务  
- 日志显示真实客户端 IP  
- 支持 JSON 配置文件模式，可同时启动多个代理实例  
- 调试模式可显示连接、列表加载和协议解析日志
- 支持Fallback回落，非名单IP访问则会转发到该地址

## 运行

```text
Usage of ./spfw:
  -C string
        JSON 配置文件路径
  -D    显示调试日志
  -L string
        格式: tcp://:端口/目标 (必填)
  -blacklist
        是否使用黑名单模式
  -debug
        显示调试日志
  -fallback
        回落地址，非名单IP转发到此
  -local string
        本地列表文件路径
  -t int
        更新间隔(秒) (default 60)
  -url string
        列表 URL
  -use-protocol
        是否使用 PROXY 协议转发目标
```
单端口运行
~~~
./spfw -L tcp://:监听端口/目标地址 -url 白名单URL 
~~~
单端口多url列表运行
~~~
./spfw -L tcp://:监听端口/目标地址 -url 白名单URL1,白名单URL2 
~~~

批量端口转发
~~~
tcp://:2333-2444/127.0.0.1:3333 则2333-2444端口都转发去3333端口
tcp://:2333-2444/127.0.0.1:3333-3444 则2333-2444端口则转发去3333-3444端口
~~~
如果
~~~
tcp://:2333-2444/127.0.0.1:3333-3555 则一样只会转发去3333-3444端口
~~~
or配置文件
~~~
./spfw -C config.json
~~~
