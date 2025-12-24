# Secure Port Forward (SPFW)

**Secure Port Forward (SPFW)** is a lightweight proxy server that supports  **TCP, HTTP, and PROXY protocols** , with client IP whitelist/blacklist management and optional PROXY protocol forwarding capabilities. Suitable for scenarios such as intranet access control, traffic forwarding, and remote service protection.

[ENG](https://github.com/Usagi537233/SPFW/blob/main/README.md) [中文](https://github.com/Usagi537233/SPFW/blob/main/README_CN.md)

## Functional Features

- Automatically recognize TCP, HTTP, and PROXY protocols
- Support client IP whitelist/blacklist and mutil iplist:
- Local files
- Remote URL automatic update, download failure or non 200 status does not overwrite backup file
- Supports IP Segments (CIDR)
- Batch port forwarding
- Each port maintains an independent list to avoid multiple instances from overlapping
- Optional PROXY protocol v1 forwarding to backend service
- The log displays the real client IP address
- Supports JSON configuration file mode and can start multiple proxy instances simultaneously
- Debugging mode can display connection, list loading, and protocol parsing logs

## Run

```text
Usage of ./spfw:
  -C string
        JSON config file path
  -D    Enable debug logging
  -L string
        tcp://[host]:port[-range]/targetHost:targetPort[-range]
  -ZH
        Use Chinese messages
  -blacklist
        Use blacklist mode
  -fallback string
        Fallback address, e.g. 127.0.0.1:8080 (forward non-allowlisted clients to this address when target is IP)
  -local string
        Local list path(s), supports glob
  -t int
        Update interval (seconds) (default 60)
  -url string
        List URL(s), comma/semicolon/space separated
  -use-protocol
        Use PROXY protocol when forwarding
```
Single port operation
~~~
./spfw -L tcp://:listening_port/target:port -url whitelistURL
~~~
Single port mutil iplist operation
~~~
./spfw -L tcp://:listening_port/target:port -url whitelistURL1,whitelistURL2
~~~
Batch Port Forwarding
~~~
tcp://:2333-2444/127.0.0.1:3333
    → Forwards ports 2333–2444 to port 3333

tcp://:2333-2444/127.0.0.1:3333-3444
    → Forwards ports 2333–2444 to 3333–3444

tcp://:2333-2444/127.0.0.1:3333-3555
    → Still forwards only to 3333–3444 range
~~~
Or configuration file
~~~
./spfw -C config.json
~~~
