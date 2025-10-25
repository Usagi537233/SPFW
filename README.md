# Secure Port Forward (SPFW)

**Secure Port Forward (SPFW)** is a lightweight proxy server that supports  **TCP, HTTP, and PROXY protocols** , with client IP whitelist/blacklist management and optional PROXY protocol forwarding capabilities. Suitable for scenarios such as intranet access control, traffic forwarding, and remote service protection.

[ENG](https://github.com/Usagi537233/SPFW/blob/main/README.md) [中文](https://github.com/Usagi537233/SPFW/blob/main/README_CN.md)

## Functional Features

-Automatically recognize TCP, HTTP, and PROXY protocols
-Support client IP whitelist/blacklist:
-Local files
-Remote URL automatic update, download failure or non 200 status does not overwrite backup file
-Supports IP Segments (CIDR)
-Each port maintains an independent list to avoid multiple instances from overlapping
-Optional PROXY protocol v1 forwarding to backend service
-The log displays the real client IP address
-Supports JSON configuration file mode and can start multiple proxy instances simultaneously
-Debugging mode can display connection, list loading, and protocol parsing logs

## Run

```text
Usage of ./spfw:
-C string
JSON configuration file path
-D displays debugging logs
-L string
Format: tcp://: Port/Target (required)
-blacklist
Do you want to use blacklist mode
-debug
Display debugging logs
-local string
Local list file path
-t int
Update interval (seconds) (default 60)
-url string
List URL
-use-protocol
Should we use the PROXY protocol to forward the target
```
Single port operation
~~~
./spfw -L tcp://:listening_port/target:port -url whitelist URL
~~~
Or configuration file
~~~
./spfw -C config.json
~~~
