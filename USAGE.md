# mDNS 协议资产测绘 CLI 工具使用与操作说明文档

## 1. 软件简介 (Software Introduction)

**mDNS 资产测绘 CLI 工具**（`mdns-survey`）是一款基于 Go 语言开发的高性能网络资产测绘与局域网服务发现程序。

本工具基于 Multicast DNS (mDNS, RFC 6762) 与 DNS-Based Service Discovery (DNS-SD, RFC 6763) 协议规范，能够根据用户指定的 **IP 网段** 与 **端口范围**，自动对网络中的设备与服务进行探测，提取并输出包含 `IP`、`Port`、`Hostname`、`TTL` 以及深层 `Banner` 属性（如设备型号 `model`、固件版本 `fwVer`、HTTP 访问路径 `path` 等）的结构化资产信息。

---

## 2. 核心功能特性 (Key Features)

* **灵活的输入目标解析**：
  * **IP 网段**：支持 CIDR 格式（如 `192.168.1.0/24`）、IP 范围格式（如 `192.168.1.1-192.168.1.100` 或 `192.168.1.1-100`）、单个 IP（如 `192.168.1.50`）。
  * **端口范围**：支持端口区间（如 `1-65535`）、离散端口列表（如 `80,445,5000`）及组合格式（如 `80,8080-8085`）。
* **双模 mDNS 探测机制**：
  * **组播发现 (Multicast Probe)**：向 `224.0.0.251:5353` 发送 DNS-SD 查询，覆盖同一二层广播域中的全量 mDNS 节点。
  * **单播探测 (Unicast Probe)**：支持对指定目标 IP 网段并发发送 UDP 5353 单播请求，应对组播受限或跨子网测绘场景。
* **Banner 深度识别与关联**：
  * 自动关联 PTR、SRV、TXT、A、AAAA 记录。
  * 深入分割提取 TXT 记录中的多元属性（如智联网关/NAS 属性 `accessType=https,model=TS-X64,fwVer=5.2.9`，苹果设备属性 `model=Xserve` 等）。
  * 自动还原 DNS 域名 label 转义字符（如将 `slw-nas\ [24:5e:be:69:a3:13]` 转义还原为人类可读的 `slw-nas [24:5e:be:69:a3:13]`）。
* **规范化输出**：
  * 输出严格匹配 YAML/Text 格式规范，清晰展示 `services:` 分项及 `answers: PTR:` 总结。
* **内建自动化测试套件**：
  * 内置包含全流程 Mock UDP mDNS 服务端的端到端自动化测试，确保程序稳定可靠。

---

## 3. 编译与安装 (Build & Installation)

### 前置要求
* Go 语言环境 (Go 1.18 或更高版本)

### 编译步骤
在项目根目录运行以下命令编译可执行文件：

```bash
# Windows 环境编译
go build -o mdns-survey.exe main.go

# Linux / macOS 环境编译
go build -o mdns-survey main.go
```

---

## 4. 命令行参数说明 (CLI Usage & Flags)

```text
Usage:
  mdns-survey.exe -i <IP/CIDR/Range> -p <Port/Range> [options]

Options:
  -i, --ip string
    	目标 IP、CIDR 网段或 IP 范围（例如: 192.168.1.0/24, 192.168.1.1-100, 10.0.0.1）
  -p, --port string
    	目标端口或端口范围（例如: 1-65535, 80,445,5000）
  -t, --timeout int
    	探测响应等待超时时间，单位：秒（默认: 3）
  -c, --concurrent int
    	单播探测并发协程数上限（默认: 100）
  -o, --output string
    	将测绘结果输出并保存至指定的文件路径
  -h, --help
    	显示帮助信息
```

---

## 5. 典型使用示例 (Examples)

### 示例 1：探测 C 段网段的全端口资产
```bash
.\mdns-survey.exe -i 192.168.1.0/24 -p 1-65535
```

### 示例 2：探测指定 IP 范围与常用服务端口，并保存结果至文件
```bash
.\mdns-survey.exe -i 192.168.1.1-100 -p 80,445,5000 -o result.txt
```

### 示例 3：高并发快速测绘大网段（自定义超时与并发数）
```bash
.\mdns-survey.exe -i 10.0.0.0/16 -p 1-65535 -t 5 -c 500
```

---

## 6. 标准输出结果格式样例 (Sample Output)

```yaml
services:
  9/tcp workstation:
    Name=slw-nas [24:5e:be:69:a3:13]
    IPv4=192.168.1.100
    IPv6=fe80::265e:beff:fe69:a313
    Hostname=slw-nas.local
    TTL=10
  5000/tcp http:
    Name=slw-nas
    IPv4=192.168.1.100
    IPv6=fe80::265e:beff:fe69:a313
    Hostname=slw-nas.local
    TTL=10
    path=/
  445/tcp smb:
    Name=slw-nas
    IPv4=192.168.1.100
    IPv6=fe80::265e:beff:fe69:a313
    Hostname=slw-nas.local
    TTL=10
  5000/tcp qdiscover:
    Name=slw-nas
    IPv4=192.168.1.100
    IPv6=fe80::265e:beff:fe69:a313
    Hostname=slw-nas.local
    TTL=10
    accessType=https,accessPort=86,model=TS-X64,displayModel=TS-464C,fwVer=5.2.9,fwBuildNum=20260214
  device-info:
    Name=slw-nas(AFP)
    IPv4=192.168.1.100
    IPv6=fe80::265e:beff:fe69:a313
    Hostname=slw-nas.local
    TTL=10
    model=Xserve
  548/tcp afpovertcp:
    Name=slw-nas(AFP)
    IPv4=192.168.1.100
    IPv6=fe80::265e:beff:fe69:a313
    Hostname=slw-nas.local
    TTL=10
answers:
  PTR:
    _workstation._tcp.local
    _http._tcp.local
    _smb._tcp.local
    _qdiscover._tcp.local
    _device-info._tcp.local
    _afpovertcp._tcp.local
```

---

## 7. 测试与验证指南 (Testing Guide)

软件包含全套单元测试与端到端自动化 Mock 测试，无需真实设备连接即可验证：

```bash
# 运行项目中所有的单元与 Mock 测试
go test -v ./...

# 强制不使用缓存重新运行全量测试
go test -v -count=1 ./...
```
