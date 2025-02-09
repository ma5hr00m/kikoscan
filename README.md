# kikoscan

[![Go Version](https://img.shields.io/badge/Go-1.23.5-blue.svg)](https://golang.org/doc/devel/release.html)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

kikoscan 是一个轻量级的端口扫描工具，使用 Go 语言开发。

> 工具目前仍在开发阶段

## 主要功能

🎯 支持多种目标扫描：IP、域名、CIDR 范围
🔍 三种扫描方式：TCP（默认）、SYN（管理员）、UDP
🎮 灵活的端口选择：预设端口、自定义范围、全端口扫描
📊 多级信息收集：基础信息、Banner 获取、服务识别
🎨 丰富的输出格式：文本、JSON、CSV
📝 完善的日志系统：支持不同级别，彩色输出
⚡ 并发扫描：高效的协程池管理
🔄 自动域名解析：自动将域名转换为 IP
⏱️ 可配置的超时设置：连接超时和读取超时
💻 跨平台支持：Windows、Linux、macOS

## 使用方法

### 命令行参数

```
-target      目标IP、域名或CIDR范围
-ports       端口范围（如：80,443 或 1-1000）
-type        扫描类型（tcp/syn/udp）
-port-level  端口扫描级别（0-2）
-info-level  信息收集级别（0-2）
-output      输出格式（text/json/csv）
-output-file 输出文件路径
-log-level   日志级别（debug/info/warn/error）
-threads     并发线程数（默认50）
```

### 使用示例

1. 基础扫描（默认使用常用端口）
```bash
go run main.go -target example.com
```

2. 指定端口范围扫描
```bash
go run main.go -target example.com -ports 80,443,8080-8090
```

3. UDP 端口扫描
```bash
go run main.go -target example.com -ports 53,161,162 -type udp
```

4. CIDR 范围扫描
```bash
go run main.go -target 192.168.1.0/24 -ports 80,443
```

5. 详细信息收集
```bash
go run main.go -target example.com -info-level 1 -log-level debug
```

6. 输出到 JSON 文件
```bash
go run main.go -target example.com -output json -output-file results.json
```

7. 指定并发线程数
```bash
go run main.go -target example.com -threads 100
```

### 端口扫描级别说明

- 级别 0：仅扫描常用端口（如 80, 443, 22 等）
- 级别 1：扫描前 1000 个端口
- 级别 2：扫描所有端口（1-65535）

### 信息收集级别说明

- 级别 0：仅显示端口状态和服务名称
- 级别 1：显示详细信息，包括 Banner 和时间戳

### 输出格式示例

1. 文本格式（默认）
```
[TCP] 192.168.1.1:80 open (HTTP)
```

2. JSON 格式
```json
{
  "ip": "192.168.1.1",
  "port": 80,
  "state": "open",
  "service": "HTTP",
  "protocol": "TCP",
  "timestamp": "2025-02-09T18:21:37+08:00"
}
```

3. CSV 格式
```csv
IP,Port,Protocol,State,Service,Banner,Timestamp
192.168.1.1,80,TCP,open,HTTP,,2025-02-09T18:21:37+08:00
```
