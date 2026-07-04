# Python-BitTorrent-Tracker

一个高性能、内存型的 BitTorrent Tracker 服务端，同时支持 HTTP 和 UDP 协议，严格遵循 BitTorrent 协议规范。

## 目录

- [功能特性](#功能特性)
  - [双协议支持](#双协议支持)
  - [双栈网络支持](#双栈网络支持)
  - [高性能设计](#高性能设计)
  - [状态持久化](#状态持久化)
  - [安全特性](#安全特性)
  - [管理功能](#管理功能)
- [环境需求](#环境需求)
- [快速开始](#快速开始)
  - [1. 安装依赖](#1-安装依赖)
  - [2. 启动服务](#2-启动服务)
- [详细部署教程](#详细部署教程)
  - [方式一：直接运行](#方式一直接运行)
    - [步骤 1：准备目录](#步骤-1准备目录)
    - [步骤 2：安装依赖](#步骤-2安装依赖)
    - [步骤 3：创建启动脚本](#步骤-3创建启动脚本)
    - [步骤 4：启动服务](#步骤-4启动服务)
  - [方式二：systemd 服务部署（推荐生产环境）](#方式二systemd-服务部署推荐生产环境)
    - [步骤 1：创建专用用户](#步骤-1创建专用用户)
    - [步骤 2：准备目录和文件](#步骤-2准备目录和文件)
    - [步骤 3：安装依赖到系统或虚拟环境](#步骤-3安装依赖到系统或虚拟环境)
    - [步骤 4：创建环境变量配置文件](#步骤-4创建环境变量配置文件)
    - [步骤 5：创建 systemd 服务文件](#步骤-5创建-systemd-服务文件)
    - [步骤 6：启动并启用服务](#步骤-6启动并启用服务)
    - [常用管理命令](#常用管理命令)
  - [方式三：Docker 部署](#方式三docker-部署)
    - [步骤 1：创建 Dockerfile](#步骤-1创建-dockerfile)
    - [步骤 2：构建镜像](#步骤-2构建镜像)
    - [步骤 3：运行容器](#步骤-3运行容器)
    - [使用 docker-compose](#使用-docker-compose)
  - [方式四：反向代理配置（Nginx）](#方式四反向代理配置nginx)
    - [Nginx 配置示例](#nginx-配置示例)
    - [重要说明](#重要说明)
- [配置详解](#配置详解)
  - [监听地址与端口](#监听地址与端口)
  - [时间间隔配置](#时间间隔配置)
  - [数据存储配置](#数据存储配置)
  - [容量限制配置](#容量限制配置)
  - [安全与认证配置](#安全与认证配置)
  - [UDP 协议配置](#udp-协议配置)
  - [布尔值说明](#布尔值说明)
- [API 端点](#api-端点)
  - [公共端点（无需认证）](#公共端点无需认证)
    - [`GET /`](#get-)
    - [`GET /health`](#get-health)
    - [`GET /announce`](#get-announce)
    - [`GET /scrape` 或 `GET /scrape/<hash1>/<hash2>/...`](#get-scrape-或-get-scrapehash1hash2)
  - [管理端点（需要 `X-API-Key` 请求头）](#管理端点需要-x-api-key-请求头)
    - [`POST /add_torrent_info`](#post-add_torrent_info)
    - [`GET /stats`](#get-stats)
    - [`POST /save_state`](#post-save_state)
    - [`POST /shutdown`](#post-shutdown)
- [私有 Tracker 模式](#私有-tracker-模式)
  - [HTTP 模式启用](#http-模式启用)
  - [UDP 模式启用](#udp-模式启用)
- [协议兼容性](#协议兼容性)
  - [BEP 3 兼容细节](#bep-3-兼容细节)
  - [BEP 15 兼容细节](#bep-15-兼容细节)
- [注意事项](#注意事项)

---

## 功能特性

### 双协议支持
- **HTTP Tracker**：完整实现 BEP 3 规范，同时支持 compact（BEP 23）和非 compact 两种 peer 列表格式
- **UDP Tracker**：基于 asyncio 协程实现 BEP 15 协议，无线程池设计，高并发下性能优异，信号量限制并发数（默认 256）防止内存溢出

### 双栈网络支持
- 原生支持 IPv4 和 IPv6
- 自动处理 IPv4-mapped IPv6、6to4、Teredo 等特殊地址格式
- 默认尝试 IPv6 双栈监听，失败自动回退到 IPv4
- UDP 接收缓冲区设置为 8MB，应对突发流量

### 高性能设计
- 纯内存存储，读写操作均在内存完成
- 使用可重入锁（RLock）保证线程安全
- 统计信息 10 秒缓存，减少重复计算
- UDP 响应严格限制 MTU 为 1400 字节，避免 IP 分片
- Peer 列表随机采样返回，符合 BEP 15 建议

### 状态持久化
- 自动定期保存状态到 JSON 文件（默认 300 秒）
- 临时文件 + 原子替换（`os.replace`）写入，保证文件完整性
- 启动时自动加载历史状态，过期 peer 自动过滤
- 损坏记录自动跳过，单条失败不影响整体加载
- 优雅关闭时自动保存状态

### 安全特性
- 可选 API 密钥认证，管理端点默认受保护
- 支持私有 Tracker 模式（announce/scrape 需要 key 验证）
- 可配置是否允许私有 IP 地址接入
- 反向代理支持（自动识别 `X-Forwarded-For` / `X-Real-IP` 头）
- 常量时间字符串比较（`hmac.compare_digest`），防止时序攻击
- UDP 连接 ID 有效期 2 分钟且不刷新，防止放大攻击

### 管理功能
- 查询所有种子的详细统计信息（名称、大小、做种数、下载数、累计流量等）
- 手动触发状态保存
- 优雅关闭服务（支持 SIGINT/SIGTERM 信号）
- 健康检查端点，方便接入监控系统
- 支持通过 API 添加/更新种子元数据

---

## 环境需求

| 项目 | 要求 |
|------|------|
| Python 版本 | **3.11 及以上** |
| 操作系统 | Linux（推荐）、macOS、Windows（部分功能有限制） |
| 依赖包 | `bencodepy`、`orjson`、`flask`、`werkzeug` |
| 网络 | 需要开放 TCP 和 UDP 对应端口（默认 6969） |

---

## 快速开始

### 1. 安装依赖

```bash
pip install bencodepy orjson flask werkzeug
```

### 2. 启动服务

```bash
python tracker.py
```

默认监听 `0.0.0.0:6969`（TCP 和 UDP 同端口），启动后可以访问 `http://your-server-ip:6969/health` 验证服务是否正常运行。

---

## 详细部署教程

### 方式一：直接运行

适合测试或小型站点使用。

#### 步骤 1：准备目录

```bash
# 创建工作目录
mkdir -p /opt/bittorrent-tracker
cd /opt/bittorrent-tracker

# 将 tracker.py 上传到该目录
```

#### 步骤 2：安装依赖

```bash
# 建议使用虚拟环境
python3.11 -m venv venv
source venv/bin/activate
pip install bencodepy orjson flask werkzeug
```

#### 步骤 3：创建启动脚本

创建 `start.sh`：

```bash
#!/bin/bash
cd /opt/bittorrent-tracker
source venv/bin/activate

# 配置环境变量
export TRACKER_API_KEY="your-secret-key-change-this"
export TRACKER_PORT=6969
export TRACKER_UDP_PORT=6969
export DATA_FILE="/opt/bittorrent-tracker/data/tracker_state.json"
export PEER_TIMEOUT=1800
export AUTO_SAVE_INTERVAL=300

exec python tracker.py
```

```bash
chmod +x start.sh

# 创建数据目录
mkdir -p data
```

#### 步骤 4：启动服务

```bash
./start.sh
```

---

### 方式二：systemd 服务部署（推荐生产环境）

适合长期稳定运行的生产环境。

#### 步骤 1：创建专用用户

```bash
useradd -r -s /sbin/nologin bt-tracker
```

#### 步骤 2：准备目录和文件

```bash
mkdir -p /opt/bittorrent-tracker/data
chown bt-tracker:bt-tracker /opt/bittorrent-tracker/data

# 将 tracker.py 放到 /opt/bittorrent-tracker/
cp tracker.py /opt/bittorrent-tracker/
chown -R bt-tracker:bt-tracker /opt/bittorrent-tracker
```

#### 步骤 3：安装依赖到系统或虚拟环境

```bash
cd /opt/bittorrent-tracker
python3.11 -m venv venv
source venv/bin/activate
pip install bencodepy orjson flask werkzeug
chown -R bt-tracker:bt-tracker venv
```

#### 步骤 4：创建环境变量配置文件

创建 `/etc/bittorrent-tracker.conf`：

```ini
# 监听配置
TRACKER_IP=0.0.0.0
TRACKER_PORT=6969
TRACKER_UDP_PORT=6969

# 间隔配置
TRACKER_MIN_INTERVAL=900
TRACKER_INTERVAL=1800
PEER_TIMEOUT=1800

# 存储配置
DATA_FILE=/opt/bittorrent-tracker/data/tracker_state.json
AUTO_SAVE_INTERVAL=300
CLEANUP_INTERVAL=120

# 安全配置 - 请修改为自己的密钥
TRACKER_API_KEY=your-very-secret-api-key-here
TRACKER_PROTECT_ANNOUNCE=false
TRACKER_PROTECT_SCRAPE=false
TRACKER_ALLOW_PRIVATE_IP=false
# 仅在使用反向代理（如 Nginx）时设为 true；独立部署时设为 false，否则可被伪造 X-Forwarded-For 头欺骗
TRACKER_BEHIND_PROXY=false

# UDP 配置
UDP_CONNECTION_TIMEOUT=120
UDP_CONN_CLEANUP_INTERVAL=30
```

```bash
chmod 600 /etc/bittorrent-tracker.conf
chown bt-tracker:bt-tracker /etc/bittorrent-tracker.conf
```

#### 步骤 5：创建 systemd 服务文件

创建 `/etc/systemd/system/bittorrent-tracker.service`：

```ini
[Unit]
Description=BitTorrent Tracker Service
After=network.target
Wants=network.target

[Service]
Type=simple
User=bt-tracker
Group=bt-tracker
WorkingDirectory=/opt/bittorrent-tracker
EnvironmentFile=/etc/bittorrent-tracker.conf
ExecStart=/opt/bittorrent-tracker/venv/bin/python /opt/bittorrent-tracker/tracker.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=bittorrent-tracker

# 资源限制
LimitNOFILE=65536
LimitNPROC=4096

# 安全加固
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/bittorrent-tracker/data

[Install]
WantedBy=multi-user.target
```

#### 步骤 6：启动并启用服务

```bash
# 重新加载 systemd 配置
systemctl daemon-reload

# 启动服务
systemctl start bittorrent-tracker

# 设置开机自启
systemctl enable bittorrent-tracker

# 查看状态
systemctl status bittorrent-tracker

# 查看日志
journalctl -u bittorrent-tracker -f
```

#### 常用管理命令

```bash
# 重启服务
systemctl restart bittorrent-tracker

# 停止服务
systemctl stop bittorrent-tracker

# 查看最近 100 行日志
journalctl -u bittorrent-tracker -n 100
```

---

### 方式三：Docker 部署

#### 步骤 1：创建 Dockerfile

在 `tracker.py` 同目录创建 `Dockerfile`：

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# 安装依赖
RUN pip install --no-cache-dir bencodepy orjson flask werkzeug

# 复制代码
COPY tracker.py .

# 创建数据目录
RUN mkdir -p /data

# 环境变量默认值
ENV TRACKER_IP=0.0.0.0 \
    TRACKER_PORT=6969 \
    TRACKER_UDP_PORT=6969 \
    DATA_FILE=/data/tracker_state.json \
    TRACKER_ALLOW_PRIVATE_IP=false \
    TRACKER_BEHIND_PROXY=false

# 暴露端口（TCP 和 UDP）
EXPOSE 6969/tcp
EXPOSE 6969/udp

# 数据卷
VOLUME ["/data"]

# 启动命令
CMD ["python", "tracker.py"]
```

#### 步骤 2：构建镜像

```bash
docker build -t bittorrent-tracker .
```

#### 步骤 3：运行容器

```bash
docker run -d \
  --name bittorrent-tracker \
  --restart always \
  -p 6969:6969/tcp \
  -p 6969:6969/udp \
  -v /opt/bittorrent-tracker/data:/data \
  -e TRACKER_API_KEY="your-secret-key" \
  -e TRACKER_ALLOW_PRIVATE_IP=false \
  bittorrent-tracker
```

#### 使用 docker-compose

创建 `docker-compose.yml`：

```yaml
version: '3.8'

services:
  tracker:
    build: .
    container_name: bittorrent-tracker
    restart: always
    ports:
      - "6969:6969/tcp"
      - "6969:6969/udp"
    volumes:
      - ./data:/data
    environment:
      - TRACKER_API_KEY=your-secret-key-change-this
      - TRACKER_ALLOW_PRIVATE_IP=false
      - TRACKER_BEHIND_PROXY=true
      - PEER_TIMEOUT=1800
      - AUTO_SAVE_INTERVAL=300
    ulimits:
      nofile:
        soft: 65536
        hard: 65536
```

启动：

```bash
docker-compose up -d
```

---

### 方式四：反向代理配置（Nginx）

如果需要通过 HTTPS 访问管理 API，或者需要在同一服务器部署多个服务，可以使用 Nginx 反向代理。

#### Nginx 配置示例

```nginx
server {
    listen 80;
    server_name tracker.example.com;

    # 重定向到 HTTPS
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name tracker.example.com;

    # SSL 证书配置
    ssl_certificate /etc/letsencrypt/live/tracker.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/tracker.example.com/privkey.pem;

    # 日志
    access_log /var/log/nginx/tracker.access.log;
    error_log /var/log/nginx/tracker.error.log;

    # 注意：Tracker 的 announce/scrape 端点通常不建议走 HTTPS，
    # 因为很多 BT 客户端不支持 HTTPS Tracker，建议 HTTP 和 HTTPS 分开
    # 这里只代理管理 API 端点走 HTTPS

    location /health {
        proxy_pass http://127.0.0.1:6969;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location /stats {
        proxy_pass http://127.0.0.1:6969;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location /add_torrent_info {
        proxy_pass http://127.0.0.1:6969;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location /save_state {
        proxy_pass http://127.0.0.1:6969;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location /shutdown {
        proxy_pass http://127.0.0.1:6969;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

#### 重要说明

BitTorrent 客户端对 HTTPS Tracker 的支持并不统一，**建议 announce 和 scrape 端点直接暴露 HTTP（端口 6969）**，不要走反向代理 HTTPS，否则可能导致部分客户端无法连接。管理 API 可以走 HTTPS 反向代理。

配置反向代理后，需要设置环境变量 `TRACKER_BEHIND_PROXY=true`，否则服务端获取到的是 Nginx 的 IP 而不是真实客户端 IP。

---

## 配置详解

所有配置均通过环境变量设置，无需修改源码。

### 监听地址与端口

| 环境变量 | 默认值 | 说明 |
|---------|--------|------|
| `TRACKER_IP` | `0.0.0.0` | 监听 IP 地址。设为 `::` 启用 IPv6 双栈；设为具体 IPv4/IPv6 地址只监听对应地址 |
| `TRACKER_PORT` | `6969` | HTTP 监听端口（TCP） |
| `TRACKER_UDP_PORT` | 同 `TRACKER_PORT` | UDP 监听端口，默认与 HTTP 端口一致 |

### 时间间隔配置

| 环境变量 | 默认值 | 说明 |
|---------|--------|------|
| `TRACKER_MIN_INTERVAL` / `MIN_INTERVAL` | `900` | 最小 announce 间隔（秒），客户端不得低于此频率重新 announce。BEP 3 规定为 900 秒（15 分钟） |
| `TRACKER_INTERVAL` | 同 `MIN_INTERVAL` | 普通重 announce 间隔（秒），客户端建议按此间隔刷新 |
| `PEER_TIMEOUT` | `1800` | Peer 过期时间（秒），超时未更新的 peer 将被自动清理。默认 30 分钟 |

### 数据存储配置

| 环境变量 | 默认值 | 说明 |
|---------|--------|------|
| `DATA_FILE` | `tracker_state.json` | 状态持久化文件路径，建议使用绝对路径 |
| `AUTO_SAVE_INTERVAL` | `300` | 自动保存间隔（秒），默认 5 分钟 |
| `CLEANUP_INTERVAL` | `120` | 过期 peer 清理间隔（秒），默认 2 分钟 |

### 容量限制配置

| 环境变量 | 默认值 | 说明 |
|---------|--------|------|
| `MAX_PEERS_PER_TORRENT` | `1000` | 每个种子最大 peer 数量，达到上限后拒绝新 peer 加入（已存在的 peer 仍可更新） |
| `MAX_NUMWANT` | `200` | 单次 announce 返回 peer 数量的上限，对应客户端 如`numwant=-1`（尽可能多）的情况 |

### 安全与认证配置

| 环境变量 | 默认值 | 说明 |
|---------|--------|------|
| `TRACKER_API_KEY` | `""`（空） | API 密钥，用于管理端点认证和私有 Tracker 模式。**生产环境必须设置** |
| `TRACKER_PROTECT_ANNOUNCE` | `false` | 是否对 announce 端点启用密钥保护（即私有 Tracker 模式） |
| `TRACKER_PROTECT_SCRAPE` | `false` | 是否对 scrape 端点启用密钥保护 |
| `TRACKER_ALLOW_PRIVATE_IP` | `true` | 是否接受来自私有 IP 地址（如 192.168.x.x、10.x.x.x、127.0.0.1 等）的 announce。公网部署建议设为 `false` |
| `TRACKER_BEHIND_PROXY` | `false` | 是否部署在反向代理之后。设为 `true` 时会从 `X-Forwarded-For` 或 `X-Real-IP` 头获取真实客户端 IP |

### UDP 协议配置

| 环境变量 | 默认值 | 说明 |
|---------|--------|------|
| `UDP_CONNECTION_TIMEOUT` | `120` | UDP 连接 ID 有效期（秒），不建议修改 |
| `UDP_CONN_CLEANUP_INTERVAL` | `30` | UDP 过期连接清理间隔（秒） |

### 布尔值说明

布尔类型环境变量不区分大小写，接受以下值表示 `true`：`1`、`true`、`yes`、`on`。其他任意值均视为 `false`！

---

## API 端点

### 公共端点（无需认证）

#### `GET /`
服务信息端点，返回服务状态、运行时间、可用端点列表。

**响应示例：**
```json
{
  "status": "ok",
  "service": "BitTorrent Tracker",
  "uptime": 12345.678,
  "endpoints": {
    "announce": "/announce",
    "scrape": "/scrape",
    "health": "/health",
    "stats": "/stats (requires API key)"
  }
}
```

#### `GET /health`
健康检查端点，用于监控系统检测服务是否存活。

**响应示例：**
```json
{
  "status": "ok",
  "uptime": 12345.678,
  "torrents": 42,
  "udp_port": 6969,
  "http_port": 6969
}
```

#### `GET /announce`
BitTorrent HTTP announce 端点（BEP 3），这是 BT 客户端通信的核心端点。

**支持参数：**
- `info_hash`：20 字节种子 info_hash（支持原始二进制或 40 字符十六进制）
- `peer_id`：20 字节 peer ID（支持原始二进制或 40 字符十六进制）
- `port`：客户端监听端口（1-65535）
- `uploaded`：已上传字节数
- `downloaded`：已下载字节数
- `left`：剩余字节数
- `event`：事件类型，可选值：`started`、`stopped`、`completed`
- `numwant`：请求返回的 peer 数量，默认 50，`-1` 表示尽可能多（受 `MAX_NUMWANT` 限制）
- `compact`：设为 `1` 启用 compact 响应格式（BEP 23），推荐使用
- `ip`：客户端声明自己的 IP（BEP 7），可选
- `key`：私有 Tracker 模式下的认证密钥

响应为 bencode 编码格式。

#### `GET /scrape` 或 `GET /scrape/<hash1>/<hash2>/...`
BitTorrent scrape 端点，用于批量查询种子统计信息。

- `info_hash` 参数可重复指定，查询多个种子
- URL 路径支持直接写十六进制 info_hash，多个用 `/` 分隔
- 单次最多查询 74 个 info_hash（实现限制，用于控制响应大小）

响应为 bencode 编码格式，包含每个种子的 `complete`（做种数）、`downloaded`（完成数）、`incomplete`（下载数）。

---

### 管理端点（需要 `X-API-Key` 请求头）

以下端点需要在 HTTP 请求头中携带 `X-API-Key: your-api-key`，值与 `TRACKER_API_KEY` 一致。

#### `POST /add_torrent_info`
注册或更新种子的元数据信息。

**请求体（JSON）：**
```json
{
  "info_hash": "0123456789abcdef0123456789abcdef01234567",
  "name": "Example File Name",
  "size": 1073741824,
  "piece_length": 524288,
  "comment": "This is an example torrent",
  "created_by": "Tracker Admin"
}
```

字段说明：
- `info_hash`：必填，40 字符十六进制 info_hash
- `name`：种子名称
- `size`：种子总大小（字节）
- `piece_length`：分片大小（字节）
- `comment`：备注信息
- `created_by`：创建者信息

#### `GET /stats`
查询所有种子的详细统计信息，返回 JSON 格式。

**响应示例结构：**
```json
{
  "0123456789abcdef0123456789abcdef01234567": {
    "name": "Example File",
    "size": 1073741824,
    "creation_date": 1700000000.0,
    "complete": 10,
    "incomplete": 5,
    "downloaded": 123,
    "uploaded_bytes": 1099511627776,
    "downloaded_bytes": 549755813888,
    "peers": 15
  }
}
```

字段说明：
- `complete`：做种者数量（seeders，已完成下载）
- `incomplete`：下载者数量（leechers，未完成下载）
- `downloaded`：累计完成下载次数（BEP 3 语义）
- `uploaded_bytes`：所有 peer 累计上传字节数
- `downloaded_bytes`：所有 peer 累计下载字节数
- `peers`：当前活跃 peer 总数

#### `POST /save_state`
手动触发状态保存到磁盘，正常情况下不需要调用，服务会自动定期保存。

#### `POST /shutdown`
优雅关闭 Tracker 服务，关闭前会自动保存状态。

---

## 私有 Tracker 模式

启用私有 Tracker 模式后，客户端必须在请求中携带正确的 key 才能进行 announce 和 scrape，适合内部站点使用。

### HTTP 模式启用

```bash
export TRACKER_API_KEY="your-private-key"
export TRACKER_PROTECT_ANNOUNCE=true
export TRACKER_PROTECT_SCRAPE=true
```

客户端需要在 announce/scrape 的 query string 中添加 `key=your-private-key` 参数。

### UDP 模式启用

UDP 模式下的 key 是 4 字节整数，服务端按以下优先级从 `TRACKER_API_KEY` 派生：
1. 如果 API key 是纯整数，直接作为 UDP key
2. 如果 API key 是 8 字符十六进制，解析为整数
3. 其他任意字符串，取 SHA-256 哈希的前 4 字节作为 key

客户端需要在 UDP announce 请求的 key 字段填入对应的 4 字节整数。

**注意：** 启用 `TRACKER_PROTECT_SCRAPE` 后，UDP scrape 将被禁用，这是因为 UDP scrape 协议没有携带 key 字段的位置。

---

## 协议兼容性

本 Tracker 严格遵循以下 BitTorrent 增强协议（BEP）：

| BEP 编号 | 协议名称 | 支持情况 |
|---------|---------|---------|
| BEP 3 | BitTorrent Protocol Specification（HTTP Tracker） | 完整支持 |
| BEP 7 | IPv6 Tracker Extension | 完整支持，`peers` 为 IPv4，`peers6` 为 IPv6 |
| BEP 15 | UDP Tracker Protocol | 完整支持，基于 asyncio 实现 |
| BEP 23 | Tracker Returns Compact Peer Lists | 完整支持，`compact=1` 启用 |
| BEP 48 | Tracker Protocol Extension: Scrape | 完整支持，最多 74 个 info_hash |

### BEP 3 兼容细节
- 完整返回 `interval`、`min interval`、`complete`、`incomplete`、`downloaded` 字段
- `completed` 事件正确递增下载完成计数，强制将 `left` 视为 0
- `left` 字段为负数时视为极大值（标记为 leecher），不会误判为 seeder

### BEP 15 兼容细节
- Connect / Announce / Scrape / Error 四种 action 完整实现
- Announce 响应按客户端地址族（IPv4/IPv6）返回对应格式的 peer 列表
- 响应大小严格限制在 1400 字节 MTU 内，避免 IP 分片
- 连接 ID 有效期 2 分钟，不刷新过期时间，防止连接劫持
- `numwant=-1` 正确映射到 `MAX_NUMWANT`

---

## 注意事项

1. **数据持久化**：本 Tracker 是内存型服务，所有运行时数据都在内存中，依赖定期自动保存到 JSON 文件。服务意外重启会丢失最后一次自动保存之后的数据。

2. **API 密钥安全**：未设置 `TRACKER_API_KEY` 时，所有管理端点（`/stats`、`/shutdown` 等）将完全暴露，公网部署前必须设置强密钥。

3. **私有 IP 过滤**：默认 `TRACKER_ALLOW_PRIVATE_IP=true`，适合内网测试使用；公网部署建议设为 `false`，防止无效的内网 IP 污染 peer 列表。

4. **防火墙配置**：部署时需要同时开放 TCP 和 UDP 的对应端口（默认 6969），只开放 TCP 会导致 UDP Tracker 无法使用。

5. **文件描述符限制**：高并发场景下需要调大系统的文件描述符限制（systemd 配置中已设置 `LimitNOFILE=65536`），否则可能出现 "too many open files" 错误。

6. **NTP 时间同步**：虽然本服务不依赖时间戳认证，但建议服务器开启 NTP 时间同步，保证日志时间和统计数据准确。

7. **HTTPS 不推荐用于 announce**：绝大多数 BT 客户端对 HTTPS Tracker 支持不好，建议 announce 和 scrape 端点直接使用 HTTP，管理 API 可以走 HTTPS 反向代理。

8. **状态文件备份**：`tracker_state.json` 是唯一的数据文件，建议定期备份，防止磁盘损坏导致数据丢失。
