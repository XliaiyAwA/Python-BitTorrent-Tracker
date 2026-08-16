# Python-BitTorrent-Tracker

一个高性能、内存型的 BitTorrent Tracker 服务端，同时支持 HTTP 和 UDP 协议，严格遵循 BitTorrent 协议规范。支持 TOML 配置文件 + 环境变量双重配置方式，使用 SQLite 作为持久化存储（Write-Behind 异步批量落库），兼容旧版 JSON 状态文件自动迁移。

## 目录

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
  - [日志配置](#日志配置)
  - [时间间隔配置](#时间间隔配置)
  - [数据存储配置](#数据存储配置)
  - [容量限制配置](#容量限制配置)
  - [安全与认证配置](#安全与认证配置)
  - [UDP 协议配置](#udp-协议配置)
  - [UDP 速率限制配置（防 DDoS）](#udp-速率限制配置防-ddos)
  - [HTTP 速率限制配置](#http-速率限制配置)
  - [布尔值说明](#布尔值说明)
- [API 端点](#api-端点)
  - [公共端点（无需认证）](#公共端点无需认证)
    - [`GET /`](#get-)
    - [`GET /health`](#get-health)
    - [`GET /metrics`](#get-metrics)
    - [`GET /announce`](#get-announce)
    - [`GET /scrape` 或 `GET /scrape/<hash1>/<hash2>/...`](#get-scrape-或-get-scrapehash1hash2)
  - [管理端点（需要 `X-API-Key` 请求头）](#管理端点需要-x-api-key-请求头)
    - [`GET /export_state`](#get-export_state)
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

## 环境需求

| 项目 | 要求 |
|------|------|
| Python 版本 | **3.11 及以上**（使用 `asyncio.TaskGroup`、`tomllib`） |
| 操作系统 | Linux（推荐）、macOS、Windows（部分功能有限制） |
| 依赖包 | `bencodepy`、`orjson`、`aiohttp` |
| 配置文件 | 可选：`tracker.toml`（与 `tracker.py` 同目录） |
| 网络 | 需要开放 TCP 和 UDP 对应端口（默认 6969） |

---

## 快速开始

### 1. 安装依赖

```bash
pip install bencodepy orjson aiohttp
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
pip install bencodepy orjson aiohttp
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
export TRACKER_DB_FILE="/opt/bittorrent-tracker/data/tracker_state.db"
export TRACKER_PEER_TIMEOUT=1800
export AUTO_SAVE_INTERVAL=300
export LOG_LEVEL="INFO"

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
pip install bencodepy orjson aiohttp
chown -R bt-tracker:bt-tracker venv
```

#### 步骤 4：创建环境变量配置文件

创建 `/etc/bittorrent-tracker.conf`：

```ini
# 监听配置
TRACKER_IP=0.0.0.0
TRACKER_PORT=6969
TRACKER_UDP_PORT=6969

# 日志配置
LOG_LEVEL=INFO

# 间隔配置
TRACKER_MIN_INTERVAL=900
TRACKER_INTERVAL=1800
TRACKER_PEER_TIMEOUT=1800

# 存储配置
TRACKER_DB_FILE=/opt/bittorrent-tracker/data/tracker_state.db
TRACKER_DB_FLUSH_INTERVAL=3
AUTO_SAVE_INTERVAL=300
CLEANUP_INTERVAL=120

# 容量限制
MAX_PEERS_PER_TORRENT=1000
MAX_TORRENTS=1000000

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

# UDP 速率限制
UDP_RATE_LIMIT_ENABLED=true
UDP_RATE_LIMIT_PACKET_PER_SEC=20
UDP_RATE_LIMIT_CONNECT_PER_SEC=2
UDP_RATE_LIMIT_BURST=5

# HTTP 速率限制
HTTP_RATE_LIMIT_ENABLED=true
HTTP_RATE_LIMIT_RPS=20
HTTP_RATE_LIMIT_BURST=50
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
RUN pip install --no-cache-dir bencodepy orjson aiohttp

# 复制代码
COPY tracker.py .

# 创建数据目录
RUN mkdir -p /data

# 环境变量默认值
ENV TRACKER_IP=0.0.0.0 \
    TRACKER_PORT=6969 \
    TRACKER_UDP_PORT=6969 \
    TRACKER_DB_FILE=/data/tracker_state.db \
    LOG_LEVEL=INFO \
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
  -e LOG_LEVEL=INFO \
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
      - LOG_LEVEL=INFO
      - TRACKER_PEER_TIMEOUT=1800
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
    # 这里只代理管理 API 和监控端点走 HTTPS

    location /health {
        proxy_pass http://127.0.0.1:6969;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location /metrics {
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

BitTorrent 客户端对 HTTPS Tracker 的支持并不统一，**建议 announce 和 scrape 端点直接暴露 HTTP（端口 6969）**，不要走反向代理 HTTPS，否则可能导致部分客户端无法连接。管理 API 和 `/metrics` 端点可以走 HTTPS 反向代理。

配置反向代理后，需要设置环境变量 `TRACKER_BEHIND_PROXY=true`，否则服务端获取到的是 Nginx 的 IP 而不是真实客户端 IP。

---

## 配置详解

所有配置均通过 TOML 配置文件（`tracker.toml`）或环境变量设置，环境变量优先级更高。无需修改源码。

### TOML 配置文件

服务启动时会自动查找当前目录或 `tracker.py` 所在目录下的 `tracker.toml` 文件。所有配置项均可在 TOML 中设置，键名与环境变量名一致。示例：

```toml
# tracker.toml
TRACKER_IP = "0.0.0.0"
TRACKER_PORT = 6969
TRACKER_API_KEY = "your-secret-key"
LOG_LEVEL = "INFO"
TRACKER_PEER_TIMEOUT = 1800
TRACKER_DB_FILE = "tracker_state.db"
TRACKER_DB_FLUSH_INTERVAL = 3
```

若 TOML 文件不存在或解析失败，服务会回退到默认值/环境变量并记录警告日志。

### 监听地址与端口

| 环境变量 | 默认值 | 说明 |
|---------|--------|------|
| `TRACKER_IP` | `0.0.0.0` | 监听 IP 地址。设为 `::` 启用 IPv6 双栈；设为具体 IPv4/IPv6 地址只监听对应地址 |
| `TRACKER_PORT` | `6969` | HTTP 监听端口（TCP） |
| `TRACKER_UDP_PORT` | 同 `TRACKER_PORT` | UDP 监听端口，默认与 HTTP 端口一致 |

### 日志配置

| 环境变量 | 默认值 | 说明 |
|---------|--------|------|
| `LOG_LEVEL` | `INFO` | 日志级别，可选值：`DEBUG`、`INFO`、`WARNING`、`ERROR`、`CRITICAL` |

### 时间间隔配置

| 环境变量 | 默认值 | 说明 |
|---------|--------|------|
| `TRACKER_MIN_INTERVAL` / `MIN_INTERVAL` | `900` | 最小 announce 间隔（秒），客户端不得低于此频率重新 announce。BEP 3 规定为 900 秒（15 分钟） |
| `TRACKER_INTERVAL` | 同 `MIN_INTERVAL` | 普通重 announce 间隔（秒），客户端建议按此间隔刷新 |
| `TRACKER_PEER_TIMEOUT` / `PEER_TIMEOUT` | `1800` | Peer 过期时间（秒），超时未更新的 peer 将被自动清理。默认 30 分钟 |

### 数据存储配置

Tracker 使用 SQLite 作为主存储（WAL 模式，Write-Behind 异步批量落库），内存读写、SQLite 持久化。启动时若 SQLite 为空，会自动从旧版 `tracker_state.json` 一次性迁移。

| 环境变量 | 默认值 | 说明 |
|---------|--------|------|
| `TRACKER_DB_FILE` | `tracker_state.db` | SQLite 数据库文件路径，建议使用绝对路径 |
| `TRACKER_DATA_FILE` / `DATA_FILE` | `tracker_state.json` | 旧版 JSON 状态文件路径（仅用于一次性迁移，不再作为主存储） |
| `TRACKER_DB_FLUSH_INTERVAL` | `3` | SQLite 异步批量落库间隔（秒），默认 3 秒 |
| `TRACKER_DB_FLUSH_BATCH` | `5000` | SQLite 单次批量落库最大行数 |
| `TRACKER_AUTO_SAVE_INTERVAL` / `AUTO_SAVE_INTERVAL` | `300` | 强制落库 + WAL checkpoint 间隔（秒），默认 5 分钟 |
| `TRACKER_CLEANUP_INTERVAL` / `CLEANUP_INTERVAL` | `120` | 过期 peer 清理间隔（秒），默认 2 分钟 |
| `TRACKER_DB_STATS_HISTORY` | `true` | 是否启用 stats_history 表（定期采样种子计数，用于事后趋势分析） |
| `TRACKER_STATS_HISTORY_INTERVAL` | `60` | stats_history 采样间隔（秒），默认 60 秒 |
| `TRACKER_STATS_HISTORY_RETENTION` | `604800` | stats_history 数据保留时间（秒），默认 7 天 |

### 容量限制配置

| 环境变量 | 默认值 | 说明 |
|---------|--------|------|
| `TRACKER_MAX_PEERS_PER_TORRENT` / `MAX_PEERS_PER_TORRENT` | `1000` | 每个种子最大 peer 数量，达到上限后拒绝新 peer 加入（已存在的 peer 仍可更新） |
| `TRACKER_MAX_TORRENTS` / `MAX_TORRENTS` | `1000000` | 全局最大种子数量，达到上限后拒绝新 info_hash 的 announce |
| `TRACKER_MAX_NUMWANT` / `MAX_NUMWANT` | `200` | 单次 announce 返回 peer 数量的上限，对应客户端如 `numwant=-1`（尽可能多）的情况 |
| `TRACKER_MAX_UDP_CONNECTIONS` / `MAX_UDP_CONNECTIONS` | `100000` | UDP 连接表最大条目数，采用 LRU 策略自动淘汰最久未使用的连接 |
| `TRACKER_MAX_UDP_PACKET_SIZE` / `MAX_UDP_PACKET_SIZE` | `4096` | UDP 单个数据包最大字节数，超过此大小的包直接丢弃 |
| `TRACKER_MAX_HTTP_BODY_SIZE` / `MAX_HTTP_BODY_SIZE` | `65536` | HTTP 请求体最大字节数（64KB），用于 `/add_torrent_info` 等 POST 接口 |
| `TRACKER_MAX_SCRAPE_HASHES` | `74` | 单次 scrape 请求最多查询的 info_hash 数量 |

### 防 info_hash 洪水配置

基于 per-IP Token Bucket 限制新种子的创建频率，防止恶意客户端通过大量随机 info_hash 耗尽内存。

| 环境变量 | 默认值 | 说明 |
|---------|--------|------|
| `TRACKER_NEW_HASH_BURST` | `20` | 突发允许的新种子创建数（burst 容量） |
| `TRACKER_NEW_HASH_PER_HOUR` | `40` | 每小时允许的新种子创建数（补充速率） |
| `TRACKER_NEW_HASH_MAX_ENTRIES` | `100000` | 洪水表最大条目数，超过时自动淘汰最旧条目 |

### 安全与认证配置

| 环境变量 | 默认值 | 说明 |
|---------|--------|------|
| `TRACKER_API_KEY` | `""`（空） | API 密钥，用于管理端点认证和私有 Tracker 模式。**生产环境必须设置** |
| `TRACKER_PROTECT_ANNOUNCE` | `false` | 是否对 announce 端点启用密钥保护（即私有 Tracker 模式） |
| `TRACKER_PROTECT_SCRAPE` | `false` | 是否对 scrape 端点启用密钥保护 |
| `TRACKER_ALLOW_PRIVATE_IP` | `true` | 是否接受来自私有 IP 地址（如 192.168.x.x、10.x.x.x、127.0.0.1 等）的 announce。公网部署建议设为 `false` |
| `TRACKER_BEHIND_PROXY` | `false` | 是否部署在反向代理之后。设为 `true` 时会从 `X-Forwarded-For` 或 `X-Real-IP` 头获取真实客户端 IP |
| `TRACKER_ALLOW_IP_PARAM` | `false` | 是否信任 HTTP announce 的 `ip` 查询参数。默认关闭以防止伪造 IP 污染 swarm |

### UDP 协议配置

| 环境变量 | 默认值 | 说明 |
|---------|--------|------|
| `TRACKER_UDP_CONNECTION_TIMEOUT` / `UDP_CONNECTION_TIMEOUT` | `120` | UDP 连接 ID 有效期（秒），不建议修改 |
| `TRACKER_UDP_CONN_CLEANUP_INTERVAL` / `UDP_CONN_CLEANUP_INTERVAL` | `30` | UDP 过期连接清理间隔（秒） |

### UDP 速率限制配置（防 DDoS）

Tracker 内置双 Token Bucket 速率限制机制，基于源 IP 地址进行流量控制，被限速的数据包会被静默丢弃（不返回任何响应），有效防止 UDP 反射放大攻击。速率限制条目也会在清理循环中自动回收，防止内存泄漏。

| 环境变量 | 默认值 | 说明 |
|---------|--------|------|
| `UDP_RATE_LIMIT_ENABLED` | `true` | 是否启用 UDP 速率限制 |
| `UDP_RATE_LIMIT_PACKET_PER_SEC` | `20` | 每个 IP 每秒允许的最大 UDP 数据包数 |
| `UDP_RATE_LIMIT_CONNECT_PER_SEC` | `2` | 每个 IP 每秒允许的最大 connect 请求数 |
| `UDP_RATE_LIMIT_BURST` | `5` | 突发流量允许的最大包数（burst 容量） |
| `UDP_RATE_MAX_PENDING_PER_IP` | `10` | 每个 IP 最大并发处理任务数，防止慢客户端耗尽资源 |
| `UDP_RATE_MAX_ENTRIES` | `200000` | 速率限制表最大条目数，超过时自动淘汰最旧条目，防止内存溢出 |

### HTTP 速率限制配置

HTTP 层面同样内置 Token Bucket 速率限制，对 `/announce` 和 `/scrape` 端点进行 per-IP 流量控制。被限速的请求会返回 bencode 格式的 "Rate limit exceeded" 错误。

| 环境变量 | 默认值 | 说明 |
|---------|--------|------|
| `HTTP_RATE_LIMIT_ENABLED` | `true` | 是否启用 HTTP 速率限制 |
| `HTTP_RATE_LIMIT_RPS` | `20` | 每个 IP 每秒允许的最大 HTTP 请求数 |
| `HTTP_RATE_LIMIT_BURST` | `50` | 突发流量允许的最大请求数（burst 容量） |
| `HTTP_RATE_LIMIT_MAX_ENTRIES` | `200000` | 速率限制表最大条目数，超过时自动淘汰最旧条目 |

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
    "stats": "/stats (requires API key)",
    "metrics": "/metrics"
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

#### `GET /metrics`
Prometheus 格式指标端点，返回当前 Tracker 的运行指标，可直接接入 Prometheus 或兼容的监控系统。

**返回的指标包括：**
- `tracker_torrents_total`（gauge）：活跃种子总数
- `tracker_peers_total`（gauge）：活跃 peer 总数
- `tracker_udp_connections_total`（gauge）：当前 UDP 连接数
- `tracker_announce_requests_total`（counter，按 protocol=http/udp）：announce 请求总数
- `tracker_scrape_requests_total`（counter，按 protocol=http/udp）：scrape 请求总数
- `tracker_announce_failures_total`（counter，按 protocol=http/udp）：announce 失败次数
- `tracker_scrape_failures_total`（counter，按 protocol=http/udp）：scrape 失败次数
- `tracker_rate_limit_hits_total`（counter）：速率限制命中次数
- `tracker_request_duration_seconds_total`（counter，按 endpoint）：请求耗时累计
- `tracker_request_duration_seconds_count`（counter，按 endpoint）：请求计数
- `tracker_db_flush_total`（counter）：SQLite 落库操作总次数
- `tracker_db_flush_errors_total`（counter）：SQLite 落库失败总次数
- `tracker_db_flush_seconds_sum`（counter）：SQLite 落库累计耗时（秒）

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
- `ip`：客户端声明自己的 IP（BEP 7），默认不信任（需设置 `TRACKER_ALLOW_IP_PARAM=true` 才启用）
- `key`：私有 Tracker 模式下的认证密钥

响应为 bencode 编码格式。

#### `GET /scrape` 或 `GET /scrape/<hash1>/<hash2>/...`
BitTorrent scrape 端点，用于批量查询种子统计信息。

- `info_hash` 参数可重复指定，查询多个种子
- URL 路径支持直接写十六进制 info_hash，多个用 `/` 分隔
- 单次最多查询 `TRACKER_MAX_SCRAPE_HASHES` 个 info_hash（默认 74），可通过环境变量或 TOML 配置

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
查询所有种子的详细统计信息，通过 SQLite 聚合查询返回 JSON 格式。

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
手动触发状态落库（强制 flush + WAL checkpoint），正常情况下不需要调用，服务会自动定期落库。

#### `GET /export_state`
导出与旧版 JSON 状态格式兼容的全量快照，用于备份或迁移。返回 JSON 格式。

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
2. 其他任意字符串，取 SHA-256 哈希的前 4 字节作为 key

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
| BEP 48 | Tracker Protocol Extension: Scrape | 完整支持，最多 `TRACKER_MAX_SCRAPE_HASHES` 个 info_hash |

### BEP 3 兼容细节
- 完整返回 `interval`、`min interval`、`complete`、`incomplete`、`downloaded` 字段
- `completed` 事件正确递增下载完成计数，强制将 `left` 视为 0
- `left` 字段为负数时视为极大值（标记为 leecher），不会误判为 seeder
- 错误响应始终返回 HTTP 200 + bencode 格式的 `failure reason`（符合 BEP 3 规范）

### BEP 15 兼容细节
- Connect / Announce / Scrape / Error 四种 action 完整实现
- Announce 响应按客户端地址族（IPv4/IPv6）返回对应格式的 peer 列表
- 响应大小严格限制在 1400 字节 MTU 内，避免 IP 分片
- 连接 ID 使用 `secrets.randbits(64)` 加密安全生成，有效期 2 分钟，不刷新过期时间，防止连接劫持
- `numwant=-1` 正确映射到 `MAX_NUMWANT`

---

## 注意事项

1. **数据持久化**：本 Tracker 是内存型服务，所有运行时数据都在内存中，通过 SQLite（WAL 模式，Write-Behind 异步批量落库）持久化。服务意外重启最多丢失最近 `DB_FLUSH_INTERVAL`（默认 3 秒）内的数据。

2. **数据库文件安全**：SQLite 使用 WAL 模式，默认每 300 秒执行 WAL checkpoint 确保数据落盘。启动时若 SQLite 为空，会自动从旧版 `tracker_state.json` 一次性迁移数据到 SQLite，迁移成功后将 JSON 文件重命名为 `.migrated.<timestamp>` 归档。

3. **API 密钥安全**：未设置 `TRACKER_API_KEY` 时，所有管理端点（`/stats`、`/save_state`、`/shutdown`、`/add_torrent_info`、`/export_state`）将被禁用，日志中会记录警告。公网部署前必须设置强密钥。

4. **私有 IP 过滤**：默认 `TRACKER_ALLOW_PRIVATE_IP=true`，适合内网测试使用；公网部署建议设为 `false`，防止无效的内网 IP 污染 peer 列表。

5. **防火墙配置**：部署时需要同时开放 TCP 和 UDP 的对应端口（默认 6969），只开放 TCP 会导致 UDP Tracker 无法使用。

6. **文件描述符限制**：高并发场景下需要调大系统的文件描述符限制（systemd 配置中已设置 `LimitNOFILE=65536`），否则可能出现 "too many open files" 错误。

7. **NTP 时间同步**：虽然本服务不依赖时间戳认证，但建议服务器开启 NTP 时间同步，保证日志时间和统计数据准确。

8. **HTTPS 不推荐用于 announce**：绝大多数 BT 客户端对 HTTPS Tracker 支持不好，建议 announce 和 scrape 端点直接使用 HTTP，管理 API 和 `/metrics` 端点可以走 HTTPS 反向代理。

9. **数据库备份**：`tracker_state.db`（SQLite）是唯一的数据文件，建议定期备份。可使用 `GET /export_state` 端点导出 JSON 格式快照作为额外备份。

10. **速率限制**：HTTP 和 UDP 均默认启用速率限制。如果作为内网 Tracker 使用且流量较大，可根据需要调整 `HTTP_RATE_LIMIT_RPS`、`HTTP_RATE_LIMIT_BURST`、`UDP_RATE_LIMIT_PACKET_PER_SEC` 等参数或关闭限制。

11. **种子数量上限**：默认 `MAX_TORRENTS=1000000`，达到上限后新的 info_hash 的 announce 请求会返回空结果（不会崩溃），日志中会记录警告。

12. **种子元数据清理**：Tracker 会自动清理无活跃 peer、无名称、无大小、无完成计数的孤儿种子元数据条目，防止内存中积累无用数据。