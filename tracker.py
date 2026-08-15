# -*- coding: utf-8 -*-

import asyncio
import functools
import hashlib
import hmac
import ipaddress
import logging
import os
import random
import re
import secrets
import signal
import socket
import sqlite3
import struct
import sys
import threading
import time
import tomllib
from collections import OrderedDict
from dataclasses import dataclass, asdict
from typing import Any, Final, NamedTuple, Self, TypedDict

try:
    import bencodepy
    import orjson
    from aiohttp import web
except ImportError as exc:
    sys.stderr.write(
        f"缺少依赖：{exc}。请执行: pip install bencodepy orjson aiohttp\n"
    )
    raise


# ---------------------------------------------------------------------------
# JSON 辅助函数
# ---------------------------------------------------------------------------
def _json_loads(data: bytes) -> Any:
    return orjson.loads(data)


def _json_dumps(obj: Any, **kwargs: Any) -> bytes:
    option = orjson.OPT_INDENT_2 if kwargs.get("indent") else 0
    return orjson.dumps(obj, option=option)


# ---------------------------------------------------------------------------
# 配置（TOML 文件 + 环境变量，环境变量优先级更高）
# ---------------------------------------------------------------------------
# TOML 加载状态（logging 在导入期尚未配置，先记录、配置完成后统一输出）
_TOML_LOADED_FROM: str | None = None
_TOML_LOAD_ERROR: str | None = None


def _load_toml_config(path: str = "tracker.toml") -> dict[str, Any]:
    """加载 TOML 配置文件，文件不存在时返回空字典。

    解析失败不再静默：错误信息记录到 _TOML_LOAD_ERROR，待日志系统就绪后输出。
    """
    global _TOML_LOADED_FROM, _TOML_LOAD_ERROR
    # 支持多个路径查找
    candidates = [path, os.path.join(os.path.dirname(os.path.abspath(__file__)), path)]
    for p in candidates:
        try:
            with open(p, "rb") as f:
                cfg = tomllib.load(f)
        except FileNotFoundError:
            continue
        except tomllib.TOMLDecodeError as exc:
            # 配置文件存在但解析失败：明确记录，避免静默回退到默认值
            _TOML_LOAD_ERROR = f"TOML 配置文件 {p} 解析失败: {exc}"
            continue
        _TOML_LOADED_FROM = p
        return cfg
    return {}


# 全局 TOML 配置快照（仅加载一次，环境变量覆盖）
_toml_cfg = _load_toml_config()


def _env_bool(name: str, default: bool = False) -> bool:
    # 环境变量优先，其次 TOML
    raw = os.environ.get(name)
    if raw is not None:
        return raw.strip().lower() in ("1", "true", "yes", "on")
    toml_val = _toml_cfg.get(name)
    if toml_val is not None:
        return bool(toml_val)
    return default


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is not None:
        try:
            return int(raw)
        except (ValueError, TypeError):
            pass
    toml_val = _toml_cfg.get(name)
    if toml_val is not None:
        try:
            return int(toml_val)
        except (ValueError, TypeError):
            pass
    return default


def _env_int_any(names: tuple[str, ...], default: int) -> int:
    """按顺序尝试多个配置名（用于统一 TRACKER_ 前缀并兼容旧名称）。"""
    for name in names:
        raw = os.environ.get(name)
        if raw is not None:
            try:
                return int(raw)
            except (ValueError, TypeError):
                pass
    for name in names:
        toml_val = _toml_cfg.get(name)
        if toml_val is not None:
            try:
                return int(toml_val)
            except (ValueError, TypeError):
                pass
    return default


def _env_bool_any(names: tuple[str, ...], default: bool) -> bool:
    """按顺序尝试多个配置名的布尔值读取。"""
    for name in names:
        raw = os.environ.get(name)
        if raw is not None:
            return raw.strip().lower() in ("1", "true", "yes", "on")
    for name in names:
        toml_val = _toml_cfg.get(name)
        if toml_val is not None:
            return bool(toml_val)
    return default


def _env_str_any(names: tuple[str, ...], default: str) -> str:
    """按顺序尝试多个配置名的字符串读取。"""
    for name in names:
        raw = os.environ.get(name)
        if raw is not None:
            return raw
    for name in names:
        toml_val = _toml_cfg.get(name)
        if toml_val is not None:
            return str(toml_val)
    return default


def _env_log_level(name: str, default: str = "INFO") -> int:
    raw = os.environ.get(name, "").strip().upper()
    if raw:
        return getattr(logging, raw, logging.INFO)
    toml_val = _toml_cfg.get(name)
    if toml_val:
        return getattr(logging, str(toml_val).strip().upper(), logging.INFO)
    return getattr(logging, default, logging.INFO)


IP: str = _env_str_any(("TRACKER_IP",), "0.0.0.0")
PORT: int = _env_int_any(("TRACKER_PORT",), 6969)
UDP_PORT: int = _env_int_any(("TRACKER_UDP_PORT",), PORT)

MIN_INTERVAL: int = _env_int_any(("TRACKER_MIN_INTERVAL", "MIN_INTERVAL"), 900)
INTERVAL: int = _env_int_any(("TRACKER_INTERVAL",), MIN_INTERVAL)
PEER_TIMEOUT: int = _env_int_any(("TRACKER_PEER_TIMEOUT", "PEER_TIMEOUT"), 1800)
DATA_FILE: str = _env_str_any(("TRACKER_DATA_FILE", "DATA_FILE"), "tracker_state.json")
CLEANUP_INTERVAL: int = _env_int_any(("TRACKER_CLEANUP_INTERVAL", "CLEANUP_INTERVAL"), 120)


DB_FILE: str = _env_str_any(("TRACKER_DB_FILE",), "tracker_state.db")
DB_FLUSH_INTERVAL: int = _env_int_any(("TRACKER_DB_FLUSH_INTERVAL",), 3)
DB_FLUSH_BATCH: int = _env_int_any(("TRACKER_DB_FLUSH_BATCH",), 5000)
DB_STATS_HISTORY: bool = _env_bool_any(("TRACKER_DB_STATS_HISTORY",), True)
STATS_HISTORY_INTERVAL: int = _env_int_any(("TRACKER_STATS_HISTORY_INTERVAL",), 60)
STATS_HISTORY_RETENTION: int = _env_int_any(
    ("TRACKER_STATS_HISTORY_RETENTION",), 7 * 86400
)
# 定期强制落库 + WAL checkpoint 的间隔（秒）
AUTO_SAVE_INTERVAL: int = _env_int_any(
    ("TRACKER_AUTO_SAVE_INTERVAL", "AUTO_SAVE_INTERVAL"), 300
)

MAX_PEERS_PER_TORRENT: int = _env_int_any(
    ("TRACKER_MAX_PEERS_PER_TORRENT", "MAX_PEERS_PER_TORRENT"), 1000
)
MAX_TORRENTS: int = _env_int_any(("TRACKER_MAX_TORRENTS", "MAX_TORRENTS"), 1_000_000)
MAX_NUMWANT: int = _env_int_any(("TRACKER_MAX_NUMWANT", "MAX_NUMWANT"), 200)
MAX_SCRAPE_HASHES: int = _env_int_any(("TRACKER_MAX_SCRAPE_HASHES",), 74)
# 单 peer 传输量上限：取 SQLite INTEGER 上界（2^63-1），
# 防止超大值污染统计或导致落库 OverflowError
_MAX_TRANSFER_VALUE: int = (1 << 63) - 1

API_KEY: str = _env_str_any(("TRACKER_API_KEY",), "")
PROTECT_ANNOUNCE: bool = _env_bool_any(("TRACKER_PROTECT_ANNOUNCE",), False)
PROTECT_SCRAPE: bool = _env_bool_any(("TRACKER_PROTECT_SCRAPE",), False)
ALLOW_PRIVATE_IP: bool = _env_bool_any(("TRACKER_ALLOW_PRIVATE_IP",), True)
BEHIND_PROXY: bool = _env_bool_any(("TRACKER_BEHIND_PROXY",), False)
# 是否信任 HTTP announce 的 ip 查询参数（默认关闭，防止伪造他人 IP 污染 swarm）
ALLOW_IP_PARAM: bool = _env_bool_any(("TRACKER_ALLOW_IP_PARAM",), False)

# 防 info_hash 洪水：单 IP 新建种子的 Token Bucket（突发容量 + 每小时补充速率）
NEW_HASH_BURST: int = _env_int_any(("TRACKER_NEW_HASH_BURST",), 20)
NEW_HASH_PER_HOUR: int = _env_int_any(("TRACKER_NEW_HASH_PER_HOUR",), 40)
NEW_HASH_RATE_PER_SEC: float = max(1, NEW_HASH_PER_HOUR) / 3600.0
NEW_HASH_MAX_ENTRIES: int = _env_int_any(("TRACKER_NEW_HASH_MAX_ENTRIES",), 100_000)

UDP_CONNECTION_TIMEOUT: int = _env_int_any(
    ("TRACKER_UDP_CONNECTION_TIMEOUT", "UDP_CONNECTION_TIMEOUT"), 120
)
UDP_CONN_CLEANUP_INTERVAL: int = _env_int_any(
    ("TRACKER_UDP_CONN_CLEANUP_INTERVAL", "UDP_CONN_CLEANUP_INTERVAL"), 30
)
MAX_UDP_CONNECTIONS: int = _env_int_any(
    ("TRACKER_MAX_UDP_CONNECTIONS", "MAX_UDP_CONNECTIONS"), 100_000
)

MAX_UDP_PACKET_SIZE: int = _env_int_any(("TRACKER_MAX_UDP_PACKET_SIZE", "MAX_UDP_PACKET_SIZE"), 4096)
MAX_HTTP_BODY_SIZE: int = _env_int_any(("TRACKER_MAX_HTTP_BODY_SIZE", "MAX_HTTP_BODY_SIZE"), 65536)

UDP_MTU: int = 1400
UDP_ANNOUNCE_HDR_SIZE: int = 20

# 预编译 struct
COMPACT4_STRUCT = struct.Struct("!4sH")
COMPACT6_STRUCT = struct.Struct("!16sH")
UDP_CONNECT_RESPONSE = struct.Struct("!IIQ")
UDP_ANNOUNCE_HEADER = struct.Struct("!IIIII")
UDP_ERROR_HEADER = struct.Struct("!II")
UDP_SCRAPE_HEADER = struct.Struct("!II")
UDP_SCRAPE_STATS = struct.Struct("!III")
UDP_ANNOUNCE_REQUEST = struct.Struct("!20s20sQQQIIiiH")

UDP_PROTOCOL_ID: int = 0x41727101980
ACTION_CONNECT: int = 0
ACTION_ANNOUNCE: int = 1
ACTION_SCRAPE: int = 2
ACTION_ERROR: int = 3

UINT32_MAX: int = 0xFFFFFFFF
_SENTINEL_HUGE: Final[int] = (1 << 63) - 1

# 配置合理性校验
if MIN_INTERVAL <= 0:
    MIN_INTERVAL = 900
if INTERVAL < MIN_INTERVAL:
    INTERVAL = MIN_INTERVAL
if MAX_UDP_CONNECTIONS <= 0:
    MAX_UDP_CONNECTIONS = 100_000
if not (1 <= PORT <= 65535):
    PORT = 6969
if not (1 <= UDP_PORT <= 65535):
    UDP_PORT = PORT

# 防止 0/负数导致忙循环或语义错误
MIN_INTERVAL = max(1, MIN_INTERVAL)
INTERVAL = max(MIN_INTERVAL, INTERVAL)
PEER_TIMEOUT = max(1, PEER_TIMEOUT)
CLEANUP_INTERVAL = max(1, CLEANUP_INTERVAL)
DB_FLUSH_INTERVAL = max(1, DB_FLUSH_INTERVAL)
DB_FLUSH_BATCH = max(100, DB_FLUSH_BATCH)
STATS_HISTORY_INTERVAL = max(10, STATS_HISTORY_INTERVAL)
STATS_HISTORY_RETENTION = max(3600, STATS_HISTORY_RETENTION)
AUTO_SAVE_INTERVAL = max(1, AUTO_SAVE_INTERVAL)
UDP_CONNECTION_TIMEOUT = max(1, UDP_CONNECTION_TIMEOUT)
UDP_CONN_CLEANUP_INTERVAL = max(1, UDP_CONN_CLEANUP_INTERVAL)
MAX_PEERS_PER_TORRENT = max(1, MAX_PEERS_PER_TORRENT)
MAX_TORRENTS = max(1, MAX_TORRENTS)
MAX_NUMWANT = max(1, MAX_NUMWANT)
MAX_SCRAPE_HASHES = max(1, MAX_SCRAPE_HASHES)
NEW_HASH_BURST = max(1, NEW_HASH_BURST)

VALID_EVENTS: frozenset[str] = frozenset({"started", "completed", "stopped"})
UDP_EVENT_MAP: dict[int, str | None] = {0: None, 1: "completed", 2: "started", 3: "stopped"}

# compact 参数真值集合（小写）— BEP 23 仅规定 "1"，但部分客户端发送其他真值
_COMPACT_TRUTHY: frozenset[bytes] = frozenset({b"1", b"true", b"yes", b"on"})


# ---------------------------------------------------------------------------
# 日志
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=_env_log_level("LOG_LEVEL", "INFO"),
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("tracker")

# 输出导入期记录的 TOML 加载结果（此时日志系统才刚就绪）
if _TOML_LOAD_ERROR:
    logger.warning("%s（已回退到默认值/环境变量）", _TOML_LOAD_ERROR)
elif _TOML_LOADED_FROM:
    logger.info("已加载 TOML 配置: %s", _TOML_LOADED_FROM)

# 校验 LOG_LEVEL 配置值是否有效
_log_level_raw = os.environ.get("LOG_LEVEL", "") or str(_toml_cfg.get("LOG_LEVEL", ""))
if _log_level_raw.strip() and not hasattr(logging, _log_level_raw.strip().upper()):
    logger.warning("无效的 LOG_LEVEL 配置 %r，已回退到 INFO", _log_level_raw)


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------
_HEX_RE = re.compile(rb"^[0-9a-fA-F]+$")

_HEX_NIBBLE: list[int] = [-1] * 256
for _c in range(256):
    if 48 <= _c <= 57:
        _HEX_NIBBLE[_c] = _c - 48
    elif 65 <= _c <= 70:
        _HEX_NIBBLE[_c] = _c - 55
    elif 97 <= _c <= 102:
        _HEX_NIBBLE[_c] = _c - 87

_rand = random.Random()

# 日志节流：同一 key 的告警最多每 interval 秒输出一次，避免被高频事件刷屏
_LOG_THROTTLE_TS: dict[str, float] = {}


def _warn_throttled(key: str, msg: str, *args: Any, interval: float = 60.0) -> None:
    now = time.monotonic()
    last = _LOG_THROTTLE_TS.get(key)
    if last is not None and now - last < interval:
        return
    if len(_LOG_THROTTLE_TS) > 10_000:
        _LOG_THROTTLE_TS.clear()
    _LOG_THROTTLE_TS[key] = now
    logger.warning(msg, *args)


def bytes_to_hex(b: bytes) -> str:
    return b.hex()


def hex_to_bytes(s: str | bytes) -> bytes:
    if isinstance(s, bytes):
        s = s.decode("ascii", errors="replace")
    if len(s) % 2:
        raise ValueError("hex string length must be even")
    return bytes.fromhex(s)


def constant_time_compare(a: str | bytes, b: str | bytes) -> bool:
    if isinstance(a, str):
        a = a.encode("utf-8")
    if isinstance(b, str):
        b = b.encode("utf-8")
    if len(a) != len(b):
        return False
    return hmac.compare_digest(a, b)


def _constant_time_compare_int(a: int, b: int) -> bool:
    """恒时比较两个整数（64 位无符号掩码，支持负数/大整数）。"""
    return hmac.compare_digest(
        (a & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "big"),
        (b & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "big"),
    )


def _percent_decode_bytes(b: bytes) -> bytes:
    if not b or (b"%" not in b and b"+" not in b):
        return b
    n = len(b)
    result = bytearray(n)
    i = j = 0
    while i < n:
        c = b[i]
        if c == ord("+"):
            result[j] = 0x20
            i += 1
            j += 1
        elif c == ord("%") and i + 2 < n:
            high = _HEX_NIBBLE[b[i + 1]]
            low = _HEX_NIBBLE[b[i + 2]]
            if high >= 0 and low >= 0:
                result[j] = (high << 4) | low
                i += 3
                j += 1
                continue
            result[j] = c
            i += 1
            j += 1
        else:
            result[j] = c
            i += 1
            j += 1
    return bytes(result[:j])


def _parse_query_string_raw(qs: bytes) -> dict[bytes, list[bytes]]:
    result: dict[bytes, list[bytes]] = {}
    if not qs:
        return result
    for item in qs.split(b"&"):
        if not item:
            continue
        if b"=" in item:
            key, val = item.split(b"=", 1)
        else:
            key, val = item, b""
        key = _percent_decode_bytes(key)
        val = _percent_decode_bytes(val)
        lst = result.get(key)
        if lst is None:
            result[key] = [val]
        else:
            lst.append(val)
    return result


def _get_first(parsed_qs: dict[bytes, list[bytes]], key: str) -> bytes | None:
    vals = parsed_qs.get(key.encode("ascii"))
    return vals[0] if vals else None


def _get_all(parsed_qs: dict[bytes, list[bytes]], key: str) -> list[bytes]:
    return parsed_qs.get(key.encode("ascii"), [])


def _get_int(
    parsed_qs: dict[bytes, list[bytes]],
    key: str,
    default: int = 0,
    *,
    negative_as_huge: bool = False,
) -> int:
    val = _get_first(parsed_qs, key)
    if val is None:
        return default
    try:
        v = int(val)
    except (ValueError, TypeError):
        return default
    if negative_as_huge:
        return v if v >= 0 else _SENTINEL_HUGE
    return max(0, v)


def _is_truthy(val: bytes | None) -> bool:
    """判断 bencoded/query 参数是否为真值（1/true/True）。"""
    if val is None:
        return False
    return val.lower() in _COMPACT_TRUTHY


@functools.lru_cache(maxsize=65536)
def _is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return addr.is_private or addr.is_loopback or addr.is_multicast or addr.is_unspecified


@functools.lru_cache(maxsize=65536)
def _normalize_ip(ip_str: str) -> str:
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return ip_str
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped is not None:
            return str(addr.ipv4_mapped)
        if addr.sixtofour is not None:
            return str(addr.sixtofour)
        if addr.teredo is not None:
            _, client = addr.teredo
            return str(client)
        return addr.compressed
    return ip_str


@functools.lru_cache(maxsize=65536)
def _is_valid_ip(ip_str: str) -> bool:
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def _maybe_hex_to_bytes(s: bytes | None) -> bytes | None:
    if s is None:
        return None
    if len(s) == 40 and _HEX_RE.match(s):
        try:
            return bytes.fromhex(s.decode("ascii"))
        except ValueError:
            return s
    return s


def _udp_key_from_api_key() -> int | None:
    """将 API_KEY 派生为 UDP 32 位 signed 整数 key。

    派生规则：若 API_KEY 是十进制数字字符串，取其低 32 位；
    否则始终通过 SHA-256 哈希派生，确保与 HTTP API_KEY 语义一致。
    派生结果为 0 时视为无效（客户端未携带 key 时默认值即 0），强制改用哈希派生或置 1。
    """
    if not API_KEY:
        return None
    raw: int | None = None
    try:
        # 纯数字字符串：直接取低 32 位
        raw = int(API_KEY) & 0xFFFFFFFF
    except ValueError:
        raw = None
    if raw is None or raw == 0:
        digest = hashlib.sha256(API_KEY.encode("utf-8")).digest()
        raw = int.from_bytes(digest[:4], "big", signed=False)
    if raw == 0:
        raw = 1  # 极端情况下哈希前 4 字节全零，避免与"未携带 key"混淆
    return raw - 0x100000000 if raw >= 0x80000000 else raw


# ---------------------------------------------------------------------------
# 类型定义
# ---------------------------------------------------------------------------
class _PeerDict(TypedDict):
    peer_id: str
    ip: str
    port: int
    last_seen: float
    uploaded: int
    downloaded: int
    left: int


class _TorrentStatsDict(TypedDict):
    complete: int
    incomplete: int
    peers: int
    completed: int


class _TorrentStateDict(TypedDict):
    info: dict[str, Any]
    peers_info: list[_PeerDict]
    stats: _TorrentStatsDict


# ---------------------------------------------------------------------------
# 数据模型
# ---------------------------------------------------------------------------
@dataclass(slots=True, frozen=True)
class Peer:
    peer_id: bytes
    ip: str
    port: int
    last_seen: float
    uploaded: int = 0
    downloaded: int = 0
    left: int = 0
    # 单调时钟版本的 last_seen（仅运行时使用，不持久化）：
    # 过期判断用它，避免 NTP 校时跳变导致 peer 被提前/延迟剔除
    mono_seen: float = 0.0

    def to_dict(self) -> _PeerDict:
        return {
            "peer_id": bytes_to_hex(self.peer_id),
            "ip": self.ip,
            "port": self.port,
            "last_seen": self.last_seen,
            "uploaded": self.uploaded,
            "downloaded": self.downloaded,
            "left": self.left,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        last_seen = float(data.get("last_seen", 0.0))
        age = max(0.0, time.time() - last_seen)
        return cls(
            peer_id=hex_to_bytes(data.get("peer_id", "")),
            ip=data.get("ip", "0.0.0.0"),
            port=int(data.get("port", 0)),
            last_seen=last_seen,
            uploaded=int(data.get("uploaded", 0)),
            downloaded=int(data.get("downloaded", 0)),
            left=int(data.get("left", 0)),
            mono_seen=time.monotonic() - age,
        )


_TORRENT_INFO_FIELDS: frozenset[str] = frozenset({
    "info_hash",
    "name",
    "size",
    "piece_length",
    "creation_date",
    "comment",
    "created_by",
})


@dataclass(slots=True)
class TorrentInfo:
    info_hash: bytes
    name: str = ""
    size: int = 0
    piece_length: int = 0
    creation_date: float = 0.0
    comment: str | None = None
    created_by: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["info_hash"] = bytes_to_hex(self.info_hash)
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        filtered = {k: v for k, v in data.items() if k in _TORRENT_INFO_FIELDS}
        filtered["info_hash"] = hex_to_bytes(data.get("info_hash", ""))
        return cls(**filtered)


# ---------------------------------------------------------------------------
# 可观测性指标
# ---------------------------------------------------------------------------
class MetricsCollector:
    """Prometheus 风格的指标收集器（不依赖 prometheus_client）。
    """

    def __init__(self) -> None:
        self._torrents = 0
        self._peers = 0
        self._udp_connections = 0
        self._announce_total: dict[str, int] = {"http": 0, "udp": 0}
        self._scrape_total: dict[str, int] = {"http": 0, "udp": 0}
        self._announce_fail: dict[str, int] = {"http": 0, "udp": 0}
        self._scrape_fail: dict[str, int] = {"http": 0, "udp": 0}
        self._rate_limit_hits = 0
        self._request_duration_sum: dict[str, float] = {
            "http_announce": 0.0,
            "http_scrape": 0.0,
            "udp_announce": 0.0,
            "udp_scrape": 0.0,
        }
        self._request_duration_count: dict[str, int] = {
            "http_announce": 0,
            "http_scrape": 0,
            "udp_announce": 0,
            "udp_scrape": 0,
        }
        # SQLite 落库观测
        self._db_flush_total = 0
        self._db_flush_errors = 0
        self._db_flush_seconds = 0.0
        self._db_pending = 0

    def set_torrents(self, value: int) -> None:
        self._torrents = value

    def set_peers(self, value: int) -> None:
        self._peers = value

    def set_udp_connections(self, value: int) -> None:
        self._udp_connections = value

    def inc_announce(self, protocol: str, failed: bool = False) -> None:
        self._announce_total[protocol] = self._announce_total.get(protocol, 0) + 1
        if failed:
            self._announce_fail[protocol] = self._announce_fail.get(protocol, 0) + 1

    def inc_scrape(self, protocol: str, failed: bool = False) -> None:
        self._scrape_total[protocol] = self._scrape_total.get(protocol, 0) + 1
        if failed:
            self._scrape_fail[protocol] = self._scrape_fail.get(protocol, 0) + 1

    def inc_rate_limit(self) -> None:
        self._rate_limit_hits += 1

    def observe_duration(self, endpoint: str, duration: float) -> None:
        self._request_duration_sum[endpoint] += duration
        self._request_duration_count[endpoint] += 1

    def observe_db_flush(self, duration: float, pending: int, error: bool = False) -> None:
        self._db_flush_total += 1
        self._db_flush_seconds += duration
        self._db_pending = pending
        if error:
            self._db_flush_errors += 1

    def snapshot_json(self) -> bytes:
        """累计型指标快照（写入 SQLite meta 表，重启不丢计数）。"""
        return _json_dumps(
            {
                "announce_total": self._announce_total,
                "scrape_total": self._scrape_total,
                "announce_fail": self._announce_fail,
                "scrape_fail": self._scrape_fail,
                "rate_limit_hits": self._rate_limit_hits,
                "duration_sum": self._request_duration_sum,
                "duration_count": self._request_duration_count,
            }
        )

    def load_snapshot_json(self, raw: bytes | str) -> None:
        """从持久化快照恢复累计型指标。"""
        try:
            data = _json_loads(raw)
            if not isinstance(data, dict):
                return
            for proto in ("http", "udp"):
                self._announce_total[proto] = int(data.get("announce_total", {}).get(proto, 0))
                self._scrape_total[proto] = int(data.get("scrape_total", {}).get(proto, 0))
                self._announce_fail[proto] = int(data.get("announce_fail", {}).get(proto, 0))
                self._scrape_fail[proto] = int(data.get("scrape_fail", {}).get(proto, 0))
            self._rate_limit_hits = int(data.get("rate_limit_hits", 0))
            for k, v in data.get("duration_sum", {}).items():
                if k in self._request_duration_sum:
                    self._request_duration_sum[k] = float(v)
            for k, v in data.get("duration_count", {}).items():
                if k in self._request_duration_count:
                    self._request_duration_count[k] = int(v)
        except Exception as exc:
            logger.warning("指标快照恢复失败（从 0 开始计数）：%s", exc)

    def render(self) -> str:
        lines: list[str] = []
        lines.append("# HELP tracker_torrents_total Number of active torrents")
        lines.append("# TYPE tracker_torrents_total gauge")
        lines.append(f"tracker_torrents_total {self._torrents}")

        lines.append("# HELP tracker_peers_total Number of active peers")
        lines.append("# TYPE tracker_peers_total gauge")
        lines.append(f"tracker_peers_total {self._peers}")

        lines.append("# HELP tracker_udp_connections_total Number of active UDP connections")
        lines.append("# TYPE tracker_udp_connections_total gauge")
        lines.append(f"tracker_udp_connections_total {self._udp_connections}")

        # HELP/TYPE 每个指标族只输出一次（Prometheus 文本格式要求）
        lines.append("# HELP tracker_announce_requests_total Total announce requests")
        lines.append("# TYPE tracker_announce_requests_total counter")
        for protocol in ("http", "udp"):
            lines.append(
                f'tracker_announce_requests_total{{protocol="{protocol}"}} '
                f"{self._announce_total.get(protocol, 0)}"
            )

        lines.append("# HELP tracker_scrape_requests_total Total scrape requests")
        lines.append("# TYPE tracker_scrape_requests_total counter")
        for protocol in ("http", "udp"):
            lines.append(
                f'tracker_scrape_requests_total{{protocol="{protocol}"}} '
                f"{self._scrape_total.get(protocol, 0)}"
            )

        lines.append("# HELP tracker_announce_failures_total Total failed announce requests")
        lines.append("# TYPE tracker_announce_failures_total counter")
        for protocol in ("http", "udp"):
            lines.append(
                f'tracker_announce_failures_total{{protocol="{protocol}"}} '
                f"{self._announce_fail.get(protocol, 0)}"
            )

        lines.append("# HELP tracker_scrape_failures_total Total failed scrape requests")
        lines.append("# TYPE tracker_scrape_failures_total counter")
        for protocol in ("http", "udp"):
            lines.append(
                f'tracker_scrape_failures_total{{protocol="{protocol}"}} '
                f"{self._scrape_fail.get(protocol, 0)}"
            )

        lines.append("# HELP tracker_rate_limit_hits_total Total rate limit hits")
        lines.append("# TYPE tracker_rate_limit_hits_total counter")
        lines.append(f"tracker_rate_limit_hits_total {self._rate_limit_hits}")

        lines.append("# HELP tracker_request_duration_seconds_sum Total request duration in seconds")
        lines.append("# TYPE tracker_request_duration_seconds_sum counter")
        for endpoint, total in self._request_duration_sum.items():
            lines.append(
                f'tracker_request_duration_seconds_sum{{endpoint="{endpoint}"}} {total}'
            )

        lines.append("# HELP tracker_request_duration_seconds_count Total request count")
        lines.append("# TYPE tracker_request_duration_seconds_count counter")
        for endpoint, count in self._request_duration_count.items():
            lines.append(
                f'tracker_request_duration_seconds_count{{endpoint="{endpoint}"}} {count}'
            )

        lines.append("# HELP tracker_db_flush_total Total SQLite flush operations")
        lines.append("# TYPE tracker_db_flush_total counter")
        lines.append(f"tracker_db_flush_total {self._db_flush_total}")

        lines.append("# HELP tracker_db_flush_errors_total Total failed SQLite flush operations")
        lines.append("# TYPE tracker_db_flush_errors_total counter")
        lines.append(f"tracker_db_flush_errors_total {self._db_flush_errors}")

        lines.append("# HELP tracker_db_flush_seconds_sum Total time spent in SQLite flushes")
        lines.append("# TYPE tracker_db_flush_seconds_sum counter")
        lines.append(f"tracker_db_flush_seconds_sum {self._db_flush_seconds}")

        lines.append("# HELP tracker_db_pending_ops Pending changes waiting for SQLite flush")
        lines.append("# TYPE tracker_db_pending_ops gauge")
        lines.append(f"tracker_db_pending_ops {self._db_pending}")

        return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# SQLite 持久层（write-behind 模式）
# ---------------------------------------------------------------------------
_PEER_UPSERT_SQL = """
INSERT INTO peers (info_hash, peer_id, ip, port, last_seen, uploaded, downloaded, left)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(info_hash, peer_id) DO UPDATE SET
    ip = excluded.ip,
    port = excluded.port,
    last_seen = excluded.last_seen,
    uploaded = excluded.uploaded,
    downloaded = excluded.downloaded,
    left = excluded.left
"""

_TORRENT_COUNTER_SQL = """
INSERT INTO torrents (info_hash, seeders, leechers, completed, updated_at)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(info_hash) DO UPDATE SET
    seeders = excluded.seeders,
    leechers = excluded.leechers,
    completed = excluded.completed,
    updated_at = excluded.updated_at
"""

_TORRENT_META_SQL = """
INSERT INTO torrents (info_hash, name, size, piece_length, creation_date, comment, created_by, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(info_hash) DO UPDATE SET
    name = excluded.name,
    size = excluded.size,
    piece_length = excluded.piece_length,
    creation_date = excluded.creation_date,
    comment = excluded.comment,
    created_by = excluded.created_by,
    updated_at = excluded.updated_at
"""

_ALL_STATS_SQL = """
SELECT t.info_hash, t.name, t.size, t.creation_date, t.completed, t.seeders, t.leechers,
       COALESCE(SUM(CASE WHEN p.last_seen > ? THEN p.uploaded ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN p.last_seen > ? THEN p.downloaded ELSE 0 END), 0),
       COUNT(CASE WHEN p.last_seen > ? THEN 1 END)
FROM torrents t
LEFT JOIN peers p ON p.info_hash = t.info_hash
GROUP BY t.info_hash
"""


def _chunked(rows: list, size: int):
    """把行列表切成不超过 size 的块，控制单条 executemany 的内存峰值。"""
    for i in range(0, len(rows), size):
        yield rows[i : i + size]


class SQLiteStore:
    """SQLite 持久层：批量落库（write-behind）+ 启动加载 + 统计查询。
    """

    _SCHEMA = (
        """
        CREATE TABLE IF NOT EXISTS torrents (
            info_hash BLOB PRIMARY KEY,
            name TEXT NOT NULL DEFAULT '',
            size INTEGER NOT NULL DEFAULT 0,
            piece_length INTEGER NOT NULL DEFAULT 0,
            creation_date REAL NOT NULL DEFAULT 0,
            comment TEXT,
            created_by TEXT,
            completed INTEGER NOT NULL DEFAULT 0,
            seeders INTEGER NOT NULL DEFAULT 0,
            leechers INTEGER NOT NULL DEFAULT 0,
            updated_at REAL NOT NULL DEFAULT 0
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS peers (
            info_hash BLOB NOT NULL,
            peer_id BLOB NOT NULL,
            ip TEXT NOT NULL,
            port INTEGER NOT NULL,
            last_seen REAL NOT NULL,
            uploaded INTEGER NOT NULL DEFAULT 0,
            downloaded INTEGER NOT NULL DEFAULT 0,
            left INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (info_hash, peer_id)
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_peers_last_seen ON peers (last_seen)",
        """
        CREATE TABLE IF NOT EXISTS stats_history (
            ts REAL NOT NULL,
            info_hash BLOB NOT NULL,
            seeders INTEGER NOT NULL,
            leechers INTEGER NOT NULL
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_stats_history_ts ON stats_history (ts)",
        "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)",
    )

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._conn: sqlite3.Connection | None = None
        # 串行化所有 sqlite3 调用（连接以 check_same_thread=False 创建，
        # 实际只在本锁保护下被 to_thread 工作线程依次使用）
        self._write_lock = threading.Lock()
        # 串行化 flush 流程，保证批次按产生顺序落库
        self._flush_seq_lock = asyncio.Lock()
        # pending 结构仅在事件循环线程内访问/修改
        # (info_hash, peer_id) -> Peer（upsert）或 None（删除墓碑）
        self._pend_peers: dict[tuple[bytes, bytes], Peer | None] = {}
        # info_hash -> (seeders, leechers, completed) 绝对值快照
        self._pend_torrents: dict[bytes, tuple[int, int, int]] = {}
        # info_hash -> 元数据快照（立即取值为元组，避免后续原地修改与写线程竞争）
        self._pend_meta: dict[
            bytes, tuple[str, int, int, float, str | None, str | None]
        ] = {}
        self._pend_del_torrents: set[bytes] = set()
        self._dirty = False

    # -- 事件循环侧：变更入队（同 key 后写覆盖，天然合并高频更新） -----------

    def queue_peer(self, info_hash: bytes, peer: Peer) -> None:
        self._pend_peers[(info_hash, peer.peer_id)] = peer
        self._dirty = True

    def queue_del_peer(self, info_hash: bytes, peer_id: bytes) -> None:
        self._pend_peers[(info_hash, peer_id)] = None
        self._dirty = True

    def queue_torrent(self, info_hash: bytes, seeders: int, leechers: int, completed: int) -> None:
        self._pend_torrents[info_hash] = (seeders, leechers, completed)
        self._dirty = True

    def queue_meta(self, info: TorrentInfo) -> None:
        self._pend_meta[info.info_hash] = (
            info.name,
            info.size,
            info.piece_length,
            info.creation_date,
            info.comment,
            info.created_by,
        )
        self._dirty = True

    def queue_del_torrent(self, info_hash: bytes) -> None:
        self._pend_del_torrents.add(info_hash)
        self._pend_torrents.pop(info_hash, None)
        self._pend_meta.pop(info_hash, None)
        self._dirty = True

    def pending_count(self) -> int:
        return (
            len(self._pend_peers)
            + len(self._pend_torrents)
            + len(self._pend_meta)
            + len(self._pend_del_torrents)
        )

    # -- flush 流程 -----------------------------------------------------------

    async def flush_now(self, metrics_snapshot: bytes | None = None) -> int:
        """收集 pending 批次并在线程内单事务写入。返回落库变更数。"""
        async with self._flush_seq_lock:
            batch = self._take_batch()
            if batch is None and metrics_snapshot is None:
                return 0
            try:
                return await asyncio.to_thread(
                    self._flush_batch_sync, batch, metrics_snapshot
                )
            except Exception:
                # 批次已取走但写入失败：合并回 pending 等待下次重试
                self._merge_back(batch)
                raise

    def _take_batch(self):
        if not self._dirty:
            return None
        batch = (
            self._pend_peers,
            self._pend_torrents,
            self._pend_meta,
            self._pend_del_torrents,
        )
        self._pend_peers = {}
        self._pend_torrents = {}
        self._pend_meta = {}
        self._pend_del_torrents = set()
        self._dirty = False
        return batch

    def _merge_back(self, batch) -> None:
        """落库失败时把批次放回 pending；期间新产生的变更（更新）优先保留。"""
        if batch is None:
            return
        pend_peers, pend_torrents, pend_meta, pend_del = batch
        for k, v in pend_peers.items():
            self._pend_peers.setdefault(k, v)
        for k, v in pend_torrents.items():
            self._pend_torrents.setdefault(k, v)
        for k, v in pend_meta.items():
            self._pend_meta.setdefault(k, v)
        for k in pend_del:
            # 若期间该种子又有新写入，则以新状态为准，不再整体删除
            if k not in self._pend_torrents and k not in self._pend_meta:
                self._pend_del_torrents.add(k)
        self._dirty = True

    def _ensure_conn(self) -> sqlite3.Connection:
        if self._conn is not None:
            return self._conn
        conn = sqlite3.connect(
            self.db_path, isolation_level=None, check_same_thread=False, timeout=5.0
        )
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.execute("PRAGMA cache_size=-16000")
        try:
            conn.execute("PRAGMA mmap_size=134217728")
        except sqlite3.Error:
            pass
        for stmt in self._SCHEMA:
            conn.execute(stmt)
        mode = conn.execute("PRAGMA journal_mode").fetchone()
        if mode and str(mode[0]).lower() != "wal":
            logger.warning(
                "SQLite journal_mode=%s（非 WAL，并发读性能受限；请确认数据库在本地磁盘）",
                mode[0],
            )
        self._conn = conn
        return conn

    def _flush_batch_sync(self, batch, metrics_snapshot: bytes | None) -> int:
        with self._write_lock:
            conn = self._ensure_conn()
            count = 0
            try:
                conn.execute("BEGIN")
                if batch is not None:
                    pend_peers, pend_torrents, pend_meta, pend_del = batch
                    now = time.time()
                    if pend_peers:
                        upserts: list[tuple] = []
                        deletes: list[tuple] = []
                        for (ih, pid), p in pend_peers.items():
                            if p is None:
                                deletes.append((ih, pid))
                            else:
                                # 防御性钳制：确保任何来源的 Peer 值都不超过
                                # SQLite INTEGER 上界，避免单条毒数据阻塞整批落库
                                upserts.append(
                                    (ih, pid, p.ip, p.port, p.last_seen,
                                     max(0, min(p.uploaded, _MAX_TRANSFER_VALUE)),
                                     max(0, min(p.downloaded, _MAX_TRANSFER_VALUE)),
                                     max(0, min(p.left, _MAX_TRANSFER_VALUE)))
                                )
                        for chunk in _chunked(upserts, 10_000):
                            conn.executemany(_PEER_UPSERT_SQL, chunk)
                        for chunk in _chunked(deletes, 10_000):
                            conn.executemany(
                                "DELETE FROM peers WHERE info_hash=? AND peer_id=?",
                                chunk,
                            )
                        count += len(pend_peers)
                    if pend_torrents:
                        rows = [
                            (ih, s, l, c, now)
                            for ih, (s, l, c) in pend_torrents.items()
                        ]
                        for chunk in _chunked(rows, 10_000):
                            conn.executemany(_TORRENT_COUNTER_SQL, chunk)
                        count += len(rows)
                    if pend_meta:
                        rows = [
                            (ih, name, size, plen, cdate, comment, created_by, now)
                            for ih, (name, size, plen, cdate, comment, created_by)
                            in pend_meta.items()
                        ]
                        for chunk in _chunked(rows, 10_000):
                            conn.executemany(_TORRENT_META_SQL, chunk)
                        count += len(rows)
                    # 整体删除放在最后：同批次的墓碑/重建操作先落地，语义安全
                    if pend_del:
                        dels = [(ih,) for ih in pend_del]
                        conn.executemany("DELETE FROM peers WHERE info_hash=?", dels)
                        conn.executemany("DELETE FROM torrents WHERE info_hash=?", dels)
                        count += len(dels)
                if metrics_snapshot is not None:
                    conn.execute(
                        "INSERT INTO meta(key, value) VALUES('metrics', ?) "
                        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                        (metrics_snapshot.decode("utf-8"),),
                    )
                conn.execute("COMMIT")
                return count
            except Exception:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise

    # -- 启动加载 / 查询 / 维护 -----------------------------------------------

    def open_and_init_sync(self) -> None:
        with self._write_lock:
            self._ensure_conn()

    def load_meta_sync(self) -> dict[str, str]:
        with self._write_lock:
            conn = self._ensure_conn()
            return {k: v for k, v in conn.execute("SELECT key, value FROM meta")}

    def load_all_sync(self, cutoff: float) -> tuple[list, list]:
        """加载种子元数据与未过期 peer 行（原始行，由 Tracker 装配校验）。"""
        with self._write_lock:
            conn = self._ensure_conn()
            torrent_rows = conn.execute(
                "SELECT info_hash, name, size, piece_length, creation_date, "
                "comment, created_by, completed FROM torrents"
            ).fetchall()
            peer_rows = conn.execute(
                "SELECT info_hash, peer_id, ip, port, last_seen, uploaded, downloaded, left "
                "FROM peers WHERE last_seen > ? AND port BETWEEN 1 AND 65535",
                (cutoff,),
            ).fetchall()
        return torrent_rows, peer_rows

    def query_all_stats_sync(self, cutoff: float) -> list:
        with self._write_lock:
            conn = self._ensure_conn()
            return conn.execute(_ALL_STATS_SQL, (cutoff, cutoff, cutoff)).fetchall()

    def insert_stats_history_sync(
        self, rows: list[tuple[float, bytes, int, int]], cutoff: float
    ) -> None:
        if not rows:
            return
        with self._write_lock:
            conn = self._ensure_conn()
            try:
                conn.execute("BEGIN")
                for chunk in _chunked(rows, 10_000):
                    conn.executemany(
                        "INSERT INTO stats_history(ts, info_hash, seeders, leechers) "
                        "VALUES(?, ?, ?, ?)",
                        chunk,
                    )
                conn.execute("DELETE FROM stats_history WHERE ts < ?", (cutoff,))
                conn.execute("COMMIT")
            except Exception:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise

    def checkpoint_sync(self) -> None:
        with self._write_lock:
            if self._conn is None:
                return
            try:
                self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except sqlite3.Error as exc:
                logger.warning("WAL checkpoint 失败：%s", exc)

    def close_sync(self) -> None:
        with self._write_lock:
            if self._conn is not None:
                try:
                    self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                except sqlite3.Error:
                    pass
                self._conn.close()
                self._conn = None


# ---------------------------------------------------------------------------
# 异步 Tracker 核心
# ---------------------------------------------------------------------------
class Tracker:
    def __init__(self) -> None:
        self.data_file: str = DATA_FILE
        self.store: SQLiteStore = SQLiteStore(DB_FILE)
        self.lock: asyncio.Lock = asyncio.Lock()
        self.torrents: dict[bytes, dict[bytes, Peer]] = {}
        self.torrent_info: dict[bytes, TorrentInfo] = {}
        self.completed_count: dict[bytes, int] = {}
        # 每个种子的 [seeders, leechers] 增量计数：announce/scrape O(1) 取用。
        # 由 announce/stopped 增量维护，cleanup 移除过期 peer 时重算校准（自愈）。
        # 误差上界：最近一个 CLEANUP_INTERVAL 内过期但尚未清理的 peer。
        self._swarm_counts: dict[bytes, list[int]] = {}
        self._stop_event = asyncio.Event()
        # 防 info_hash 洪水：ip -> (tokens, last_monotonic)
        self._new_hash_table: OrderedDict[str, list[float]] = OrderedDict()
        self._flush_task: asyncio.Task[None] | None = None
        self._metrics: "MetricsCollector | None" = None

    async def initialize(self, metrics: "MetricsCollector | None" = None) -> None:
        """启动加载：优先 SQLite；空库时尝试从旧版 JSON 状态文件一次性迁移。"""
        self._metrics = metrics
        await asyncio.to_thread(self.store.open_and_init_sync)

        meta = await asyncio.to_thread(self.store.load_meta_sync)
        if metrics is not None and meta.get("metrics"):
            metrics.load_snapshot_json(meta["metrics"])

        cutoff = time.time() - PEER_TIMEOUT
        torrent_rows, peer_rows = await asyncio.to_thread(
            self.store.load_all_sync, cutoff
        )
        if self._apply_db_rows(torrent_rows, peer_rows):
            return
        # SQLite 为空：尝试从旧版 JSON 状态文件迁移（一次性）
        if os.path.exists(self.data_file):
            await self._migrate_from_json()
        else:
            logger.info("未发现历史状态，以空状态启动（DB: %s）", self.store.db_path)

    def _apply_db_rows(self, torrent_rows: list, peer_rows: list) -> bool:
        """把 SQLite 加载的原始行装配进内存结构。返回是否有有效数据。"""
        now_wall = time.time()
        mono_now = time.monotonic()
        infos: dict[bytes, TorrentInfo] = {}
        completed: dict[bytes, int] = {}
        for row in torrent_rows:
            ih = row[0]
            if not isinstance(ih, bytes) or len(ih) != 20:
                continue
            infos[ih] = TorrentInfo(
                info_hash=ih,
                name=row[1] or "",
                size=int(row[2] or 0),
                piece_length=int(row[3] or 0),
                creation_date=float(row[4] or 0.0),
                comment=row[5],
                created_by=row[6],
            )
            completed[ih] = max(0, int(row[7] or 0))

        swarms: dict[bytes, dict[bytes, Peer]] = {}
        skipped = 0
        for row in peer_rows:
            ih, pid = row[0], row[1]
            if (
                not isinstance(ih, bytes)
                or len(ih) != 20
                or not isinstance(pid, bytes)
                or len(pid) != 20
            ):
                skipped += 1
                continue
            ip = row[2]
            port = int(row[3])
            if not _is_valid_ip(ip) or not (0 <= port <= 65535):
                skipped += 1
                continue
            last_seen = float(row[4])
            peer = Peer(
                peer_id=pid,
                ip=ip,
                port=port,
                last_seen=last_seen,
                uploaded=int(row[5] or 0),
                downloaded=int(row[6] or 0),
                left=int(row[7] or 0),
                mono_seen=mono_now - max(0.0, now_wall - last_seen),
            )
            swarm = swarms.get(ih)
            if swarm is None:
                swarm = {}
                swarms[ih] = swarm
            existing = swarm.get(pid)
            if existing is not None and existing.last_seen >= peer.last_seen:
                continue
            swarm[pid] = peer

        if not infos and not swarms:
            if skipped:
                logger.warning("SQLite 中仅有 %d 条非法记录，按空状态启动", skipped)
            return False

        counts: dict[bytes, list[int]] = {}
        for ih, swarm in swarms.items():
            seeders = sum(1 for p in swarm.values() if p.left == 0)
            counts[ih] = [seeders, len(swarm) - seeders]

        self.torrent_info.update(infos)
        self.completed_count.update(completed)
        self.torrents.update(swarms)
        self._swarm_counts.update(counts)
        if skipped:
            logger.warning("SQLite 加载时跳过 %d 条非法 peer 记录", skipped)
        logger.info(
            "状态从 %s 加载完毕：种子元数据 %d 条，活跃种子 %d 个，活跃 peer %d 个",
            self.store.db_path,
            len(infos),
            len(swarms),
            sum(len(s) for s in swarms.values()),
        )
        return True

    async def _migrate_from_json(self) -> None:
        """从旧版 JSON 状态文件一次性迁移到 SQLite，成功后归档 JSON。"""
        try:
            raw = await asyncio.to_thread(self._read_file_sync, self.data_file)
        except OSError as exc:
            logger.error("读取 JSON 状态文件失败：%s", exc)
            return
        if not raw:
            return
        try:
            state = _json_loads(raw)
        except Exception as exc:
            logger.error("JSON 状态文件解析失败，放弃迁移：%s", exc)
            return
        torrents_data = state.get("torrents", {}) if isinstance(state, dict) else {}
        if not isinstance(torrents_data, dict) or not torrents_data:
            logger.warning("JSON 状态文件无有效数据，跳过迁移")
            return

        now = time.time()
        loaded = skipped = 0
        for hex_hash, tdata in torrents_data.items():
            try:
                info_hash = hex_to_bytes(hex_hash)
                if len(info_hash) != 20:
                    raise ValueError(f"info_hash 长度非法: {len(info_hash)} 字节")
                info = TorrentInfo.from_dict(tdata["info"])
                if len(info.info_hash) != 20:
                    info.info_hash = info_hash

                unique: dict[bytes, Peer] = {}
                for pdata in tdata.get("peers_info", []):
                    last_seen = float(pdata.get("last_seen", 0))
                    if now - last_seen >= PEER_TIMEOUT:
                        continue
                    peer = Peer.from_dict(pdata)
                    if len(peer.peer_id) != 20 or not _is_valid_ip(peer.ip):
                        continue
                    if not (0 <= peer.port <= 65535):
                        continue
                    existing = unique.get(peer.peer_id)
                    if existing is None or peer.last_seen > existing.last_seen:
                        unique[peer.peer_id] = peer

                self.torrent_info[info_hash] = info
                self.completed_count[info_hash] = max(
                    0, int(tdata.get("stats", {}).get("completed", 0))
                )
                if unique:
                    self.torrents[info_hash] = unique
                    seeders = sum(1 for p in unique.values() if p.left == 0)
                    self._swarm_counts[info_hash] = [seeders, len(unique) - seeders]
                loaded += 1
            except Exception as exc:
                logger.warning("迁移时跳过损坏的种子记录 %s: %s", hex_hash, exc)
                skipped += 1

        # 全量入队并立即落库
        for info in self.torrent_info.values():
            self.store.queue_meta(info)
        for ih, swarm in self.torrents.items():
            for p in swarm.values():
                self.store.queue_peer(ih, p)
            s, l = self._swarm_counts.get(ih, (0, 0))
            self.store.queue_torrent(ih, s, l, self.completed_count.get(ih, 0))
        for ih, c in self.completed_count.items():
            if ih not in self.torrents:
                self.store.queue_torrent(ih, 0, 0, c)
        try:
            await self.store.flush_now()
        except sqlite3.Error as exc:
            logger.error("迁移落库失败：%s", exc)
            return
        try:
            os.replace(self.data_file, f"{self.data_file}.migrated.{int(time.time())}")
        except OSError:
            pass
        logger.info(
            "JSON → SQLite 迁移完成：成功 %d 条，跳过 %d 条（DB: %s）",
            loaded,
            skipped,
            self.store.db_path,
        )

    def _allow_new_hash(self, ip: str) -> bool:
        """单 IP 新建种子限速（Token Bucket）"""
        now = time.monotonic()
        table = self._new_hash_table
        entry = table.get(ip)
        if entry is None:
            entry = [float(NEW_HASH_BURST), now]
            table[ip] = entry
            while len(table) > NEW_HASH_MAX_ENTRIES:
                table.popitem(last=False)
        else:
            table.move_to_end(ip)
            elapsed = max(0.0, now - entry[1])
            entry[0] = min(float(NEW_HASH_BURST), entry[0] + elapsed * NEW_HASH_RATE_PER_SEC)
            entry[1] = now
        if entry[0] < 1.0:
            return False
        entry[0] -= 1.0
        return True

    async def cleanup_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=CLEANUP_INTERVAL)
                break
            except asyncio.TimeoutError:
                pass
            try:
                await self.cleanup_once()
            except Exception:
                logger.exception("定期清理异常")

    async def cleanup_once(self) -> None:
        cutoff_mono = time.monotonic() - PEER_TIMEOUT
        async with self.lock:
            for info_hash in tuple(self.torrents.keys()):
                peers = self.torrents.get(info_hash)
                if peers is None:
                    continue
                if not peers:
                    self.torrents.pop(info_hash, None)
                    self._swarm_counts.pop(info_hash, None)
                    continue
                expired = [pid for pid, p in peers.items() if p.mono_seen < cutoff_mono]
                if not expired:
                    continue
                for pid in expired:
                    del peers[pid]
                    self.store.queue_del_peer(info_hash, pid)
                if peers:
                    # 重算计数，顺带自愈校准增量计数器
                    seeders = sum(1 for p in peers.values() if p.left == 0)
                    leechers = len(peers) - seeders
                    self._swarm_counts[info_hash] = [seeders, leechers]
                    self.store.queue_torrent(
                        info_hash, seeders, leechers,
                        self.completed_count.get(info_hash, 0),
                    )
                else:
                    self.torrents.pop(info_hash, None)
                    self._swarm_counts.pop(info_hash, None)
                    self.store.queue_torrent(
                        info_hash, 0, 0, self.completed_count.get(info_hash, 0)
                    )
            # 清理 orphaned torrent_info 和 completed_count（无活跃 peer 且无有意义元数据）
            orphaned = [
                ih
                for ih in tuple(self.torrent_info.keys())
                if ih not in self.torrents
                and self.torrent_info[ih].name == ""
                and self.torrent_info[ih].size == 0
                and self.completed_count.get(ih, 0) == 0
            ]
            for ih in orphaned:
                self.torrent_info.pop(ih, None)
                self.completed_count.pop(ih, None)
                self.store.queue_del_torrent(ih)
            if orphaned:
                logger.debug("清理了 %d 个 orphaned 种子元数据条目", len(orphaned))
        logger.debug("清理完成，活跃种子数：%d", len(self.torrents))

    @staticmethod
    def _build_state_entry(
        info_dict: dict[str, Any], peers: tuple[Peer, ...], completed: int
    ) -> _TorrentStateDict:
        seeders = 0
        for p in peers:
            if p.left == 0:
                seeders += 1
        leechers = len(peers) - seeders
        return {
            "info": info_dict,
            "peers_info": [p.to_dict() for p in peers],
            "stats": {
                "complete": seeders,
                "incomplete": leechers,
                "peers": len(peers),
                "completed": completed,
            },
        }

    async def save_state(self, metrics: "MetricsCollector | None" = None) -> None:
        """强制把内存变更落库并做 WAL checkpoint"""
        count = await self.flush_to_db(metrics)
        await asyncio.to_thread(self.store.checkpoint_sync)
        logger.info("状态已持久化至 %s（本次落库 %d 条变更）", self.store.db_path, count)

    async def flush_to_db(self, metrics: "MetricsCollector | None" = None) -> int:
        """把 pending 变更批量写入 SQLite，并上报 flush 观测指标。"""
        start = time.monotonic()
        snap = metrics.snapshot_json() if metrics is not None else None
        try:
            count = await self.store.flush_now(snap)
        except Exception:
            if metrics is not None:
                metrics.observe_db_flush(
                    time.monotonic() - start, self.store.pending_count(), error=True
                )
            raise
        if metrics is not None:
            metrics.observe_db_flush(time.monotonic() - start, self.store.pending_count())
        return count

    def _maybe_flush(self) -> None:
        """pending 变更达到批量阈值时触发后台 flush（不阻塞热路径）。"""
        if self.store.pending_count() < DB_FLUSH_BATCH:
            return
        task = self._flush_task
        if task is not None and not task.done():
            return
        self._flush_task = asyncio.create_task(self._background_flush())

    async def _background_flush(self) -> None:
        try:
            await self.store.flush_now()
        except Exception:
            logger.exception("后台 SQLite flush 失败")

    async def db_flush_loop(self) -> None:
        """定期把 pending 变更落库（write-behind 的时间维度触发）。

        与 _maybe_flush 的批量阈值触发互补：低流量时保证变更在
        DB_FLUSH_INTERVAL 秒内持久化，缩小崩溃丢失窗口。
        """
        while not self._stop_event.is_set():
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=DB_FLUSH_INTERVAL)
                break
            except asyncio.TimeoutError:
                pass
            try:
                if self.store.pending_count():
                    await self.flush_to_db(self._metrics)
            except Exception:
                logger.exception("定期 SQLite flush 失败")

    async def build_json_snapshot(self) -> dict[str, Any]:
        """构建与旧版 JSON 状态文件兼容的内存快照（供 /export_state 备份使用）。"""
        raw_entries: list[tuple[bytes, dict[str, Any], tuple[Peer, ...], int]] = []
        async with self.lock:
            cutoff_mono = time.monotonic() - PEER_TIMEOUT
            seen: set[bytes] = set()
            for info_hash, info in self.torrent_info.items():
                seen.add(info_hash)
                peers_dict = self.torrents.get(info_hash)
                peers = (
                    tuple(p for p in peers_dict.values() if p.mono_seen >= cutoff_mono)
                    if peers_dict
                    else ()
                )
                raw_entries.append(
                    (info_hash, asdict(info), peers, self.completed_count.get(info_hash, 0))
                )
            for info_hash, peers_dict in self.torrents.items():
                if info_hash in seen:
                    continue
                peers = tuple(p for p in peers_dict.values() if p.mono_seen >= cutoff_mono)
                if peers:
                    seen.add(info_hash)
                    raw_entries.append(
                        (
                            info_hash,
                            asdict(TorrentInfo(info_hash=info_hash)),
                            peers,
                            self.completed_count.get(info_hash, 0),
                        )
                    )
            for info_hash, count in self.completed_count.items():
                if info_hash in seen:
                    continue
                if count > 0:
                    raw_entries.append(
                        (info_hash, asdict(TorrentInfo(info_hash=info_hash)), (), count)
                    )

        snapshot: dict[str, _TorrentStateDict] = {}
        for info_hash, info_dict, peers, completed in raw_entries:
            hex_hash = bytes_to_hex(info_hash)
            info_dict["info_hash"] = hex_hash
            snapshot[hex_hash] = self._build_state_entry(info_dict, peers, completed)
        return {"torrents": snapshot}

    @staticmethod
    def _read_file_sync(filepath: str) -> bytes:
        with open(filepath, "rb") as f:
            return f.read()

    async def stop(self) -> None:
        self._stop_event.set()

    async def announce(
        self,
        info_hash: bytes,
        peer_id: bytes,
        ip: str,
        port: int,
        uploaded: int,
        downloaded: int,
        left: int,
        event: str | None,
        numwant: int = 50,
    ) -> tuple[dict[str, int], list[Peer], str | None]:
        """处理 announce 请求。
        """
        # 输入校验：防止负值/超大值污染统计
        uploaded = max(0, min(uploaded, _MAX_TRANSFER_VALUE))
        downloaded = max(0, min(downloaded, _MAX_TRANSFER_VALUE))
        left = max(0, min(left, _MAX_TRANSFER_VALUE))

        zero_stats = {"complete": 0, "incomplete": 0, "downloaded": 0}
        is_private = not ALLOW_PRIVATE_IP and _is_private_ip(ip)
        snapshot: tuple[Peer, ...] = ()
        async with self.lock:
            peers = self.torrents.get(info_hash)
            if peers is None:
                if len(self.torrents) >= MAX_TORRENTS:
                    _warn_throttled(
                        "max_torrents",
                        "达到最大种子数上限 %d，拒绝新 info_hash %s",
                        MAX_TORRENTS,
                        bytes_to_hex(info_hash),
                    )
                    return zero_stats, [], "Torrent limit reached"
                if not self._allow_new_hash(ip):
                    _warn_throttled(
                        f"new_hash_flood:{ip}",
                        "IP %s 新建种子过快，已触发限速",
                        ip,
                    )
                    return zero_stats, [], "Rate limit: too many new torrents"
                peers = {}
                self.torrents[info_hash] = peers
            if info_hash not in self.torrent_info:
                self.torrent_info[info_hash] = TorrentInfo(info_hash=info_hash)
            if info_hash not in self.completed_count:
                self.completed_count[info_hash] = 0
            counts = self._swarm_counts.setdefault(info_hash, [0, 0])

            now_wall = time.time()
            now_mono = time.monotonic()
            old_peer = peers.get(peer_id)

            if event == "stopped":
                if old_peer is not None:
                    del peers[peer_id]
                    if old_peer.left == 0:
                        counts[0] -= 1
                    else:
                        counts[1] -= 1
                    self.store.queue_del_peer(info_hash, peer_id)
                if peers:
                    seeders, leechers = counts
                else:
                    self.torrents.pop(info_hash, None)
                    self._swarm_counts.pop(info_hash, None)
                    seeders = leechers = 0
                completed = self.completed_count.get(info_hash, 0)
                self.store.queue_torrent(info_hash, seeders, leechers, completed)
                self._maybe_flush()
                return (
                    {"complete": seeders, "incomplete": leechers, "downloaded": completed},
                    [],
                    None,
                )

            if not is_private:
                if event == "completed":
                    left = 0
                    if old_peer is None or old_peer.left > 0:
                        self.completed_count[info_hash] += 1

                if old_peer is None and len(peers) >= MAX_PEERS_PER_TORRENT:
                    # 仅在满员时做一次性惰性过期清理，避免每请求全扫描
                    cutoff_mono = now_mono - PEER_TIMEOUT
                    expired = [
                        pid for pid, p in peers.items() if p.mono_seen < cutoff_mono
                    ]
                    for pid in expired:
                        p = peers.pop(pid)
                        if p.left == 0:
                            counts[0] -= 1
                        else:
                            counts[1] -= 1
                        self.store.queue_del_peer(info_hash, pid)

                if old_peer is not None or len(peers) < MAX_PEERS_PER_TORRENT:
                    new_peer = Peer(
                        peer_id=peer_id,
                        ip=ip,
                        port=port,
                        last_seen=now_wall,
                        uploaded=uploaded,
                        downloaded=downloaded,
                        left=left,
                        mono_seen=now_mono,
                    )
                    peers[peer_id] = new_peer
                    # 增量维护 seeders/leechers 计数器
                    old_is_seed = old_peer is not None and old_peer.left == 0
                    new_is_seed = left == 0
                    if old_peer is None:
                        if new_is_seed:
                            counts[0] += 1
                        else:
                            counts[1] += 1
                    elif old_is_seed and not new_is_seed:
                        counts[0] -= 1
                        counts[1] += 1
                    elif not old_is_seed and new_is_seed:
                        counts[0] += 1
                        counts[1] -= 1
                    self.store.queue_peer(info_hash, new_peer)
                else:
                    _warn_throttled(
                        f"max_peers:{bytes_to_hex(info_hash)}",
                        "种子 %s 达到最大对等体数，拒绝新对等体",
                        bytes_to_hex(info_hash),
                    )

            seeders, leechers = counts
            completed = self.completed_count.get(info_hash, 0)
            stats = {
                "complete": seeders,
                "incomplete": leechers,
                "downloaded": completed,
            }
            self.store.queue_torrent(info_hash, seeders, leechers, completed)
            if peers:
                snapshot = tuple(peers.values())
            self._maybe_flush()

        if is_private or numwant <= 0 or not snapshot:
            return stats, [], None

        # 锁外过滤 + 采样：过期 peer 在此被跳过（实际删除交给定期清理）
        cutoff_mono = time.monotonic() - PEER_TIMEOUT
        candidates = [
            p
            for p in snapshot
            if p.mono_seen >= cutoff_mono and p.port > 0 and p.peer_id != peer_id
        ]
        n = len(candidates)
        if numwant >= n:
            _rand.shuffle(candidates)
            return stats, candidates, None
        return stats, _rand.sample(candidates, numwant), None

    async def scrape(self, info_hashes: list[bytes]) -> dict[bytes, dict[bytes, int]]:
        # 增量计数器使 scrape 降为 O(hash 数)，无需遍历 peer
        async with self.lock:
            result: dict[bytes, dict[bytes, int]] = {}
            for ih in info_hashes:
                counts = self._swarm_counts.get(ih)
                if counts is not None:
                    seeders, leechers = counts
                else:
                    seeders = leechers = 0
                result[ih] = {
                    b"seeders": seeders,
                    b"completed": self.completed_count.get(ih, 0),
                    b"leechers": leechers,
                }
            return result

    async def snapshot_swarm_stats(self) -> list[tuple[float, bytes, int, int]]:
        """当前各种子计数的快照（供 stats_history 定期采样）。"""
        ts = time.time()
        async with self.lock:
            return [
                (ts, ih, counts[0], counts[1])
                for ih, counts in self._swarm_counts.items()
                if counts[0] or counts[1]
            ]

    async def get_all_stats(self) -> dict[str, dict[str, Any]]:
        """先清理过期 peer 并强制 flush，再经 SQLite 聚合查询。
        """
        await self.cleanup_once()
        await self.flush_to_db()
        cutoff = time.time() - PEER_TIMEOUT
        rows = await asyncio.to_thread(self.store.query_all_stats_sync, cutoff)
        result: dict[str, dict[str, Any]] = {}
        for row in rows:
            ih = row[0]
            if not isinstance(ih, bytes) or len(ih) != 20:
                continue
            result[bytes_to_hex(ih)] = {
                "name": row[1] or "",
                "size": int(row[2] or 0),
                "creation_date": float(row[3] or 0.0),
                "complete": int(row[5] or 0),
                "incomplete": int(row[6] or 0),
                "downloaded": int(row[4] or 0),
                "uploaded_bytes": int(row[7] or 0),
                "downloaded_bytes": int(row[8] or 0),
                "peers": int(row[9] or 0),
            }
        return result

    async def upsert_torrent_info(
        self, info_hash: bytes, fields: dict[str, Any]
    ) -> None:
        """新增或更新种子元数据（供 /add_torrent_info 端点使用）。"""
        async with self.lock:
            info = self.torrent_info.get(info_hash)
            if info is not None:
                for field, value in fields.items():
                    setattr(info, field, value)
            else:
                info = TorrentInfo(
                    info_hash=info_hash,
                    name=fields.get("name", ""),
                    size=fields.get("size", 0),
                    piece_length=fields.get("piece_length", 0),
                    creation_date=time.time(),
                    comment=fields.get("comment"),
                    created_by=fields.get("created_by"),
                )
                self.torrent_info[info_hash] = info
            if info_hash not in self.completed_count:
                self.completed_count[info_hash] = 0
            self.store.queue_meta(info)
            counts = self._swarm_counts.get(info_hash, (0, 0))
            self.store.queue_torrent(
                info_hash, counts[0], counts[1], self.completed_count[info_hash]
            )


# ---------------------------------------------------------------------------
# HTTP 辅助函数
# ---------------------------------------------------------------------------
def _bencode_response(data: dict[Any, Any], status: int = 200) -> web.Response:
    try:
        payload = bencodepy.encode(data)
    except Exception:
        # 注意 bencode 长度前缀必须与字符串实际字节数一致（"encode error" = 12 字节）
        payload = b"d14:failure reason12:encode errore"
    return web.Response(body=payload, status=status, content_type="text/plain")


def _bencode_error(message: str) -> web.Response:
    """BEP 3: tracker 错误响应始终返回 HTTP 200 + failure reason。"""
    try:
        payload = bencodepy.encode({b"failure reason": message.encode("utf-8")})
    except Exception:
        msg = message.encode("utf-8")
        payload = b"d14:failure reason" + str(len(msg)).encode() + b":" + msg + b"e"
    return web.Response(body=payload, status=200, content_type="text/plain")


def _json_response(data: Any, status: int = 200, indent: int | None = None) -> web.Response:
    body = _json_dumps(data, indent=indent) if indent is not None else _json_dumps(data)
    return web.Response(body=body, status=status, content_type="application/json")


def _json_error(message: str, status: int = 400) -> web.Response:
    return _json_response({"error": message}, status=status)


def _get_client_ip(request: web.Request) -> str:
    if BEHIND_PROXY:
        # 从右向左取第一个合法 IP：右侧条目由可信代理追加，最左侧最易被客户端伪造
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            for part in reversed(xff.split(",")):
                cand = part.strip()
                if cand and _is_valid_ip(cand):
                    return _normalize_ip(cand)
        real_ip = request.headers.get("X-Real-IP", "").strip()
        if real_ip and _is_valid_ip(real_ip):
            return _normalize_ip(real_ip)
    transport = request.transport
    if transport is not None:
        peername = transport.get_extra_info("peername")
        if peername:
            return _normalize_ip(peername[0])
    return "127.0.0.1"


def _validate_hash(h: bytes | None, name: str) -> web.Response | None:
    if h is None:
        return _bencode_error(f"Missing {name}")
    if len(h) != 20:
        return _bencode_error(
            f"Invalid {name} length ({len(h)} bytes, expected 20). "
            f"Pass raw 20-byte binary or 40-char hex string."
        )
    return None


def _encode_compact_peers(peers: list[Peer]) -> tuple[bytes, bytes]:
    """编码 compact peer 列表，返回 (IPv4_blob, IPv6_blob)。
    """
    parts4: list[bytes] = []
    parts6: list[bytes] = []
    for p in peers:
        if p.port <= 0 or p.port > 65535:
            continue
        ip = _normalize_ip(p.ip)
        if ":" in ip:
            try:
                packed = socket.inet_pton(socket.AF_INET6, ip)
            except OSError:
                logger.debug("跳过无效 IPv6 peer: %s", ip)
                continue
            parts6.append(COMPACT6_STRUCT.pack(packed, p.port))
        else:
            try:
                packed = socket.inet_pton(socket.AF_INET, ip)
            except OSError:
                logger.debug("跳过无效 IPv4 peer: %s", ip)
                continue
            parts4.append(COMPACT4_STRUCT.pack(packed, p.port))
    return b"".join(parts4), b"".join(parts6)


def _check_api_key(request: web.Request) -> web.Response | None:
    if not API_KEY:
        # 未配置 API_KEY 时管理端点一律禁用，避免 /shutdown 等被匿名调用
        return _json_error("Admin API disabled (server has no API key)", status=403)
    provided = request.headers.get("X-API-Key", "")
    if not constant_time_compare(provided, API_KEY):
        return _json_error("Unauthorized", status=401)
    return None


def _check_announce_key(parsed_qs: dict[bytes, list[bytes]]) -> web.Response | None:
    if not API_KEY or not PROTECT_ANNOUNCE:
        return None
    key_bytes = _get_first(parsed_qs, "key")
    if key_bytes is None:
        return _bencode_error("Missing key (private tracker)")
    if not constant_time_compare(key_bytes, API_KEY.encode("utf-8")):
        return _bencode_error("Invalid key (private tracker)")
    return None


def _check_scrape_key(parsed_qs: dict[bytes, list[bytes]]) -> web.Response | None:
    if not API_KEY or not PROTECT_SCRAPE:
        return None
    key_bytes = _get_first(parsed_qs, "key")
    if key_bytes is None:
        return _bencode_error("Missing key (private tracker)")
    if not constant_time_compare(key_bytes, API_KEY.encode("utf-8")):
        return _bencode_error("Invalid key (private tracker)")
    return None


# ---------------------------------------------------------------------------
# HTTP 速率限制
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class _HttpRateEntry:
    tokens: float
    last_update: float


class _HttpRateLimiter:
    """per-IP Token Bucket，用于 HTTP /announce 与 /scrape。

    内部使用 OrderedDict 实现 LRU 淘汰，避免 O(n) 扫描。"""

    def __init__(self) -> None:
        self._enabled = _env_bool("HTTP_RATE_LIMIT_ENABLED", True)
        self._rps = _env_int("HTTP_RATE_LIMIT_RPS", 20)
        self._burst = _env_int("HTTP_RATE_LIMIT_BURST", 50)
        self._table: OrderedDict[str, _HttpRateEntry] = OrderedDict()
        self._max_entries = _env_int("HTTP_RATE_LIMIT_MAX_ENTRIES", 200_000)

    def check(self, ip: str) -> bool:
        if not self._enabled:
            return True
        now = time.monotonic()

        while len(self._table) >= self._max_entries:
            self._table.popitem(last=False)

        entry = self._table.get(ip)
        if entry is None:
            entry = _HttpRateEntry(tokens=float(self._burst), last_update=now)
            self._table[ip] = entry
        else:
            self._table.move_to_end(ip)
        elapsed = now - entry.last_update
        entry.tokens = min(float(self._burst), entry.tokens + elapsed * self._rps)
        entry.last_update = now
        if entry.tokens < 1.0:
            return False
        entry.tokens -= 1.0
        return True


# ---------------------------------------------------------------------------
# 异步 UDP Tracker
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class _UdpRateEntry:
    """每个 UDP 客户端的速率限制状态（双 Token Bucket）。"""

    packet_tokens: float
    connect_tokens: float
    last_update: float
    pending: int = 0


class _AsyncUDPTracker:
    def __init__(
        self,
        host: str,
        port: int,
        tracker: Tracker,
        stop_event: asyncio.Event,
        metrics: MetricsCollector,
    ) -> None:
        self.host = host
        self.port = port
        self.tracker = tracker
        self._stop_event = stop_event
        self._metrics = metrics
        self.transport: asyncio.DatagramTransport | None = None
        # addr -> (connection_id, created_monotonic)
        self.connections: OrderedDict[tuple[str, int], tuple[int, float]] = OrderedDict()
        self._conn_id_set: set[int] = set()
        self._udp_key = _udp_key_from_api_key()
        self._key_required = bool(self._udp_key is not None and PROTECT_ANNOUNCE)
        self._sem = asyncio.Semaphore(256)
        self._tasks: set[asyncio.Task[None]] = set()

        # UDP 速率限制配置
        self._rate_enabled = _env_bool("UDP_RATE_LIMIT_ENABLED", True)
        self._rate_packet_per_sec = _env_int("UDP_RATE_LIMIT_PACKET_PER_SEC", 20)
        self._rate_connect_per_sec = _env_int("UDP_RATE_LIMIT_CONNECT_PER_SEC", 2)
        self._rate_burst = _env_int("UDP_RATE_LIMIT_BURST", 5)
        self._rate_max_pending = _env_int("UDP_RATE_MAX_PENDING_PER_IP", 10)
        self._rate_max_entries = _env_int("UDP_RATE_MAX_ENTRIES", 200_000)
        self._rate_table: OrderedDict[tuple[str, int], _UdpRateEntry] = OrderedDict()

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[Any, ...]) -> None:
        if len(data) > MAX_UDP_PACKET_SIZE:
            return

        addr_key = self._addr_key(addr)

        if self._rate_enabled:
            is_connect = False
            if len(data) >= 16:
                try:
                    first_qword = struct.unpack("!Q", data[0:8])[0]
                    action = struct.unpack("!II", data[8:16])[0]
                    is_connect = first_qword == UDP_PROTOCOL_ID and action == ACTION_CONNECT
                except struct.error:
                    pass
            if not self._check_rate(addr_key, is_connect):
                return

        task = asyncio.create_task(self._handle_with_sem(data, addr, addr_key))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def error_received(self, exc: Exception) -> None:
        # ICMP 不可达等错误在公网环境很常见，降级为 warning 避免误报
        logger.warning("UDP 传输错误：%s", exc)

    def connection_lost(self, exc: Exception | None) -> None:
        if exc:
            logger.warning("UDP 连接丢失：%s", exc)
        self.transport = None

    @staticmethod
    def _addr_key(addr: tuple[Any, ...]) -> tuple[str, int]:
        return (addr[0], addr[1])

    def _check_rate(self, addr_key: tuple[str, int], is_connect: bool) -> bool:
        """同步 Token Bucket 检查（单事件循环线程内调用，无需加锁）。"""
        now = time.monotonic()
        entry = self._rate_table.get(addr_key)
        if entry is None:
            entry = _UdpRateEntry(
                packet_tokens=float(self._rate_burst),
                connect_tokens=1.0,
                last_update=now,
            )
            self._rate_table[addr_key] = entry
            while len(self._rate_table) > self._rate_max_entries:
                self._rate_table.popitem(last=False)
        else:
            self._rate_table.move_to_end(addr_key)

        elapsed = now - entry.last_update

        entry.packet_tokens = min(
            float(self._rate_burst),
            entry.packet_tokens + elapsed * self._rate_packet_per_sec,
        )
        entry.connect_tokens = min(
            float(max(1, self._rate_connect_per_sec)),
            entry.connect_tokens + elapsed * self._rate_connect_per_sec,
        )
        entry.last_update = now

        if entry.packet_tokens < 1.0:
            return False
        entry.packet_tokens -= 1.0

        if is_connect:
            if entry.connect_tokens < 1.0:
                return False
            entry.connect_tokens -= 1.0

        if entry.pending >= self._rate_max_pending:
            return False
        entry.pending += 1
        return True

    async def cleanup_connections_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                await asyncio.wait_for(
                    self._stop_event.wait(), timeout=UDP_CONN_CLEANUP_INTERVAL
                )
                break
            except asyncio.TimeoutError:
                pass
            try:
                await self._cleanup_connections()
                self._metrics.set_udp_connections(len(self.connections))
            except Exception:
                logger.exception("UDP 连接清理异常")

    async def _cleanup_connections(self) -> None:
        # 使用单调时钟，避免系统校时导致连接提前/延迟过期
        now_mono = time.monotonic()
        expired = [
            addr
            for addr, (_, created) in self.connections.items()
            if now_mono - created > UDP_CONNECTION_TIMEOUT
        ]
        for addr in expired:
            cid = self.connections.pop(addr, None)
            if cid is not None:
                self._conn_id_set.discard(cid[0])
        if expired:
            logger.debug("清理了 %d 个过期 UDP 连接", len(expired))

        stale = [
            addr
            for addr, entry in self._rate_table.items()
            if entry.pending == 0 and now_mono - entry.last_update > UDP_CONNECTION_TIMEOUT
        ]
        for addr in stale:
            self._rate_table.pop(addr, None)
        if stale:
            logger.debug("清理了 %d 个过期 UDP 速率限制条目", len(stale))

    async def _handle_with_sem(
        self, data: bytes, addr: tuple[Any, ...], addr_key: tuple[str, int]
    ) -> None:
        try:
            async with self._sem:
                await self._handle(data, addr)
        finally:
            entry = self._rate_table.get(addr_key)
            if entry is not None:
                entry.pending = max(0, entry.pending - 1)

    async def _handle(self, data: bytes, addr: tuple[Any, ...]) -> None:
        if len(data) < 16:
            return
        try:
            action, trans_id = struct.unpack("!II", data[8:16])
            first_qword = struct.unpack("!Q", data[0:8])[0]
        except struct.error:
            return

        addr_key = self._addr_key(addr)

        if first_qword == UDP_PROTOCOL_ID:
            if action == ACTION_CONNECT:
                try:
                    await self._handle_connect(trans_id, addr, addr_key)
                except Exception:
                    logger.exception("UDP connect 处理异常，来源 %s:%d", addr[0], addr[1])
            return

        conn_id = first_qword
        stored = self.connections.get(addr_key)
        if stored is None or not _constant_time_compare_int(stored[0], conn_id):
            self._send_error(trans_id, "Invalid connection ID", addr)
            return
        # 单调时钟判断连接是否过期
        if (time.monotonic() - stored[1]) > UDP_CONNECTION_TIMEOUT:
            cid = self.connections.pop(addr_key, None)
            if cid is not None:
                self._conn_id_set.discard(cid[0])
            self._metrics.set_udp_connections(len(self.connections))
            self._send_error(trans_id, "Invalid connection ID", addr)
            return
        self.connections.move_to_end(addr_key)

        try:
            if action == ACTION_ANNOUNCE:
                await self._handle_announce(data, trans_id, addr)
            elif action == ACTION_SCRAPE:
                await self._handle_scrape(data, trans_id, addr)
            else:
                # 未知 action：按 BEP 15 回送 action=3 错误响应，而不是静默丢弃
                self._send_error(trans_id, f"Invalid action {action}", addr)
        except Exception:
            logger.exception("UDP 处理异常，来源 %s:%d", addr[0], addr[1])

    async def _handle_connect(
        self, trans_id: int, addr: tuple[Any, ...], addr_key: tuple[str, int]
    ) -> None:
        old = self.connections.get(addr_key)
        if old is not None:
            self._conn_id_set.discard(old[0])

        # 64 位随机数碰撞概率极低，但加入最大重试次数作为防御
        MAX_CONN_ID_RETRIES = 100
        conn_id = secrets.randbits(64) or 1
        retries = 0
        while conn_id in self._conn_id_set:
            conn_id = secrets.randbits(64) or 1
            retries += 1
            if retries >= MAX_CONN_ID_RETRIES:
                logger.error(
                    "无法分配新 connection_id（已重试 %d 次），_conn_id_set 大小: %d",
                    MAX_CONN_ID_RETRIES,
                    len(self._conn_id_set),
                )
                self._send_error(trans_id, "Server busy, please retry", addr)
                return

        self.connections[addr_key] = (conn_id, time.monotonic())
        self._conn_id_set.add(conn_id)
        self.connections.move_to_end(addr_key)

        # 新条目已 move_to_end 至队尾，MAX_UDP_CONNECTIONS >= 1 时不会淘汰自身
        while len(self.connections) > MAX_UDP_CONNECTIONS:
            evicted_addr, (evicted_cid, _) = self.connections.popitem(last=False)
            self._conn_id_set.discard(evicted_cid)
            logger.debug("UDP 连接表达到上限，淘汰 %s:%d", evicted_addr[0], evicted_addr[1])
        response = UDP_CONNECT_RESPONSE.pack(ACTION_CONNECT, trans_id, conn_id)
        self._sendto(response, addr)
        self._metrics.set_udp_connections(len(self.connections))

    def _validate_udp_key(self, key: int) -> bool:
        if not self._key_required or self._udp_key is None:
            return True
        return _constant_time_compare_int(key, self._udp_key)

    async def _handle_announce(
        self, data: bytes, trans_id: int, addr: tuple[Any, ...]
    ) -> None:
        if len(data) < 98:
            self._send_error(trans_id, "Malformed announce request (too short)", addr)
            return
        try:
            (
                info_hash,
                peer_id,
                downloaded,
                left,
                uploaded,
                event,
                ip_raw,
                key,
                numwant,
                port,
            ) = UDP_ANNOUNCE_REQUEST.unpack(data[16:98])
        except struct.error:
            self._send_error(trans_id, "Malformed announce request", addr)
            return

        if port < 1 or port > 65535:
            self._send_error(trans_id, "Invalid port", addr)
            return

        if not self._validate_udp_key(key):
            self._send_error(trans_id, "Invalid key (private tracker)", addr)
            return

        raw_client = addr[0]
        # 先归一化再判断地址族：双栈 socket 上 IPv4 客户端的源地址为
        # "::ffff:a.b.c.d" 形式，若先判族会把 IPv4 客户端误判为 IPv6，
        # 导致返回错误的（通常为空的）peer 列表
        normalized_client = _normalize_ip(raw_client)
        client_is_v6 = ":" in normalized_client

        if not client_is_v6 and ip_raw != 0:
            try:
                client_ip = socket.inet_ntoa(struct.pack("!I", ip_raw))
                if not ALLOW_PRIVATE_IP and _is_private_ip(client_ip):
                    client_ip = normalized_client
            except (struct.error, OSError):
                client_ip = normalized_client
        else:
            client_ip = normalized_client

        event_str = UDP_EVENT_MAP.get(event)
        if event_str is None and event != 0:
            logger.debug(
                "UDP announce 收到未知 event 值 %d，来源 %s:%d",
                event, addr[0], addr[1],
            )
        # numwant 为 signed int32：-1（0xFFFFFFFF）表示使用默认值，与 HTTP 语义保持一致
        if numwant < 0:
            numwant += 0x100000000
        if numwant == 0xFFFFFFFF:
            numwant = MAX_NUMWANT
        elif numwant > MAX_NUMWANT:
            numwant = MAX_NUMWANT

        start = time.monotonic()
        stats, peers, failure = await self.tracker.announce(
            info_hash,
            peer_id,
            client_ip,
            port,
            uploaded,
            downloaded,
            left,
            event_str,
            numwant,
        )
        self._metrics.observe_duration("udp_announce", time.monotonic() - start)
        if failure is not None:
            self._metrics.inc_announce("udp", failed=True)
            self._send_error(trans_id, failure, addr)
            return
        self._metrics.inc_announce("udp")

        interval = INTERVAL
        leechers = min(stats["incomplete"], UINT32_MAX)
        seeders = min(stats["complete"], UINT32_MAX)

        if client_is_v6:
            same_family = [p for p in peers if ":" in _normalize_ip(p.ip)]
            peer_entry_size = 18
        else:
            same_family = [p for p in peers if ":" not in _normalize_ip(p.ip)]
            peer_entry_size = 6

        if not same_family and peers:
            logger.debug(
                "UDP announce: 无同地址族 peer 可用（客户端 %s，%d 个跨族 peer），"
                "返回空 peer 列表",
                "IPv6" if client_is_v6 else "IPv4",
                len(peers),
            )

        max_peer_bytes = max(0, UDP_MTU - UDP_ANNOUNCE_HDR_SIZE)
        max_peers_by_mtu = max_peer_bytes // peer_entry_size

        if len(same_family) > max_peers_by_mtu:
            same_family = _rand.sample(same_family, max_peers_by_mtu)
        else:
            _rand.shuffle(same_family)

        parts: list[bytes] = []
        packer = COMPACT6_STRUCT if client_is_v6 else COMPACT4_STRUCT
        af = socket.AF_INET6 if client_is_v6 else socket.AF_INET
        for p in same_family:
            ip = _normalize_ip(p.ip)
            try:
                packed = socket.inet_pton(af, ip)
                parts.append(packer.pack(packed, p.port))
            except OSError:
                continue
        peer_blob = b"".join(parts)

        response = UDP_ANNOUNCE_HEADER.pack(
            ACTION_ANNOUNCE, trans_id, interval, leechers, seeders
        ) + peer_blob
        self._sendto(response, addr)

    async def _handle_scrape(
        self, data: bytes, trans_id: int, addr: tuple[Any, ...]
    ) -> None:
        if len(data) < 16:
            self._send_error(trans_id, "Malformed scrape request", addr)
            return
        payload_len = len(data) - 16
        if payload_len % 20 != 0:
            self._send_error(trans_id, "Malformed scrape request", addr)
            return
        if API_KEY and PROTECT_SCRAPE:
            self._send_error(
                trans_id, "Scrape not allowed via UDP (private tracker)", addr
            )
            return

        count = payload_len // 20
        if count == 0:
            self._sendto(UDP_SCRAPE_HEADER.pack(ACTION_SCRAPE, trans_id), addr)
            return
        if count > MAX_SCRAPE_HASHES:
            count = MAX_SCRAPE_HASHES

        hashes = [data[16 + i * 20 : 16 + (i + 1) * 20] for i in range(count)]
        start = time.monotonic()
        files = await self.tracker.scrape(hashes)
        self._metrics.observe_duration("udp_scrape", time.monotonic() - start)
        self._metrics.inc_scrape("udp")

        parts: list[bytes] = [UDP_SCRAPE_HEADER.pack(ACTION_SCRAPE, trans_id)]
        for ih in hashes:
            stats = files.get(ih)
            if stats is None:
                parts.append(UDP_SCRAPE_STATS.pack(0, 0, 0))
            else:
                parts.append(
                    UDP_SCRAPE_STATS.pack(
                        min(stats[b"seeders"], UINT32_MAX),
                        min(stats[b"completed"], UINT32_MAX),
                        min(stats[b"leechers"], UINT32_MAX),
                    )
                )
        self._sendto(b"".join(parts), addr)

    def _send_error(self, trans_id: int, message: str, addr: tuple[Any, ...]) -> None:
        response = UDP_ERROR_HEADER.pack(ACTION_ERROR, trans_id) + message.encode("utf-8")
        self._sendto(response, addr)

    def _sendto(self, data: bytes, addr: tuple[Any, ...]) -> None:
        if self.transport is not None:
            self.transport.sendto(data, addr)


# ---------------------------------------------------------------------------
# aiohttp 路由（通过 app 上下文注入 tracker / metrics）
# ---------------------------------------------------------------------------
routes = web.RouteTableDef()
_start_time = time.monotonic()  # uptime 使用单调时钟，避免校时跳变

_shutdown_event = asyncio.Event()
_http_rate_limiter = _HttpRateLimiter()


def _get_tracker(request: web.Request) -> Tracker:
    """从 aiohttp app 上下文获取 Tracker 实例。"""
    return request.app["tracker"]


def _get_metrics(request: web.Request) -> MetricsCollector:
    """从 aiohttp app 上下文获取 MetricsCollector 实例。"""
    return request.app["metrics"]


@routes.get("/")
async def index(request: web.Request) -> web.Response:
    return _json_response(
        {
            "status": "ok",
            "service": "BitTorrent Tracker",
            "uptime": time.monotonic() - _start_time,
            "endpoints": {
                "announce": "/announce",
                "scrape": "/scrape",
                "health": "/health",
                "stats": "/stats (requires API key)",
                "metrics": "/metrics",
            },
        }
    )


@routes.get("/announce")
async def announce(request: web.Request) -> web.Response:
    client_ip = _get_client_ip(request)
    if not _http_rate_limiter.check(client_ip):
        _get_metrics(request).inc_rate_limit()
        return _bencode_error("Rate limit exceeded")

    start = time.monotonic()
    try:
        qs = request.rel_url.raw_query_string.encode("ascii")
        parsed_qs = _parse_query_string_raw(qs)

        auth_err = _check_announce_key(parsed_qs)
        if auth_err:
            _get_metrics(request).inc_announce("http", failed=True)
            return auth_err

        info_hash = _maybe_hex_to_bytes(_get_first(parsed_qs, "info_hash"))
        peer_id = _maybe_hex_to_bytes(_get_first(parsed_qs, "peer_id"))
        port_bytes = _get_first(parsed_qs, "port")

        err = _validate_hash(info_hash, "info_hash") or _validate_hash(peer_id, "peer_id")
        if err:
            _get_metrics(request).inc_announce("http", failed=True)
            return err
        if not port_bytes:
            _get_metrics(request).inc_announce("http", failed=True)
            return _bencode_error("Missing port")
        try:
            port = int(port_bytes)
            if port < 1 or port > 65535:
                _get_metrics(request).inc_announce("http", failed=True)
                return _bencode_error("Invalid port")
        except (ValueError, TypeError):
            _get_metrics(request).inc_announce("http", failed=True)
            return _bencode_error("Invalid port")

        uploaded = _get_int(parsed_qs, "uploaded", 0)
        downloaded = _get_int(parsed_qs, "downloaded", 0)
        left = _get_int(parsed_qs, "left", 0, negative_as_huge=True)

        numwant_bytes = _get_first(parsed_qs, "numwant")
        if numwant_bytes is None:
            numwant = 50
        else:
            try:
                numwant = int(numwant_bytes)
            except (ValueError, TypeError):
                _get_metrics(request).inc_announce("http", failed=True)
                return _bencode_error("Invalid numwant parameter")
            if numwant == -1:
                numwant = MAX_NUMWANT
            elif numwant < 0:
                numwant = 0
            numwant = min(numwant, MAX_NUMWANT)

        event_bytes = _get_first(parsed_qs, "event")
        event = event_bytes.decode("ascii", errors="replace") if event_bytes else None
        if event is not None and event not in VALID_EVENTS:
            event = None

        compact = _is_truthy(_get_first(parsed_qs, "compact"))

        # ip 查询参数默认不信任（可被伪造用于污染 swarm），仅在显式配置时启用
        ip_param: str | None = None
        if ALLOW_IP_PARAM:
            ip_param_bytes = _get_first(parsed_qs, "ip")
            if ip_param_bytes:
                cand = ip_param_bytes.decode("ascii", errors="replace")
                if _is_valid_ip(cand):
                    ip_param = cand

        if ip_param is not None and (ALLOW_PRIVATE_IP or not _is_private_ip(ip_param)):
            ip = _normalize_ip(ip_param)
        else:
            ip = client_ip

        if not _is_valid_ip(ip):
            ip = "127.0.0.1"

        stats, peers, failure = await _get_tracker(request).announce(
            info_hash=info_hash,
            peer_id=peer_id,
            ip=ip,
            port=port,
            uploaded=uploaded,
            downloaded=downloaded,
            left=left,
            event=event,
            numwant=numwant,
        )
        if failure is not None:
            _get_metrics(request).inc_announce("http", failed=True)
            return _bencode_error(failure)

        response_data: dict[bytes, Any] = {
            b"interval": INTERVAL,
            b"min interval": MIN_INTERVAL,
            b"complete": stats["complete"],
            b"incomplete": stats["incomplete"],
            b"downloaded": stats["downloaded"],
        }

        if compact:
            v4_blob, v6_blob = _encode_compact_peers(peers)
            response_data[b"peers"] = v4_blob
            if v6_blob:
                response_data[b"peers6"] = v6_blob
        else:
            response_data[b"peers"] = [
                {
                    b"peer id": p.peer_id,
                    b"ip": _normalize_ip(p.ip).encode("ascii"),
                    b"port": p.port,
                }
                for p in peers
            ]

        _get_metrics(request).inc_announce("http")
        return _bencode_response(response_data)
    except Exception:
        logger.exception("Announce 处理错误")
        _get_metrics(request).inc_announce("http", failed=True)
        return _bencode_error("Internal tracker error")
    finally:
        _get_metrics(request).observe_duration("http_announce", time.monotonic() - start)


@routes.get("/scrape")
async def scrape(request: web.Request) -> web.Response:
    client_ip = _get_client_ip(request)
    if not _http_rate_limiter.check(client_ip):
        _get_metrics(request).inc_rate_limit()
        return _bencode_error("Rate limit exceeded")

    start = time.monotonic()
    try:
        qs = request.rel_url.raw_query_string.encode("ascii")
        parsed_qs = _parse_query_string_raw(qs)

        auth_err = _check_scrape_key(parsed_qs)
        if auth_err:
            _get_metrics(request).inc_scrape("http", failed=True)
            return auth_err

        info_hashes = list(_get_all(parsed_qs, "info_hash"))

        extra = request.match_info.get("extra", "")
        if extra:
            for chunk in extra.strip("/").split("/"):
                chunk = chunk.strip()
                chunk_bytes = chunk.encode("ascii")
                if len(chunk_bytes) == 40 and _HEX_RE.match(chunk_bytes):
                    info_hashes.append(chunk_bytes)

        if not info_hashes:
            _get_metrics(request).inc_scrape("http", failed=True)
            return _bencode_error("Missing info_hash")

        seen: set[bytes] = set()
        unique: list[bytes] = []
        for ih in info_hashes:
            norm = _maybe_hex_to_bytes(ih)
            if not norm or len(norm) != 20:
                continue
            if norm in seen:
                continue
            seen.add(norm)
            unique.append(norm)

        if not unique:
            _get_metrics(request).inc_scrape("http", failed=True)
            return _bencode_error("No valid info_hash")
        if len(unique) > MAX_SCRAPE_HASHES:
            unique = unique[:MAX_SCRAPE_HASHES]

        files = await _get_tracker(request).scrape(unique)
        http_files: dict[bytes, dict[bytes, int]] = {}
        for ih, s in files.items():
            http_files[ih] = {
                b"complete": s[b"seeders"],
                b"downloaded": s[b"completed"],
                b"incomplete": s[b"leechers"],
            }
        _get_metrics(request).inc_scrape("http")
        return _bencode_response({b"files": http_files})
    except Exception:
        logger.exception("Scrape 处理错误")
        _get_metrics(request).inc_scrape("http", failed=True)
        return _bencode_error("Internal tracker error")
    finally:
        _get_metrics(request).observe_duration("http_scrape", time.monotonic() - start)


@routes.get("/metrics")
async def metrics_endpoint(request: web.Request) -> web.Response:
    return web.Response(
        body=_get_metrics(request).render(),
        content_type="text/plain; version=0.0.4",
        charset="utf-8",
    )


@routes.post("/add_torrent_info")
async def add_torrent_info(request: web.Request) -> web.Response:
    auth = _check_api_key(request)
    if auth:
        return auth
    try:
        if request.content_length and request.content_length > MAX_HTTP_BODY_SIZE:
            return _json_error("Request body too large", status=413)
        try:
            data = await request.json()
        except web.HTTPException:
            # aiohttp 对非法 Content-Type 抛 HTTPBadRequest，交还给框架处理
            raise
        except (ValueError, UnicodeDecodeError):
            return _json_error("Invalid JSON body", status=400)
        if not isinstance(data, dict):
            return _json_error("Request body must be a JSON object", status=400)
        if "info_hash" not in data:
            return _json_error("Missing info_hash")
        try:
            info_hash = hex_to_bytes(str(data["info_hash"]))
            if len(info_hash) != 20:
                return _json_error("info_hash must be 20 bytes")
        except Exception:
            return _json_error("Invalid info_hash hex")

        allowed_fields = {"name", "size", "piece_length", "comment", "created_by"}
        update_data: dict[str, Any] = {}
        for field in allowed_fields:
            if field in data:
                val = data[field]
                if field in ("name", "comment", "created_by"):
                    update_data[field] = (
                        str(val) if val is not None else ("" if field == "name" else None)
                    )
                else:
                    try:
                        v = int(val) if val is not None else 0
                        if v < 0:
                            return _json_error(
                                f"Field {field} must be non-negative"
                            )
                        update_data[field] = v
                    except (ValueError, TypeError):
                        return _json_error(f"Invalid value for field {field}")

        await _get_tracker(request).upsert_torrent_info(info_hash, update_data)
        return _json_response({"status": "ok"})
    except web.HTTPException:
        raise
    except Exception:
        logger.exception("add_torrent_info 错误")
        return _json_error("Internal error", status=500)


@routes.get("/stats")
async def get_all_stats(request: web.Request) -> web.Response:
    auth = _check_api_key(request)
    if auth:
        return auth
    try:
        return _json_response(await _get_tracker(request).get_all_stats(), indent=2)
    except Exception:
        logger.exception("stats 错误")
        return _json_error("Internal error", status=500)


@routes.post("/save_state")
async def save_state(request: web.Request) -> web.Response:
    auth = _check_api_key(request)
    if auth:
        return auth
    await _get_tracker(request).save_state()
    return _json_response({"status": "ok", "message": "Tracker 状态已保存"})


@routes.get("/export_state")
async def export_state(request: web.Request) -> web.Response:
    """导出与旧版 JSON 状态格式兼容的全量快照（备份/迁移用）。"""
    auth = _check_api_key(request)
    if auth:
        return auth
    try:
        snapshot = await _get_tracker(request).build_json_snapshot()
        return _json_response(snapshot)
    except Exception:
        logger.exception("export_state 错误")
        return _json_error("Internal error", status=500)


@routes.get("/health")
async def health(request: web.Request) -> web.Response:
    return _json_response(
        {
            "status": "ok",
            "uptime": time.monotonic() - _start_time,
            "torrents": len(_get_tracker(request).torrents),
            "udp_port": UDP_PORT,
            "http_port": PORT,
        }
    )


@routes.post("/shutdown")
async def shutdown(request: web.Request) -> web.Response:
    auth = _check_api_key(request)
    if auth:
        return auth
    if not _shutdown_event.is_set():
        _shutdown_event.set()
    return _json_response({"status": "shutting down"})


# ---------------------------------------------------------------------------
# 应用工厂（便于测试）
# ---------------------------------------------------------------------------
def create_app(tracker: Tracker | None = None, metrics: MetricsCollector | None = None) -> web.Application:
    app = web.Application(client_max_size=MAX_HTTP_BODY_SIZE)
    app.add_routes(routes)
    # 统一路由：/scrape 与 /scrape/<hash>
    app.router.add_get("/scrape/{extra:.*}", scrape)
    # 注入 tracker / metrics 实例到 app 上下文
    app["tracker"] = tracker if tracker is not None else Tracker()
    app["metrics"] = metrics if metrics is not None else MetricsCollector()
    return app


# ---------------------------------------------------------------------------
# 信号与自动保存
# ---------------------------------------------------------------------------
async def _auto_save_loop(tracker: Tracker) -> None:
    while not _shutdown_event.is_set():
        try:
            await asyncio.wait_for(_shutdown_event.wait(), timeout=AUTO_SAVE_INTERVAL)
            break
        except asyncio.TimeoutError:
            pass
        try:
            await tracker.save_state()
        except Exception:
            logger.exception("自动保存失败")


async def _metrics_refresh_loop(tracker: Tracker, metrics: MetricsCollector) -> None:
    """定期刷新 gauge 类指标（活跃种子数/peer 数）。
    UDP 连接数由 _handle_connect 和 cleanup_connections_loop 增量更新。
    """
    while not _shutdown_event.is_set():
        try:
            await asyncio.wait_for(_shutdown_event.wait(), timeout=15)
            break
        except asyncio.TimeoutError:
            pass
        try:
            now = time.time()
            cutoff = now - PEER_TIMEOUT
            async with tracker.lock:
                torrents = len(tracker.torrents)
                peers = sum(
                    sum(1 for p in pdict.values() if p.last_seen >= cutoff)
                    for pdict in tracker.torrents.values()
                )
            metrics.set_torrents(torrents)
            metrics.set_peers(peers)
        except Exception:
            logger.exception("指标刷新失败")


async def _stats_history_loop(tracker: Tracker) -> None:
    """定期把各种子的 seeders/leechers 采样写入 stats_history 表。

    用于事后统计趋势；采样与保留窗口均可配置。关闭 DB_STATS_HISTORY 即停用。
    """
    if not DB_STATS_HISTORY:
        return
    while not _shutdown_event.is_set():
        try:
            await asyncio.wait_for(_shutdown_event.wait(), timeout=STATS_HISTORY_INTERVAL)
            break
        except asyncio.TimeoutError:
            pass
        try:
            rows = await tracker.snapshot_swarm_stats()
            if rows:
                cutoff = time.time() - STATS_HISTORY_RETENTION
                await asyncio.to_thread(
                    tracker.store.insert_stats_history_sync, rows, cutoff
                )
        except Exception:
            logger.exception("stats_history 采样失败")


# ---------------------------------------------------------------------------
# UDP 服务器启动
# ---------------------------------------------------------------------------
async def _setup_udp_server(
    host: str, port: int, tracker: Tracker, metrics: MetricsCollector
) -> _AsyncUDPTracker:
    loop = asyncio.get_running_loop()
    sock = _create_udp_socket(host, port)
    protocol = _AsyncUDPTracker(host, port, tracker, _shutdown_event, metrics)

    transport, _ = await loop.create_datagram_endpoint(
        lambda: protocol,
        sock=sock,
    )
    protocol.transport = transport

    logger.info("UDP Tracker 监听于 %s:%d（asyncio 模式）", host, port)
    if protocol._rate_enabled:
        logger.info(
            "UDP Tracker 已启用 per-IP 速率限制: 包 %d/s, connect %d/s, burst %d",
            protocol._rate_packet_per_sec,
            protocol._rate_connect_per_sec,
            protocol._rate_burst,
        )
    if protocol._key_required:
        logger.info("UDP Tracker 已启用 API Key 验证（私有模式）")

    return protocol


def _create_udp_socket(host: str, port: int) -> socket.socket:
    sock = _try_create_v6_dual(host, port)
    if sock is not None:
        return sock
    return _create_v4(host, port)


def _try_create_v6_dual(host: str, port: int) -> socket.socket | None:
    try:
        addr = ipaddress.ip_address(host)
        if isinstance(addr, ipaddress.IPv6Address):
            family = socket.AF_INET6
            bind = (host, port)
        elif isinstance(addr, ipaddress.IPv4Address) and str(addr) != "0.0.0.0":
            return None
        else:
            family = socket.AF_INET6
            bind = ("::", port)
    except ValueError:
        family = socket.AF_INET6
        bind = ("::", port)

    try:
        sock = socket.socket(family, socket.SOCK_DGRAM)
    except OSError:
        return None
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except (AttributeError, OSError):
        pass
    if family == socket.AF_INET6:
        try:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        except OSError:
            pass
    try:
        sock.bind(bind)
    except OSError:
        sock.close()
        return None
    sock.setblocking(False)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
    except OSError:
        pass
    return sock


def _create_v4(host: str, port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except (AttributeError, OSError):
        pass
    sock.bind((host, port))
    sock.setblocking(False)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
    except OSError:
        pass
    return sock


# ---------------------------------------------------------------------------
# 主入口
# ---------------------------------------------------------------------------
async def _main() -> None:
    tracker = Tracker()
    metrics = MetricsCollector()

    await tracker.initialize(metrics)
    udp_protocol = await _setup_udp_server(IP, UDP_PORT, tracker, metrics)

    app = create_app(tracker=tracker, metrics=metrics)

    runner = web.AppRunner(app)
    await runner.setup()
    try:
        site = web.TCPSite(runner, IP, PORT)
        await site.start()
    except Exception:
        # HTTP 绑定失败时确保 UDP socket 被释放
        await runner.cleanup()
        if udp_protocol.transport is not None:
            udp_protocol.transport.close()
        raise

    logger.info("Tracker 服务端运行于 %s:%d (TCP+UDP，统一 asyncio 事件循环)", IP, PORT)
    if API_KEY:
        logger.info("管理端点已启用 API 密钥认证")
        if PROTECT_ANNOUNCE:
            logger.info("Announce 端点已启用 API Key 保护（私有模式）")
        if PROTECT_SCRAPE:
            logger.info("Scrape 端点已启用 API Key 保护（私有模式）")
    else:
        logger.warning("API 密钥未设置：/stats、/save_state、/shutdown、/add_torrent_info 已禁用！")

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _shutdown_event.set)
        except NotImplementedError:
            # Windows 等不支持 add_signal_handler 的平台：
            # 通过 call_soon_threadsafe 安全地在事件循环线程内 set
            signal.signal(sig, lambda s, f: loop.call_soon_threadsafe(_shutdown_event.set))  # type: ignore[misc]

    try:
        async with asyncio.TaskGroup() as tg:
            background_tasks = [
                tg.create_task(udp_protocol.cleanup_connections_loop()),
                tg.create_task(tracker.cleanup_loop()),
                tg.create_task(tracker.db_flush_loop()),
                tg.create_task(_auto_save_loop(tracker)),
                tg.create_task(_metrics_refresh_loop(tracker, metrics)),
                tg.create_task(_stats_history_loop(tracker)),
            ]
            await _shutdown_event.wait()
            for task in background_tasks:
                task.cancel()
    except* asyncio.CancelledError:
        pass
    except* Exception as eg:
        for exc in eg.exceptions:
            logger.error("后台任务异常退出：%s", exc)

    await tracker.stop()

    try:
        await tracker.cleanup_once()
        await udp_protocol._cleanup_connections()
        metrics.set_udp_connections(len(udp_protocol.connections))
    except Exception:
        logger.exception("shutdown 清理异常")

    await runner.cleanup()
    if udp_protocol.transport is not None:
        udp_protocol.transport.close()
    try:
        await tracker.save_state()
    except Exception:
        logger.exception("退出前保存状态失败")
    try:
        await asyncio.to_thread(tracker.store.close_sync)
    except Exception:
        logger.exception("关闭 SQLite 连接失败")
    logger.info("Tracker 已停止。")


if __name__ == "__main__":
    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        pass
    finally:
        logger.info("进程退出。")