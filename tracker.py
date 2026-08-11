# -*- coding: utf-8 -*-

import asyncio
import functools
import hashlib
import hmac
import ipaddress
import logging
import os
import re
import secrets
import signal
import socket
import struct
import sys
import tempfile
import time
from collections import OrderedDict
from dataclasses import dataclass, asdict
from typing import Any, Final, NamedTuple, TypedDict

try:
    from typing import Self
except ImportError:  
    from typing_extensions import Self

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
# 配置
# ---------------------------------------------------------------------------
def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except (ValueError, TypeError):
        return default


def _env_log_level(name: str, default: str = "INFO") -> int:
    raw = os.environ.get(name, default).strip().upper()
    return getattr(logging, raw, logging.INFO)


IP: str = os.environ.get("TRACKER_IP", "0.0.0.0")
PORT: int = _env_int("TRACKER_PORT", 6969)
UDP_PORT: int = _env_int("TRACKER_UDP_PORT", PORT)

MIN_INTERVAL: int = _env_int("TRACKER_MIN_INTERVAL", _env_int("MIN_INTERVAL", 900))
INTERVAL: int = _env_int("TRACKER_INTERVAL", MIN_INTERVAL)
PEER_TIMEOUT: int = _env_int("PEER_TIMEOUT", 1800)

DATA_FILE: str = os.environ.get("DATA_FILE", "tracker_state.json")
AUTO_SAVE_INTERVAL: int = _env_int("AUTO_SAVE_INTERVAL", 300)
CLEANUP_INTERVAL: int = _env_int("CLEANUP_INTERVAL", 120)

MAX_PEERS_PER_TORRENT: int = _env_int("MAX_PEERS_PER_TORRENT", 1000)
MAX_TORRENTS: int = _env_int("MAX_TORRENTS", 1_000_000)
MAX_NUMWANT: int = _env_int("MAX_NUMWANT", 200)
MAX_SCRAPE_HASHES: int = 74
_MAX_TRANSFER_VALUE: int = 1 << 63  # 单 peer 传输量上限，防止统计溢出

API_KEY: str = os.environ.get("TRACKER_API_KEY", "")
PROTECT_ANNOUNCE: bool = _env_bool("TRACKER_PROTECT_ANNOUNCE", False)
PROTECT_SCRAPE: bool = _env_bool("TRACKER_PROTECT_SCRAPE", False)
ALLOW_PRIVATE_IP: bool = _env_bool("TRACKER_ALLOW_PRIVATE_IP", True)
BEHIND_PROXY: bool = _env_bool("TRACKER_BEHIND_PROXY", False)

UDP_CONNECTION_TIMEOUT: int = _env_int("UDP_CONNECTION_TIMEOUT", 120)
UDP_CONN_CLEANUP_INTERVAL: int = _env_int("UDP_CONN_CLEANUP_INTERVAL", 30)
MAX_UDP_CONNECTIONS: int = _env_int("MAX_UDP_CONNECTIONS", 100_000)

MAX_UDP_PACKET_SIZE: int = _env_int("MAX_UDP_PACKET_SIZE", 4096)
MAX_HTTP_BODY_SIZE: int = _env_int("MAX_HTTP_BODY_SIZE", 65536)

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
_SENTINEL_HUGE: Final[int] = 1 << 63

# 配置合理性校验
if MIN_INTERVAL <= 0:
    MIN_INTERVAL = 900
if INTERVAL < MIN_INTERVAL:
    INTERVAL = MIN_INTERVAL
if MAX_UDP_CONNECTIONS <= 0:
    MAX_UDP_CONNECTIONS = 100_000

# 防止 0/负数导致忙循环或语义错误
MIN_INTERVAL = max(1, MIN_INTERVAL)
INTERVAL = max(MIN_INTERVAL, INTERVAL)
PEER_TIMEOUT = max(1, PEER_TIMEOUT)
AUTO_SAVE_INTERVAL = max(1, AUTO_SAVE_INTERVAL)
CLEANUP_INTERVAL = max(1, CLEANUP_INTERVAL)
UDP_CONNECTION_TIMEOUT = max(1, UDP_CONNECTION_TIMEOUT)
UDP_CONN_CLEANUP_INTERVAL = max(1, UDP_CONN_CLEANUP_INTERVAL)
MAX_PEERS_PER_TORRENT = max(1, MAX_PEERS_PER_TORRENT)
MAX_TORRENTS = max(1, MAX_TORRENTS)
MAX_NUMWANT = max(1, MAX_NUMWANT)
MAX_SCRAPE_HASHES = max(1, MAX_SCRAPE_HASHES)

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

# 加密安全的随机源，统一用于所有随机选择
_sr = secrets.SystemRandom()


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
    allow_negative: bool = False,
) -> int:
    val = _get_first(parsed_qs, key)
    if val is None:
        return default
    try:
        v = int(val)
    except (ValueError, TypeError):
        return default
    if allow_negative:
        return v if v >= 0 else _SENTINEL_HUGE
    return max(0, v)


def _is_truthy(val: bytes | None) -> bool:
    """判断 bencoded/query 参数是否为真值（1/true/True）。"""
    if val is None:
        return False
    return val.lower() in _COMPACT_TRUTHY


@functools.lru_cache(maxsize=32768)
def _is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return addr.is_private or addr.is_loopback or addr.is_multicast or addr.is_unspecified


@functools.lru_cache(maxsize=32768)
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


@functools.lru_cache(maxsize=32768)
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
    """
    if not API_KEY:
        return None
    try:
        # 纯数字字符串：直接取低 32 位
        raw = int(API_KEY) & 0xFFFFFFFF
    except ValueError:
        pass
    else:
        return raw - 0x100000000 if raw >= 0x80000000 else raw
    digest = hashlib.sha256(API_KEY.encode("utf-8")).digest()
    raw = int.from_bytes(digest[:4], "big", signed=False)
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
    uploaded: int
    downloaded: int
    peers: int
    completed: int


class _TorrentStateDict(TypedDict):
    info: dict[str, Any]
    peers_info: list[_PeerDict]
    stats: _TorrentStatsDict


class _StatsCacheEntry(NamedTuple):
    """缓存的 torrent 统计信息。"""

    seeders: int
    leechers: int
    timestamp: float


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
        return cls(
            peer_id=hex_to_bytes(data.get("peer_id", "")),
            ip=data.get("ip", "0.0.0.0"),
            port=int(data.get("port", 0)),
            last_seen=float(data.get("last_seen", 0.0)),
            uploaded=int(data.get("uploaded", 0)),
            downloaded=int(data.get("downloaded", 0)),
            left=int(data.get("left", 0)),
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
    """Prometheus 风格的指标收集器（不依赖 prometheus_client）。"""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
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

    async def set_torrents(self, value: int) -> None:
        async with self._lock:
            self._torrents = value

    async def set_peers(self, value: int) -> None:
        async with self._lock:
            self._peers = value

    async def set_udp_connections(self, value: int) -> None:
        async with self._lock:
            self._udp_connections = value

    async def inc_announce(self, protocol: str, failed: bool = False) -> None:
        async with self._lock:
            self._announce_total[protocol] = self._announce_total.get(protocol, 0) + 1
            if failed:
                self._announce_fail[protocol] = self._announce_fail.get(protocol, 0) + 1

    async def inc_scrape(self, protocol: str, failed: bool = False) -> None:
        async with self._lock:
            self._scrape_total[protocol] = self._scrape_total.get(protocol, 0) + 1
            if failed:
                self._scrape_fail[protocol] = self._scrape_fail.get(protocol, 0) + 1

    async def inc_rate_limit(self) -> None:
        async with self._lock:
            self._rate_limit_hits += 1

    async def observe_duration(self, endpoint: str, duration: float) -> None:
        async with self._lock:
            self._request_duration_sum[endpoint] += duration
            self._request_duration_count[endpoint] += 1

    async def render(self) -> str:
        async with self._lock:
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

            for protocol in ("http", "udp"):
                lines.append("# HELP tracker_announce_requests_total Total announce requests")
                lines.append("# TYPE tracker_announce_requests_total counter")
                lines.append(
                    f'tracker_announce_requests_total{{protocol="{protocol}"}} '
                    f"{self._announce_total.get(protocol, 0)}"
                )

                lines.append("# HELP tracker_scrape_requests_total Total scrape requests")
                lines.append("# TYPE tracker_scrape_requests_total counter")
                lines.append(
                    f'tracker_scrape_requests_total{{protocol="{protocol}"}} '
                    f"{self._scrape_total.get(protocol, 0)}"
                )

                lines.append("# HELP tracker_announce_failures_total Total failed announce requests")
                lines.append("# TYPE tracker_announce_failures_total counter")
                lines.append(
                    f'tracker_announce_failures_total{{protocol="{protocol}"}} '
                    f"{self._announce_fail.get(protocol, 0)}"
                )

                lines.append("# HELP tracker_scrape_failures_total Total failed scrape requests")
                lines.append("# TYPE tracker_scrape_failures_total counter")
                lines.append(
                    f'tracker_scrape_failures_total{{protocol="{protocol}"}} '
                    f"{self._scrape_fail.get(protocol, 0)}"
                )

            lines.append("# HELP tracker_rate_limit_hits_total Total rate limit hits")
            lines.append("# TYPE tracker_rate_limit_hits_total counter")
            lines.append(f"tracker_rate_limit_hits_total {self._rate_limit_hits}")

            lines.append("# HELP tracker_request_duration_seconds_total Total request duration in seconds")
            lines.append("# TYPE tracker_request_duration_seconds_total counter")
            for endpoint, total in self._request_duration_sum.items():
                lines.append(
                    f'tracker_request_duration_seconds_total{{endpoint="{endpoint}"}} {total}'
                )

            lines.append("# HELP tracker_request_duration_seconds_count Total request count")
            lines.append("# TYPE tracker_request_duration_seconds_count counter")
            for endpoint, count in self._request_duration_count.items():
                lines.append(
                    f'tracker_request_duration_seconds_count{{endpoint="{endpoint}"}} {count}'
                )

            return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# 异步 Tracker 核心
# ---------------------------------------------------------------------------
class Tracker:
    def __init__(self) -> None:
        self.data_file: str = DATA_FILE
        self.lock: asyncio.Lock = asyncio.Lock()
        self.torrents: dict[bytes, dict[bytes, Peer]] = {}
        self.torrent_info: dict[bytes, TorrentInfo] = {}
        self.completed_count: dict[bytes, int] = {}
        self._stats_cache: dict[bytes, _StatsCacheEntry] = {}
        self._stop_event = asyncio.Event()

    async def initialize(self) -> None:
        await self._load_state_async()

    async def _expire_peers(
        self, info_hash: bytes, now: float | None = None
    ) -> dict[bytes, Peer]:
        peers = self.torrents.get(info_hash)
        if not peers:
            self._stats_cache.pop(info_hash, None)
            return {}
        ts = now if now is not None else time.time()
        cutoff = ts - PEER_TIMEOUT
        active = {pid: p for pid, p in peers.items() if p.last_seen >= cutoff}
        if active:
            self.torrents[info_hash] = active
            return active
        self.torrents.pop(info_hash, None)
        self._stats_cache.pop(info_hash, None)
        return {}

    async def _cleanup_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=CLEANUP_INTERVAL)
                break
            except asyncio.TimeoutError:
                pass
            await self._cleanup_once()

    async def _cleanup_once(self) -> None:
        now = time.time()
        async with self.lock:
            for info_hash in list(self.torrents.keys()):
                await self._expire_peers(info_hash, now)
            # 清理仅出现在 scrape 中但从未有 peer 的 stats_cache 条目
            stale = [
                ih
                for ih, entry in self._stats_cache.items()
                if now - entry.timestamp > PEER_TIMEOUT * 2
            ]
            for ih in stale:
                self._stats_cache.pop(ih, None)
            # 清理 orphaned torrent_info 和 completed_count（无活跃 peer 且无有意义元数据）
            orphaned = [
                ih
                for ih in list(self.torrent_info.keys())
                if ih not in self.torrents
                and self.torrent_info[ih].name == ""
                and self.torrent_info[ih].size == 0
                and self.completed_count.get(ih, 0) == 0
            ]
            for ih in orphaned:
                self.torrent_info.pop(ih, None)
                self.completed_count.pop(ih, None)
            if orphaned:
                logger.debug("清理了 %d 个 orphaned 种子元数据条目", len(orphaned))
        logger.debug("清理完成，活跃种子数：%d", len(self.torrents))

    @staticmethod
    def _build_state_entry(
        info: TorrentInfo, peers: list[Peer], completed: int
    ) -> _TorrentStateDict:
        seeders = 0
        total_up = total_down = 0
        for p in peers:
            if p.left == 0:
                seeders += 1
            total_up += p.uploaded
            total_down += p.downloaded
        leechers = len(peers) - seeders
        return {
            "info": info.to_dict(),
            "peers_info": [p.to_dict() for p in peers],
            "stats": {
                "complete": seeders,
                "incomplete": leechers,
                "uploaded": total_up,
                "downloaded": total_down,
                "peers": len(peers),
                "completed": completed,
            },
        }

    async def save_state(self) -> None:
        snapshot: dict[str, _TorrentStateDict] = {}
        async with self.lock:
            now = time.time()
            cutoff = now - PEER_TIMEOUT
            for info_hash, info in self.torrent_info.items():
                peers = [
                    p
                    for p in self.torrents.get(info_hash, {}).values()
                    if p.last_seen >= cutoff
                ]
                snapshot[bytes_to_hex(info_hash)] = self._build_state_entry(
                    info, peers, self.completed_count.get(info_hash, 0)
                )
            for info_hash, peers_dict in self.torrents.items():
                if info_hash in self.torrent_info:
                    continue
                peers = [p for p in peers_dict.values() if p.last_seen >= cutoff]
                if peers:
                    snapshot[bytes_to_hex(info_hash)] = self._build_state_entry(
                        TorrentInfo(info_hash=info_hash),
                        peers,
                        self.completed_count.get(info_hash, 0),
                    )
            # 保留有 completed_count 但无活跃 peer 且不在 torrent_info 中的条目
            for info_hash, count in self.completed_count.items():
                hex_key = bytes_to_hex(info_hash)
                if hex_key in snapshot:
                    continue
                if count > 0:
                    snapshot[hex_key] = self._build_state_entry(
                        TorrentInfo(info_hash=info_hash),
                        [],
                        count,
                    )

        payload = _json_dumps({"torrents": snapshot}, indent=2)
        await asyncio.to_thread(self._atomic_write, self.data_file, payload)
        logger.info("状态已保存至 %s（种子数：%d）", self.data_file, len(snapshot))

    @staticmethod
    def _atomic_write(filepath: str, data: bytes) -> None:
        """原子写入：先写临时文件，再 os.replace。"""
        dirname = os.path.dirname(filepath) or "."
        fd, tmp_path = tempfile.mkstemp(
            suffix=".tmp", prefix="tracker_state_", dir=dirname
        )
        closed = False
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(fd)
            # fd 已被 fdopen 上下文管理器关闭
            closed = True
            os.replace(tmp_path, filepath)
        except Exception:
            if not closed:
                try:
                    os.close(fd)
                except OSError:
                    pass
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    @staticmethod
    def _read_file_sync(filepath: str) -> bytes:
        with open(filepath, "rb") as f:
            return f.read()

    async def _load_state_async(self) -> None:
        if not os.path.exists(self.data_file):
            return
        try:
            raw = await asyncio.to_thread(self._read_file_sync, self.data_file)
            if not raw:
                return
            state = _json_loads(raw)
        except Exception as exc:
            logger.error("无法解析状态文件 JSON：%s —— 保留现有状态", exc)
            try:
                backup = f"{self.data_file}.corrupt.{int(time.time())}"
                os.replace(self.data_file, backup)
                logger.warning("已备份损坏状态文件至 %s", backup)
            except OSError:
                pass
            return

        # JSON 解析成功后才清空旧状态，逐条加载
        torrents_data = state.get("torrents", {})
        if not isinstance(torrents_data, dict):
            logger.error(
                "状态文件中 'torrents' 字段类型错误（%s），保留现有状态",
                type(torrents_data).__name__,
            )
            try:
                backup = f"{self.data_file}.corrupt.{int(time.time())}"
                os.replace(self.data_file, backup)
                logger.warning("已备份损坏状态文件至 %s", backup)
            except OSError:
                pass
            return

        self.torrent_info.clear()
        self.torrents.clear()
        self.completed_count.clear()
        self._stats_cache.clear()
        now = time.time()
        loaded = 0
        skipped = 0

        for hex_hash, tdata in torrents_data.items():
            try:
                info_hash = hex_to_bytes(hex_hash)
                self.torrent_info[info_hash] = TorrentInfo.from_dict(tdata["info"])

                unique: dict[bytes, Peer] = {}
                for pdata in tdata.get("peers_info", []):
                    last_seen = float(pdata.get("last_seen", 0))
                    if now - last_seen >= PEER_TIMEOUT:
                        continue
                    peer = Peer.from_dict(pdata)
                    existing = unique.get(peer.peer_id)
                    if existing is None or peer.last_seen > existing.last_seen:
                        unique[peer.peer_id] = peer
                if unique:
                    self.torrents[info_hash] = unique
                self.completed_count[info_hash] = max(
                    0, int(tdata.get("stats", {}).get("completed", 0))
                )
                loaded += 1
            except Exception as exc:
                logger.warning("跳过损坏的种子记录 %s: %s", hex_hash, exc)
                skipped += 1
        logger.info(
            "状态从 %s 加载完毕，成功 %d 条，跳过 %d 条，活跃种子数：%d",
            self.data_file,
            loaded,
            skipped,
            len(self.torrents),
        )

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
    ) -> tuple[dict[str, int], list[Peer]]:
        # 输入校验：防止负值/超大值污染统计
        uploaded = max(0, min(uploaded, _MAX_TRANSFER_VALUE))
        downloaded = max(0, min(downloaded, _MAX_TRANSFER_VALUE))
        left = max(0, min(left, _MAX_TRANSFER_VALUE))

        is_private = not ALLOW_PRIVATE_IP and _is_private_ip(ip)
        async with self.lock:
            peers = self.torrents.get(info_hash)
            if peers is None:
                # 限制 torrent 总数，防止内存无界增长
                # peers is None 意味着 info_hash 不在 self.torrents 中
                if len(self.torrents) >= MAX_TORRENTS:
                    logger.warning(
                        "达到最大种子数上限 %d，拒绝新 info_hash %s",
                        MAX_TORRENTS,
                        bytes_to_hex(info_hash),
                    )
                    return (
                        {"complete": 0, "incomplete": 0, "downloaded": 0},
                        [],
                    )
                peers = {}
                self.torrents[info_hash] = peers
            if info_hash not in self.torrent_info:
                self.torrent_info[info_hash] = TorrentInfo(info_hash=info_hash)
            if info_hash not in self.completed_count:
                self.completed_count[info_hash] = 0

            now = time.time()
            cutoff = now - PEER_TIMEOUT
            old_peer = peers.get(peer_id)

            if event == "stopped":
                peers.pop(peer_id, None)
                active = {pid: p for pid, p in peers.items() if p.last_seen >= cutoff}
                self.torrents[info_hash] = active
                seeders = sum(1 for p in active.values() if p.left == 0)
                leechers = len(active) - seeders
                self._stats_cache[info_hash] = _StatsCacheEntry(seeders, leechers, now)
                completed = self.completed_count.get(info_hash, 0)
                return (
                    {"complete": seeders, "incomplete": leechers, "downloaded": completed},
                    [],
                )

            if not is_private:
                if event == "completed":
                    left = 0
                    if old_peer is None or old_peer.left > 0:
                        self.completed_count[info_hash] += 1

                if peer_id in peers or len(peers) < MAX_PEERS_PER_TORRENT:
                    peers[peer_id] = Peer(
                        peer_id=peer_id,
                        ip=ip,
                        port=port,
                        last_seen=now,
                        uploaded=uploaded,
                        downloaded=downloaded,
                        left=left,
                    )
                else:
                    logger.warning(
                        "种子 %s 达到最大对等体数，拒绝新对等体",
                        bytes_to_hex(info_hash),
                    )

            seeders = leechers = 0
            candidates = []
            active = {}
            for pid, p in peers.items():
                if p.last_seen < cutoff:
                    continue
                active[pid] = p
                if p.left == 0:
                    seeders += 1
                else:
                    leechers += 1
                if p.port > 0 and pid != peer_id:
                    candidates.append(p)
            self.torrents[info_hash] = active
            self._stats_cache[info_hash] = _StatsCacheEntry(seeders, leechers, now)

            completed = self.completed_count.get(info_hash, 0)
            stats = {
                "complete": seeders,
                "incomplete": leechers,
                "downloaded": completed,
            }

        if event == "stopped" or is_private or numwant <= 0 or not candidates:
            return stats, []

        n = len(candidates)
        if numwant >= n:
            out = list(candidates)
            _sr.shuffle(out)
            return stats, out
        return stats, _sr.sample(candidates, numwant)

    async def scrape(self, info_hashes: list[bytes]) -> dict[bytes, dict[bytes, int]]:
        async with self.lock:
            now = time.time()
            cutoff = now - PEER_TIMEOUT
            result: dict[bytes, dict[bytes, int]] = {}
            for ih in info_hashes:
                cached = self._stats_cache.get(ih)
                if cached is not None and now - cached.timestamp < 10:
                    seeders, leechers = cached.seeders, cached.leechers
                else:
                    peers = self.torrents.get(ih, {})
                    seeders = leechers = 0
                    for p in peers.values():
                        if p.last_seen < cutoff:
                            continue
                        if p.left == 0:
                            seeders += 1
                        else:
                            leechers += 1
                    self._stats_cache[ih] = _StatsCacheEntry(seeders, leechers, now)
                result[ih] = {
                    b"seeders": seeders,
                    b"completed": self.completed_count.get(ih, 0),
                    b"leechers": leechers,
                }
            return result

    async def get_all_stats(self) -> dict[str, dict[str, Any]]:
        async with self.lock:
            now = time.time()
            cutoff = now - PEER_TIMEOUT
            result: dict[str, dict[str, Any]] = {}
            all_hashes = self.torrent_info.keys() | self.torrents.keys()
            for info_hash in all_hashes:
                info = self.torrent_info.get(info_hash)
                peers = self.torrents.get(info_hash, {})
                seeders = leechers = 0
                total_up = total_down = 0
                active = 0
                for p in peers.values():
                    if p.last_seen < cutoff:
                        continue
                    active += 1
                    if p.left == 0:
                        seeders += 1
                    else:
                        leechers += 1
                    total_up += p.uploaded
                    total_down += p.downloaded
                result[bytes_to_hex(info_hash)] = {
                    "name": info.name if info else "",
                    "size": info.size if info else 0,
                    "creation_date": info.creation_date if info else 0.0,
                    "complete": seeders,
                    "incomplete": leechers,
                    "downloaded": self.completed_count.get(info_hash, 0),
                    "uploaded_bytes": total_up,
                    "downloaded_bytes": total_down,
                    "peers": active,
                }
            return result


# ---------------------------------------------------------------------------
# HTTP 辅助函数
# ---------------------------------------------------------------------------
def _bencode_response(data: dict[Any, Any], status: int = 200) -> web.Response:
    try:
        payload = bencodepy.encode(data)
    except Exception:
        payload = b"d14:failure reason11:encode errore"
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
        xff = request.headers.get("X-Forwarded-For", "")
        ip = xff.split(",")[0].strip() if xff else ""
        if not ip:
            ip = request.headers.get("X-Real-IP", "")
        if ip and _is_valid_ip(ip):
            return _normalize_ip(ip)
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
    n = len(peers)
    parts4: list[bytes] = [b""] * n if n > 0 else []
    parts6: list[bytes] = [b""] * n if n > 0 else []
    i4 = i6 = 0
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
            parts6[i6] = COMPACT6_STRUCT.pack(packed, p.port)
            i6 += 1
        else:
            try:
                packed = socket.inet_pton(socket.AF_INET, ip)
            except OSError:
                logger.debug("跳过无效 IPv4 peer: %s", ip)
                continue
            parts4[i4] = COMPACT4_STRUCT.pack(packed, p.port)
            i4 += 1
    return b"".join(parts4[:i4]), b"".join(parts6[:i6])


def _check_api_key(request: web.Request) -> web.Response | None:
    if not API_KEY:
        return None
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
        self._max_entries = 200_000

    def check(self, ip: str) -> bool:
        if not self._enabled:
            return True
        now = time.monotonic()

        # LRU 淘汰：达到上限时移除最久未访问的条目，为新条目腾出空间
        while len(self._table) >= self._max_entries:
            self._table.popitem(last=False)

        entry = self._table.get(ip)
        if entry is None:
            entry = _HttpRateEntry(tokens=float(self._burst), last_update=now)
            self._table[ip] = entry
        else:
            # 命中时移到末尾，保持 LRU 顺序
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
        # OrderedDict 用于 LRU：最近被命中的连接移到末尾，超过上限时淘汰最旧的
        self.connections: OrderedDict[tuple[str, int], tuple[int, float]] = OrderedDict()
        # 独立 set 维护已分配的连接 ID，O(1) 碰撞检测，避免 O(n) 全量扫描
        self._conn_id_set: set[int] = set()
        self._udp_key = _udp_key_from_api_key()
        self._key_required = bool(self._udp_key is not None and PROTECT_ANNOUNCE)
        self._sem = asyncio.Semaphore(256)
        # 跟踪未完成的 UDP 处理任务，避免任务被 GC 回收
        self._tasks: set[asyncio.Task[None]] = set()

        # UDP 速率限制配置
        self._rate_enabled = _env_bool("UDP_RATE_LIMIT_ENABLED", True)
        self._rate_packet_per_sec = _env_int("UDP_RATE_LIMIT_PACKET_PER_SEC", 20)
        self._rate_connect_per_sec = _env_int("UDP_RATE_LIMIT_CONNECT_PER_SEC", 2)
        self._rate_burst = _env_int("UDP_RATE_LIMIT_BURST", 5)
        self._rate_max_pending = _env_int("UDP_RATE_MAX_PENDING_PER_IP", 10)
        self._rate_max_entries = _env_int("UDP_RATE_MAX_ENTRIES", 200_000)
        self._rate_table: OrderedDict[tuple[str, int], _UdpRateEntry] = OrderedDict()
        # 保护 _rate_table 中 pending 字段的读写与条目删除
        self._rate_lock = asyncio.Lock()

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
                # 被限速的包静默丢弃，不创建任务、不回复任何数据，避免反射放大
                return

        task = asyncio.create_task(self._handle_with_sem(data, addr, addr_key))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def error_received(self, exc: Exception) -> None:
        logger.error("UDP 传输错误：%s", exc)

    def connection_lost(self, exc: Exception | None) -> None:
        if exc:
            logger.warning("UDP 连接丢失：%s", exc)
        self.transport = None

    @staticmethod
    def _addr_key(addr: tuple[Any, ...]) -> tuple[str, int]:
        return (addr[0], addr[1])

    def _check_rate(self, addr_key: tuple[str, int], is_connect: bool) -> bool:
        """同步 Token Bucket 检查。必须在事件循环中调用（单线程）。"""
        now = time.monotonic()
        entry = self._rate_table.get(addr_key)
        if entry is None:
            entry = _UdpRateEntry(
                packet_tokens=float(self._rate_burst),
                connect_tokens=1.0,
                last_update=now,
            )
            self._rate_table[addr_key] = entry
            # 防止 spoofed 源 IP 把 rate table 撑爆，O(1) 淘汰最旧条目
            while len(self._rate_table) > self._rate_max_entries:
                self._rate_table.popitem(last=False)
        else:
            # 命中时移到末尾，保持 LRU 顺序
            self._rate_table.move_to_end(addr_key)

        elapsed = now - entry.last_update

        # 补充 packet token
        entry.packet_tokens = min(
            float(self._rate_burst),
            entry.packet_tokens + elapsed * self._rate_packet_per_sec,
        )
        # 补充 connect token（burst 保持较小，避免 connect 洪水）
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

    async def _cleanup_connections_loop(self) -> None:
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
                await self._metrics.set_udp_connections(len(self.connections))
            except Exception:
                logger.exception("UDP 连接清理异常")

    async def _cleanup_connections(self) -> None:
        now_wall = time.time()
        expired = [
            addr
            for addr, (_, created) in self.connections.items()
            if now_wall - created > UDP_CONNECTION_TIMEOUT
        ]
        for addr in expired:
            cid = self.connections.pop(addr, None)
            if cid is not None:
                self._conn_id_set.discard(cid[0])
        if expired:
            logger.debug("清理了 %d 个过期 UDP 连接", len(expired))

        # 清理长期无流量且无在途任务的速率限制条目，防止内存泄漏
        # 速率限制使用 monotonic 时钟，避免系统时间跳变导致误判
        now_mono = time.monotonic()
        async with self._rate_lock:
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
            async with self._rate_lock:
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
        now = time.time()
        if (now - stored[1]) > UDP_CONNECTION_TIMEOUT:
            cid = self.connections.pop(addr_key, None)
            if cid is not None:
                self._conn_id_set.discard(cid[0])
            await self._metrics.set_udp_connections(len(self.connections))
            self._send_error(trans_id, "Invalid connection ID", addr)
            return
        # 命中有效连接，更新 LRU 顺序
        self.connections.move_to_end(addr_key)

        try:
            if action == ACTION_ANNOUNCE:
                await self._handle_announce(data, trans_id, addr)
            elif action == ACTION_SCRAPE:
                await self._handle_scrape(data, trans_id, addr)
            else:
                self._send_error(trans_id, "Unknown action", addr)
        except Exception:
            logger.exception("UDP 处理异常，来源 %s:%d", addr[0], addr[1])

    async def _handle_connect(
        self, trans_id: int, addr: tuple[Any, ...], addr_key: tuple[str, int]
    ) -> None:
        # 若同一 addr_key 已有连接，先清理旧连接 ID，防止 _conn_id_set 泄漏
        old = self.connections.get(addr_key)
        if old is not None:
            self._conn_id_set.discard(old[0])

        # 0 会被视为未初始化/无效连接 ID，强制非零；O(1) 碰撞检测
        conn_id = secrets.randbits(64) or 1
        while conn_id in self._conn_id_set:
            conn_id = secrets.randbits(64) or 1
        self.connections[addr_key] = (conn_id, time.time())
        self._conn_id_set.add(conn_id)
        self.connections.move_to_end(addr_key)

        # LRU 淘汰：超出上限时移除最久未访问的连接（排除刚添加的条目）
        while len(self.connections) > MAX_UDP_CONNECTIONS:
            evicted = self.connections.popitem(last=False)
            # 防御：若 evicted 就是刚添加的 addr_key（极端配置下），不丢弃
            if evicted[0] == addr_key:
                continue
            self._conn_id_set.discard(evicted[1][0])
            logger.debug("UDP 连接表达到上限，淘汰 %s:%d", evicted[0][0], evicted[0][1])
        response = UDP_CONNECT_RESPONSE.pack(ACTION_CONNECT, trans_id, conn_id)
        self._sendto(response, addr)
        await self._metrics.set_udp_connections(len(self.connections))

    def _validate_udp_key(self, key: int) -> bool:
        if not self._key_required:
            return True
        return _constant_time_compare_int(key, self._udp_key or 0)

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

        # BEP 15: peer 列表格式由 UDP 包地址族决定。
        # 必须用原始 raw_client（未 normalize）判断，否则 IPv4-mapped IPv6
        # （::ffff:x.x.x.x）会被 normalize 为 IPv4 字符串，导致 client_is_v6
        # 误判为 False，compact 格式错误（6 字节 vs 18 字节）。
        raw_client = addr[0]
        try:
            client_is_v6 = isinstance(
                ipaddress.ip_address(raw_client), ipaddress.IPv6Address
            )
        except ValueError:
            client_is_v6 = False

        normalized_client = _normalize_ip(raw_client)

        # BEP 15: IPv4 地址字段仅在 IPv4 上下文中有效（32 位）
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
        # BEP 15: numwant 为无符号 32 位整数，但 struct 以有符号 'i' 解包。
        # 值 > 2^31-1 会被解释为负数，需转换为无符号。
        if numwant < 0:
            numwant += 0x100000000
        if numwant == 0 or numwant > MAX_NUMWANT:
            numwant = MAX_NUMWANT

        start = time.monotonic()
        stats, peers = await self.tracker.announce(
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
        await self._metrics.observe_duration("udp_announce", time.monotonic() - start)
        await self._metrics.inc_announce("udp")

        interval = INTERVAL
        leechers = min(stats["incomplete"], UINT32_MAX)
        seeders = min(stats["complete"], UINT32_MAX)

        if client_is_v6:
            same_family = [p for p in peers if ":" in _normalize_ip(p.ip)]
            peer_entry_size = 18
        else:
            same_family = [p for p in peers if ":" not in _normalize_ip(p.ip)]
            peer_entry_size = 6

        # dual-stack 场景：所有活跃 peer 与客户端地址族不一致时，
        # compact 响应无法跨地址族编码（BEP 15），记录警告后返回空列表
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
            same_family = _sr.sample(same_family, max_peers_by_mtu)
        else:
            _sr.shuffle(same_family)

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
        await self._metrics.observe_duration("udp_scrape", time.monotonic() - start)
        await self._metrics.inc_scrape("udp")

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
# aiohttp 路由
# ---------------------------------------------------------------------------
routes = web.RouteTableDef()
_start_time = time.time()

_shutdown_event = asyncio.Event()
_udp_transport: asyncio.DatagramTransport | None = None
_http_rate_limiter = _HttpRateLimiter()

# 模块级 tracker/metrics 引用（由 _main() 初始化后注入）
_tracker: Tracker | None = None
_metrics: MetricsCollector | None = None


def _get_tracker() -> Tracker:
    assert _tracker is not None, "tracker 未初始化"
    return _tracker


def _get_metrics() -> MetricsCollector:
    assert _metrics is not None, "metrics 未初始化"
    return _metrics


@routes.get("/")
async def index(request: web.Request) -> web.Response:
    return _json_response(
        {
            "status": "ok",
            "service": "BitTorrent Tracker",
            "uptime": time.time() - _start_time,
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
        await _get_metrics().inc_rate_limit()
        return _bencode_error("Rate limit exceeded")

    start = time.monotonic()
    try:
        # BEP 3: info_hash/peer_id 为 20 字节二进制数据，客户端以 %XX 百分号编码传输。
        # 必须使用 raw_query_string（保留 %XX 编码），而非 query_string（已被
        # aiohttp/yarl 做 UTF-8 解码，二进制数据会产生 surrogate 字符导致编码崩溃）。
        qs = request.rel_url.raw_query_string.encode("ascii")
        parsed_qs = _parse_query_string_raw(qs)

        auth_err = _check_announce_key(parsed_qs)
        if auth_err:
            await _get_metrics().inc_announce("http", failed=True)
            return auth_err

        info_hash = _maybe_hex_to_bytes(_get_first(parsed_qs, "info_hash"))
        peer_id = _maybe_hex_to_bytes(_get_first(parsed_qs, "peer_id"))
        port_bytes = _get_first(parsed_qs, "port")

        err = _validate_hash(info_hash, "info_hash") or _validate_hash(peer_id, "peer_id")
        if err:
            await _get_metrics().inc_announce("http", failed=True)
            return err
        if not port_bytes:
            await _get_metrics().inc_announce("http", failed=True)
            return _bencode_error("Missing port")
        try:
            port = int(port_bytes)
            if port < 1 or port > 65535:
                await _get_metrics().inc_announce("http", failed=True)
                return _bencode_error("Invalid port")
        except (ValueError, TypeError):
            await _get_metrics().inc_announce("http", failed=True)
            return _bencode_error("Invalid port")

        uploaded = _get_int(parsed_qs, "uploaded", 0)
        downloaded = _get_int(parsed_qs, "downloaded", 0)
        left = _get_int(parsed_qs, "left", 0, allow_negative=True)

        numwant_bytes = _get_first(parsed_qs, "numwant")
        if numwant_bytes is None:
            numwant = 50
        else:
            try:
                numwant = int(numwant_bytes)
            except (ValueError, TypeError):
                await _get_metrics().inc_announce("http", failed=True)
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

        # BEP 23: compact 参数兼容 "1"/"true"
        compact = _is_truthy(_get_first(parsed_qs, "compact"))

        ip_param_bytes = _get_first(parsed_qs, "ip")
        if ip_param_bytes:
            ip_param = ip_param_bytes.decode("ascii", errors="replace")
            if not _is_valid_ip(ip_param):
                ip_param = None
        else:
            ip_param = None

        if ip_param is not None and (ALLOW_PRIVATE_IP or not _is_private_ip(ip_param)):
            ip = _normalize_ip(ip_param)
        else:
            ip = client_ip

        if not _is_valid_ip(ip):
            ip = "127.0.0.1"

        stats, peers = await _get_tracker().announce(
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

        # BEP 3: 所有 key 使用 bytes，bencodepy 编码更可靠
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
            # BEP 3 非 compact: peer id/ip/port，统一 bytes key
            response_data[b"peers"] = [
                {
                    b"peer id": p.peer_id,
                    b"ip": _normalize_ip(p.ip).encode("ascii"),
                    b"port": p.port,
                }
                for p in peers
            ]

        await _get_metrics().inc_announce("http")
        return _bencode_response(response_data)
    except Exception:
        logger.exception("Announce 处理错误")
        await _get_metrics().inc_announce("http", failed=True)
        return _bencode_error("Internal tracker error")
    finally:
        await _get_metrics().observe_duration("http_announce", time.monotonic() - start)


@routes.get("/scrape")
async def scrape(request: web.Request) -> web.Response:
    client_ip = _get_client_ip(request)
    if not _http_rate_limiter.check(client_ip):
        await _get_metrics().inc_rate_limit()
        return _bencode_error("Rate limit exceeded")

    start = time.monotonic()
    try:
        # 同 announce：使用 raw_query_string 保留 %XX 百分号编码
        qs = request.rel_url.raw_query_string.encode("ascii")
        parsed_qs = _parse_query_string_raw(qs)

        auth_err = _check_scrape_key(parsed_qs)
        if auth_err:
            await _get_metrics().inc_scrape("http", failed=True)
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
            await _get_metrics().inc_scrape("http", failed=True)
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
            await _get_metrics().inc_scrape("http", failed=True)
            return _bencode_error("No valid info_hash")
        if len(unique) > MAX_SCRAPE_HASHES:
            unique = unique[:MAX_SCRAPE_HASHES]

        files = await _get_tracker().scrape(unique)
        http_files: dict[bytes, dict[bytes, int]] = {}
        for ih, s in files.items():
            http_files[ih] = {
                b"complete": s[b"seeders"],
                b"downloaded": s[b"completed"],
                b"incomplete": s[b"leechers"],
            }
        await _get_metrics().inc_scrape("http")
        return _bencode_response({b"files": http_files})
    except Exception:
        logger.exception("Scrape 处理错误")
        await _get_metrics().inc_scrape("http", failed=True)
        return _bencode_error("Internal tracker error")
    finally:
        await _get_metrics().observe_duration("http_scrape", time.monotonic() - start)


@routes.get("/metrics")
async def metrics_endpoint(request: web.Request) -> web.Response:
    return web.Response(
        body=await _get_metrics().render(),
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
        data = await request.json()
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

        async with _get_tracker().lock:
            info = _get_tracker().torrent_info.get(info_hash)
            if info is not None:
                for field, value in update_data.items():
                    setattr(info, field, value)
            else:
                _get_tracker().torrent_info[info_hash] = TorrentInfo(
                    info_hash=info_hash,
                    name=update_data.get("name", ""),
                    size=update_data.get("size", 0),
                    piece_length=update_data.get("piece_length", 0),
                    creation_date=time.time(),
                    comment=update_data.get("comment"),
                    created_by=update_data.get("created_by"),
                )
            if info_hash not in _get_tracker().torrents:
                _get_tracker().torrents[info_hash] = {}
            if info_hash not in _get_tracker().completed_count:
                _get_tracker().completed_count[info_hash] = 0
        return _json_response({"status": "ok"})
    except Exception:
        logger.exception("add_torrent_info 错误")
        return _json_error("Internal error", status=500)


@routes.get("/stats")
async def get_all_stats(request: web.Request) -> web.Response:
    auth = _check_api_key(request)
    if auth:
        return auth
    try:
        return _json_response(await _get_tracker().get_all_stats(), indent=2)
    except Exception:
        logger.exception("stats 错误")
        return _json_error("Internal error", status=500)


@routes.post("/save_state")
async def save_state(request: web.Request) -> web.Response:
    auth = _check_api_key(request)
    if auth:
        return auth
    await _get_tracker().save_state()
    return _json_response({"status": "ok", "message": "Tracker 状态已保存"})


@routes.get("/health")
async def health(request: web.Request) -> web.Response:
    return _json_response(
        {
            "status": "ok",
            "uptime": time.time() - _start_time,
            "torrents": len(_get_tracker().torrents),
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
def create_app() -> web.Application:
    app = web.Application(client_max_size=MAX_HTTP_BODY_SIZE)
    app.add_routes(routes)
    # 统一路由：/scrape 与 /scrape/<hash>
    app.router.add_get("/scrape/{extra:.*}", scrape)
    return app


# ---------------------------------------------------------------------------
# 信号与自动保存
# ---------------------------------------------------------------------------
async def _auto_save_loop() -> None:
    while not _shutdown_event.is_set():
        try:
            await asyncio.wait_for(_shutdown_event.wait(), timeout=AUTO_SAVE_INTERVAL)
            break
        except asyncio.TimeoutError:
            pass
        try:
            await _get_tracker().save_state()
        except Exception:
            logger.exception("自动保存失败")


async def _metrics_refresh_loop() -> None:
    """定期刷新 gauge 类指标（活跃种子数/peer 数）。
    UDP 连接数由 _handle_connect 和 _cleanup_connections_loop 增量更新。"""
    while not _shutdown_event.is_set():
        try:
            await asyncio.wait_for(_shutdown_event.wait(), timeout=15)
            break
        except asyncio.TimeoutError:
            pass
        try:
            now = time.time()
            cutoff = now - PEER_TIMEOUT
            # 锁内只取快照，避免 O(peers) 遍历阻塞 announce
            trk = _get_tracker()
            async with trk.lock:
                torrents = len(trk.torrents)
                peer_snapshots: list[dict[bytes, Peer]] = list(trk.torrents.values())
            peers = sum(
                1
                for pdict in peer_snapshots
                for p in pdict.values()
                if p.last_seen >= cutoff
            )
            await _get_metrics().set_torrents(torrents)
            await _get_metrics().set_peers(peers)
        except Exception:
            logger.exception("指标刷新失败")


# ---------------------------------------------------------------------------
# UDP 服务器启动
# ---------------------------------------------------------------------------
async def _setup_udp_server(host: str, port: int) -> _AsyncUDPTracker:
    loop = asyncio.get_running_loop()
    sock = _create_udp_socket(host, port)
    protocol = _AsyncUDPTracker(host, port, _get_tracker(), _shutdown_event, _get_metrics())

    transport, _ = await loop.create_datagram_endpoint(
        lambda: protocol,
        sock=sock,
    )
    global _udp_transport
    _udp_transport = transport

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
    global _tracker, _metrics
    _tracker = Tracker()
    _metrics = MetricsCollector()

    await _tracker.initialize()
    udp_protocol = await _setup_udp_server(IP, UDP_PORT)

    app = create_app()

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, IP, PORT)
    await site.start()

    logger.info("Tracker 服务端运行于 %s:%d (TCP+UDP，统一 asyncio 事件循环)", IP, PORT)
    if API_KEY:
        logger.info("管理端点已启用 API 密钥认证")
        if PROTECT_ANNOUNCE:
            logger.info("Announce 端点已启用 API Key 保护（私有模式）")
        if PROTECT_SCRAPE:
            logger.info("Scrape 端点已启用 API Key 保护（私有模式）")
    else:
        logger.warning("API 密钥未设置，管理端点不受保护！")

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _shutdown_event.set)
        except NotImplementedError:
            # Windows 不支持 add_signal_handler，fallback 到传统 signal.signal
            signal.signal(sig, lambda s, f: _shutdown_event.set())

    async with asyncio.TaskGroup() as tg:
        tg.create_task(udp_protocol._cleanup_connections_loop())
        tg.create_task(_tracker._cleanup_loop())
        tg.create_task(_auto_save_loop())
        tg.create_task(_metrics_refresh_loop())
        await _shutdown_event.wait()

    # 通知所有后台任务停止
    await _tracker.stop()

    # shutdown 前执行最后一次清理和指标更新
    try:
        await _tracker._cleanup_once()
        await udp_protocol._cleanup_connections()
        await _metrics.set_udp_connections(len(udp_protocol.connections))
    except Exception:
        logger.exception("shutdown 清理异常")

    await runner.cleanup()
    if _udp_transport is not None:
        _udp_transport.close()
    await _tracker.save_state()
    logger.info("Tracker 已停止。")


if __name__ == "__main__":
    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        pass
    finally:
        logger.info("进程退出。")
