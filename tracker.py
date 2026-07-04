#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

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
import struct
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, asdict, fields
from typing import Any

try:
    import bencodepy  # type: ignore
    import orjson  # type: ignore
    from flask import Flask, Response, request  # type: ignore
    from werkzeug.serving import BaseWSGIServer, make_server  # type: ignore
except ImportError as exc:  # pragma: no cover
    sys.stderr.write(
        f"缺少依赖：{exc}. 请执行: pip install bencodepy orjson flask werkzeug\n"
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


IP: str = os.environ.get("TRACKER_IP", "0.0.0.0")
PORT: int = _env_int("TRACKER_PORT", 6969)
UDP_PORT: int = _env_int("TRACKER_UDP_PORT", PORT)

# TRACKER_INTERVAL 控制普通重 announce 间隔；未设置时与 MIN_INTERVAL 保持一致（向后兼容）
MIN_INTERVAL: int = _env_int("TRACKER_MIN_INTERVAL", _env_int("MIN_INTERVAL", 900))
INTERVAL: int = _env_int("TRACKER_INTERVAL", MIN_INTERVAL)
PEER_TIMEOUT: int = _env_int("PEER_TIMEOUT", 1800)

DATA_FILE: str = os.environ.get("DATA_FILE", "tracker_state.json")
AUTO_SAVE_INTERVAL: int = _env_int("AUTO_SAVE_INTERVAL", 300)
CLEANUP_INTERVAL: int = _env_int("CLEANUP_INTERVAL", 120)

MAX_PEERS_PER_TORRENT: int = _env_int("MAX_PEERS_PER_TORRENT", 1000)
MAX_NUMWANT: int = _env_int("MAX_NUMWANT", 200)
MAX_SCRAPE_HASHES: int = 74

API_KEY: str = os.environ.get("TRACKER_API_KEY", "")
PROTECT_ANNOUNCE: bool = _env_bool("TRACKER_PROTECT_ANNOUNCE", False)
PROTECT_SCRAPE: bool = _env_bool("TRACKER_PROTECT_SCRAPE", False)
ALLOW_PRIVATE_IP: bool = _env_bool("TRACKER_ALLOW_PRIVATE_IP", True)
BEHIND_PROXY: bool = _env_bool("TRACKER_BEHIND_PROXY", False)

UDP_CONNECTION_TIMEOUT: int = _env_int("UDP_CONNECTION_TIMEOUT", 120)
UDP_CONN_CLEANUP_INTERVAL: int = _env_int("UDP_CONN_CLEANUP_INTERVAL", 30)

# UDP 响应推荐 MTU：避免 IP 分片（1500 - IP头20 - UDP头8 = 1472）
UDP_MTU: int = 1400
# announce 响应头大小：action(4) + trans_id(4) + interval(4) + leechers(4) + seeders(4) = 20
UDP_ANNOUNCE_HDR_SIZE: int = 20

# 预编译 struct（BEP 15 协议格式）
COMPACT4_STRUCT = struct.Struct("!4sH")          # IPv4 (4) + port (2) = 6 字节
COMPACT6_STRUCT = struct.Struct("!16sH")         # IPv6 (16) + port (2) = 18 字节
UDP_CONNECT_RESPONSE = struct.Struct("!IIQ")      # action, trans_id, conn_id
UDP_ANNOUNCE_HEADER = struct.Struct("!IIIII")     # action, trans_id, interval, leechers, seeders
UDP_ERROR_HEADER = struct.Struct("!II")           # action, trans_id
UDP_SCRAPE_HEADER = struct.Struct("!II")          # action, trans_id
UDP_SCRAPE_STATS = struct.Struct("!III")          # seeders, completed, leechers
# BEP 15 announce 请求（从偏移 16 起）：info_hash(20) + peer_id(20) + downloaded(8) +
# left(8) + uploaded(8) + event(4, u32) + ip(4, u32) + key(4, u32) + numwant(4, i32) + port(2, u16)
UDP_ANNOUNCE_REQUEST = struct.Struct("!20s20sQQQIIIiH")

UDP_PROTOCOL_ID: int = 0x41727101980
ACTION_CONNECT: int = 0
ACTION_ANNOUNCE: int = 1
ACTION_SCRAPE: int = 2
ACTION_ERROR: int = 3

UINT32_MAX: int = 0xFFFFFFFF

VALID_EVENTS: frozenset[str] = frozenset({"started", "completed", "stopped"})

# BEP 15 UDP 事件映射
UDP_EVENT_MAP: dict[int, str | None] = {0: None, 1: "completed", 2: "started", 3: "stopped"}


# ---------------------------------------------------------------------------
# Python 版本兼容性
# ---------------------------------------------------------------------------
_PY_310_PLUS: bool = sys.version_info >= (3, 10)


def _dataclass_kwargs(**kwargs: Any) -> dict[str, Any]:
    """根据 Python 版本返回安全的 dataclass 参数。"""
    if not _PY_310_PLUS:
        kwargs.pop("slots", None)
    return kwargs


# ---------------------------------------------------------------------------
# 日志
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("tracker")


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------
_HEX_RE = re.compile(rb"^[0-9a-fA-F]+$")


def bytes_to_hex(b: bytes) -> str:
    return b.hex()


def hex_to_bytes(s: str | bytes) -> bytes:
    if isinstance(s, bytes):
        s = s.decode("ascii", errors="replace")
    if len(s) % 2:
        raise ValueError("hex string length must be even")
    return bytes.fromhex(s)


def constant_time_compare(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def _percent_decode_bytes(b: bytes) -> bytes:
    """就地 percent-decoding，避免分配大字符串。"""
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
            try:
                result[j] = int(b[i + 1 : i + 3], 16)
                i += 3
                j += 1
                continue
            except ValueError:
                pass
            result[j] = c
            i += 1
            j += 1
        else:
            result[j] = c
            i += 1
            j += 1
    return bytes(result[:j])


def _parse_query_string_raw(qs: bytes) -> dict[bytes, list[bytes]]:
    """极简 query string 解析，保留重复 key。"""
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
        result.setdefault(key, []).append(val)
    return result


def _get_first(parsed_qs: dict[bytes, list[bytes]], key: str) -> bytes | None:
    vals = parsed_qs.get(key.encode("ascii"))
    return vals[0] if vals else None


def _get_all(parsed_qs: dict[bytes, list[bytes]], key: str) -> list[bytes]:
    return parsed_qs.get(key.encode("ascii"), [])


def _get_int(parsed_qs: dict[bytes, list[bytes]], key: str, default: int = 0) -> int:
    """解析非负整数字段（uploaded/downloaded 等），负数钳位为 0。"""
    val = _get_first(parsed_qs, key)
    if val is None:
        return default
    try:
        return max(0, int(val))
    except (ValueError, TypeError):
        return default


def _get_int_left(parsed_qs: dict[bytes, list[bytes]], key: str, default: int = 0) -> int:
    """解析 left 字段。负数表示异常值，视为极大值（leecher），而不是 0（seeder）。"""
    val = _get_first(parsed_qs, key)
    if val is None:
        return default
    try:
        v = int(val)
        return v if v >= 0 else (1 << 63)
    except (ValueError, TypeError):
        return default


@functools.lru_cache(maxsize=32768)
def _is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_multicast
        or addr.is_unspecified
    )


@functools.lru_cache(maxsize=32768)
def _normalize_ip(ip_str: str) -> str:
    """将 IPv4-mapped IPv6 / 6to4 / Teredo 转换为 IPv4 字符串，同时去除 zone ID。"""
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
        # 去除 zone ID（如 %eth0）
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
    """将 API_KEY 转换为 UDP announce 中的 4 字节 key。

    优先级：
    1. 整数形式的 key
    2. 8 字符 hex 形式
    3. 任意字符串 -> 取 SHA-256 前 4 字节（业界惯例）
    """
    if not API_KEY:
        return None
    try:
        return int(API_KEY)
    except ValueError:
        pass
    if len(API_KEY) == 8:
        try:
            return int(API_KEY, 16)
        except ValueError:
            pass
    digest = hashlib.sha256(API_KEY.encode("utf-8")).digest()
    return int.from_bytes(digest[:4], "big", signed=False)


# ---------------------------------------------------------------------------
# 数据模型
# ---------------------------------------------------------------------------
@dataclass(**_dataclass_kwargs(slots=True, frozen=True))
class Peer:
    peer_id: bytes
    ip: str
    port: int
    last_seen: float
    uploaded: int = 0
    downloaded: int = 0
    left: int = 0

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["peer_id"] = bytes_to_hex(self.peer_id)
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Peer:
        return cls(
            peer_id=hex_to_bytes(data.get("peer_id", "")),
            ip=data.get("ip", "0.0.0.0"),
            port=int(data.get("port", 0)),
            last_seen=float(data.get("last_seen", 0.0)),
            uploaded=int(data.get("uploaded", 0)),
            downloaded=int(data.get("downloaded", 0)),
            left=int(data.get("left", 0)),
        )


@dataclass(**_dataclass_kwargs(slots=True))
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
    def from_dict(cls, data: dict[str, Any]) -> TorrentInfo:
        filtered = {k: v for k, v in data.items() if k in _TORRENT_INFO_FIELDS}
        filtered["info_hash"] = hex_to_bytes(data.get("info_hash", ""))
        return cls(**filtered)


_TORRENT_INFO_FIELDS: frozenset[str] = frozenset(f.name for f in fields(TorrentInfo))


# ---------------------------------------------------------------------------
# 核心 Tracker 逻辑
# ---------------------------------------------------------------------------
class Tracker:
    """线程安全的内存型 Tracker。

    - torrents:       info_hash -> { peer_id -> Peer }
    - torrent_info:   info_hash -> TorrentInfo
    - completed_count: info_hash -> int（downloads 总数，BEP 3 语义）
    - _stats_cache:   info_hash -> (seeders, leechers, last_update) 统计缓存
    """

    def __init__(self) -> None:
        self.data_file: str = DATA_FILE
        self.lock: threading.RLock = threading.RLock()
        self.torrents: dict[bytes, dict[bytes, Peer]] = {}
        self.torrent_info: dict[bytes, TorrentInfo] = {}
        self.completed_count: dict[bytes, int] = {}
        self._stats_cache: dict[bytes, tuple[int, int, float]] = {}
        self.load_state()

        self._stop_event = threading.Event()
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop, daemon=True, name="cleanup"
        )
        self._cleanup_thread.start()

    # ---- 过期 / 清理 ----
    def _expire_peers(
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
        del self.torrents[info_hash]
        self._stats_cache.pop(info_hash, None)
        return {}

    def _cleanup_loop(self) -> None:
        while not self._stop_event.is_set():
            self._stop_event.wait(CLEANUP_INTERVAL)
            if self._stop_event.is_set():
                break
            self.cleanup_once()

    def cleanup_once(self) -> None:
        now = time.time()
        with self.lock:
            for info_hash in list(self.torrents.keys()):
                self._expire_peers(info_hash, now)
        logger.debug("清理完成，活跃种子数：%d", len(self.torrents))

    # ---- 状态持久化 ----
    def _build_state_entry(
        self, info: TorrentInfo, peers: list[Peer], completed: int
    ) -> dict[str, Any]:
        seeders = leechers = 0
        total_up = total_down = 0
        for p in peers:
            if p.left == 0:
                seeders += 1
            else:
                leechers += 1
            total_up += p.uploaded
            total_down += p.downloaded
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

    def save_state(self) -> None:
        snapshot: dict[str, Any] = {}
        with self.lock:
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

        tmp_path: str | None = None
        try:
            dirname = os.path.dirname(self.data_file) or "."
            fd, tmp_path = tempfile.mkstemp(
                suffix=".tmp", prefix="tracker_state_", dir=dirname
            )
            with os.fdopen(fd, "wb") as f:
                f.write(_json_dumps({"torrents": snapshot}, indent=2))
            os.replace(tmp_path, self.data_file)
            logger.info("状态已保存至 %s（种子数：%d）", self.data_file, len(snapshot))
        except Exception as exc:
            logger.error("保存状态失败：%s", exc)
            if tmp_path is not None:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

    def load_state(self) -> None:
        if not os.path.exists(self.data_file):
            return
        try:
            with open(self.data_file, "rb") as f:
                raw = f.read()
            if not raw:
                return
            state = _json_loads(raw)

            self.torrent_info.clear()
            self.torrents.clear()
            self.completed_count.clear()
            self._stats_cache.clear()
            now = time.time()

            for hex_hash, tdata in state.get("torrents", {}).items():
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
                    self.completed_count[info_hash] = int(
                        tdata.get("stats", {}).get("completed", 0)
                    )
                except Exception as exc:
                    logger.warning("跳过损坏的种子记录 %s: %s", hex_hash, exc)
            logger.info(
                "状态从 %s 加载完毕，活跃种子数：%d",
                self.data_file, len(self.torrents),
            )
        except Exception as exc:
            logger.error("无法加载状态：%s —— 将从头开始", exc)
            self.torrents = {}
            self.torrent_info = {}
            self.completed_count = {}
            self._stats_cache = {}

    def stop(self) -> None:
        self._stop_event.set()

    # ---- 核心 API ----
    def announce(
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
        """处理一次 announce，返回 (stats, peers)。"""
        is_private = not ALLOW_PRIVATE_IP and _is_private_ip(ip)
        with self.lock:
            peers = self.torrents.get(info_hash)
            if peers is None:
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
            elif not is_private:
                # BEP 3：completed 事件表示下载完成，left 必须视为 0
                if event == "completed":
                    left = 0
                    if old_peer is None or old_peer.left > 0:
                        self.completed_count[info_hash] += 1

                # 已存在的 peer 始终允许更新；新 peer 仅在未达上限时加入
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

            # 单次遍历：清理过期 + 统计 + 采样
            seeders = leechers = 0
            candidates: list[Peer] = []
            expired: list[bytes] = []
            for pid, p in peers.items():
                if p.last_seen < cutoff:
                    expired.append(pid)
                    continue
                if p.left == 0:
                    seeders += 1
                else:
                    leechers += 1
                if p.port > 0 and pid != peer_id:
                    candidates.append(p)
            for pid in expired:
                del peers[pid]

            self._stats_cache[info_hash] = (seeders, leechers, now)

            completed = self.completed_count.get(info_hash, 0)
            stats = {
                "complete": seeders,
                "incomplete": leechers,
                "downloaded": completed,
            }

        # 锁外进行随机采样，避免阻塞并发请求
        if event == "stopped" or is_private or numwant <= 0 or not candidates:
            return stats, []

        n = len(candidates)
        if numwant >= n:
            out = list(candidates)
            random.shuffle(out)
            return stats, out
        return stats, random.sample(candidates, numwant)

    def scrape(self, info_hashes: list[bytes]) -> dict[bytes, dict[bytes, int]]:
        with self.lock:
            now = time.time()
            cutoff = now - PEER_TIMEOUT
            result: dict[bytes, dict[bytes, int]] = {}
            for ih in info_hashes:
                cached = self._stats_cache.get(ih)
                if cached is not None and now - cached[2] < 10:
                    seeders, leechers, _ = cached
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
                    self._stats_cache[ih] = (seeders, leechers, now)
                result[ih] = {
                    b"seeders": seeders,
                    b"completed": self.completed_count.get(ih, 0),
                    b"leechers": leechers,
                }
            return result

    def get_all_stats(self) -> dict[str, dict[str, Any]]:
        with self.lock:
            now = time.time()
            cutoff = now - PEER_TIMEOUT
            result: dict[str, dict[str, Any]] = {}
            all_hashes = set(self.torrent_info.keys()) | set(self.torrents.keys())
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
# Flask 辅助函数
# ---------------------------------------------------------------------------
def _bencode_error(message: str, status: int = 200) -> Response:
    try:
        payload = bencodepy.encode({b"failure reason": message.encode("utf-8")})
    except Exception:
        msg = message.encode("utf-8")
        payload = b"d14:failure reason" + str(len(msg)).encode() + b":" + msg + b"e"
    return Response(payload, status=status, mimetype="text/plain")


def _get_client_ip_from_request() -> str:
    """从 HTTP 请求中获取对等体 IP。"""
    if BEHIND_PROXY:
        xff = request.headers.get("X-Forwarded-For", "")
        ip = xff.split(",")[0].strip() if xff else ""
        if not ip:
            ip = request.headers.get("X-Real-IP", "")
        if ip and _is_valid_ip(ip):
            return _normalize_ip(ip)
    raw = request.remote_addr or "127.0.0.1"
    return _normalize_ip(raw)


def _validate_hash(h: bytes | None, name: str) -> Response | None:
    if h is None:
        return _bencode_error(f"Missing {name}", 400)
    if len(h) != 20:
        return _bencode_error(
            f"Invalid {name} length ({len(h)} bytes, expected 20). "
            f"Pass raw 20-byte binary or 40-char hex string.",
            400,
        )
    return None


def _encode_compact_peers(peers: list[Peer]) -> tuple[bytes, bytes]:
    """编码 compact peer 列表。

    返回 (ipv4_blob, ipv6_blob)。BEP 7 规定：peers 始终为 IPv4 compact，
    peers6 为 IPv6 compact（如果存在）。
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


def _json_response(data: Any, status: int = 200, indent: int | None = None) -> Response:
    body = _json_dumps(data, indent=indent) if indent is not None else _json_dumps(data)
    return Response(body, status=status, mimetype="application/json")


def _check_api_key_header() -> Response | None:
    if not API_KEY:
        return None
    provided = request.headers.get("X-API-Key", "")
    if not constant_time_compare(provided, API_KEY):
        return _json_response({"error": "Unauthorized"}, status=401)
    return None


def _check_announce_key(parsed_qs: dict[bytes, list[bytes]]) -> Response | None:
    if not API_KEY or not PROTECT_ANNOUNCE:
        return None
    key_bytes = _get_first(parsed_qs, "key")
    if key_bytes is None:
        return _bencode_error("Missing key (private tracker)", 403)
    if not constant_time_compare(key_bytes.decode("ascii", errors="replace"), API_KEY):
        return _bencode_error("Invalid key (private tracker)", 403)
    return None


def _check_scrape_key(parsed_qs: dict[bytes, list[bytes]]) -> Response | None:
    if not API_KEY or not PROTECT_SCRAPE:
        return None
    key_bytes = _get_first(parsed_qs, "key")
    if key_bytes is None:
        return _bencode_error("Missing key (private tracker)", 403)
    if not constant_time_compare(key_bytes.decode("ascii", errors="replace"), API_KEY):
        return _bencode_error("Invalid key (private tracker)", 403)
    return None


# ---------------------------------------------------------------------------
# 异步 UDP Tracker 服务端
# ---------------------------------------------------------------------------
class _AsyncUDPTracker:
    """基于 asyncio 的 UDP Tracker（BEP 15）。

    直接在网络事件循环中处理数据包，不再通过 ThreadPoolExecutor 调用 Tracker，
    降低线程切换开销。Tracker 内部的 RLock 保证与 HTTP 线程安全共享状态。
    """

    def __init__(self, host: str, port: int, tracker: Tracker) -> None:
        self.host = host
        self.port = port
        self.tracker = tracker
        self.transport: asyncio.DatagramTransport | None = None
        # 连接 ID 字典，所有访问都在 asyncio 事件循环线程，无需锁
        self.connections: dict[tuple[str, int], tuple[int, float]] = {}
        self._udp_key = _udp_key_from_api_key()
        self._key_required = bool(
            self._udp_key is not None and PROTECT_ANNOUNCE
        )
        # 限制并发处理的 UDP 请求数，防止突发流量导致内存爆炸
        self._sem = asyncio.Semaphore(256)

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[Any, ...]) -> None:
        """异步回调：收到 UDP 数据包时由事件循环调用。"""
        asyncio.create_task(self._handle_with_sem(data, addr))

    def error_received(self, exc: Exception) -> None:
        logger.error("UDP 传输错误：%s", exc)

    def connection_lost(self, exc: Exception | None) -> None:
        if exc:
            logger.warning("UDP 连接丢失：%s", exc)
        self.transport = None

    @staticmethod
    def _addr_key(addr: tuple[Any, ...]) -> tuple[str, int]:
        """将任意长度的地址元组规范化为 (host, port) 二元组。

        IPv6 的 datagram_received 返回 4 元组 (host, port, flowinfo, scope_id)，
        IPv4 返回 2 元组 (host, port)。统一用前两项作为连接键避免 flowinfo/scope_id
        导致同一客户端被视为不同连接。
        """
        return (addr[0], addr[1])

    # ---- 连接清理（后台 asyncio 任务） ----
    async def _cleanup_connections_loop(self) -> None:
        """定期清理过期连接 ID。"""
        while True:
            await asyncio.sleep(UDP_CONN_CLEANUP_INTERVAL)
            self._cleanup_connections(time.time())

    def _cleanup_connections(self, now: float) -> None:
        expired = [
            addr
            for addr, (_, created) in self.connections.items()
            if now - created > UDP_CONNECTION_TIMEOUT
        ]
        for addr in expired:
            del self.connections[addr]
        if expired:
            logger.debug("清理了 %d 个过期 UDP 连接", len(expired))

    async def _handle_with_sem(self, data: bytes, addr: tuple[Any, ...]) -> None:
        """带并发限制的请求处理包装。"""
        async with self._sem:
            await self._handle(data, addr)

    # ---- 请求分发 ----
    async def _handle(self, data: bytes, addr: tuple[Any, ...]) -> None:
        if len(data) < 16:
            return
        try:
            action, trans_id = struct.unpack("!II", data[8:16])
            first_qword = struct.unpack("!Q", data[0:8])[0]
        except struct.error:
            return

        addr_key = self._addr_key(addr)

        # Connect 请求
        if first_qword == UDP_PROTOCOL_ID:
            if action == ACTION_CONNECT:
                self._handle_connect(trans_id, addr, addr_key)
            return

        # 其他请求需要有效的 conn_id（BEP 15：自创建起 2 分钟内有效）
        conn_id = first_qword
        stored = self.connections.get(addr_key)
        now = time.time()
        if (
            stored is None
            or stored[0] != conn_id
            or (now - stored[1]) > UDP_CONNECTION_TIMEOUT
        ):
            self._send_error(trans_id, "Invalid connection ID", addr)
            return
        # 不刷新时间戳，保证 connection_id 不会变成永久有效

        try:
            if action == ACTION_ANNOUNCE:
                await self._handle_announce(data, trans_id, addr)
            elif action == ACTION_SCRAPE:
                await self._handle_scrape(data, trans_id, addr)
            else:
                self._send_error(trans_id, "Unknown action", addr)
        except Exception:
            logger.exception("UDP 处理异常，来源 %s:%d", addr[0], addr[1])

    def _handle_connect(self, trans_id: int, addr: tuple[Any, ...], addr_key: tuple[str, int]) -> None:
        # BEP 15：connection_id 自创建起 2 分钟内有效，刷新会扩大攻击窗口，因此只记录创建时间
        conn_id = secrets.randbits(64)
        self.connections[addr_key] = (conn_id, time.time())
        response = UDP_CONNECT_RESPONSE.pack(ACTION_CONNECT, trans_id, conn_id)
        self._sendto(response, addr)

    def _validate_udp_key(self, key: int) -> bool:
        if not self._key_required:
            return True
        return key == (self._udp_key or 0)

    # ---- Announce ----
    async def _handle_announce(
        self, data: bytes, trans_id: int, addr: tuple[Any, ...]
    ) -> None:
        if len(data) < 98:
            self._send_error(trans_id, "Malformed announce request (too short)", addr)
            return
        try:
            (
                info_hash, peer_id, downloaded, left, uploaded,
                event, ip_raw, key, numwant, port,
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

        # 客户端地址处理：
        # 1. 规范化对端地址（IPv4-mapped IPv6 -> IPv4）
        # 2. 按规范化后的地址判断 family
        # 3. BEP 15: IPv4 client 可通过 ip_raw 声明自己的 IP；IPv6 client 的 ip_raw 必须为 0
        raw_client = addr[0]
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
        # BEP 15: numwant=-1 表示"尽可能多的 peer"，应映射到 MAX_NUMWANT
        if numwant == -1:
            numwant = MAX_NUMWANT
        elif numwant < 0:
            numwant = 0
        numwant = min(numwant, MAX_NUMWANT)

        # 直接调用同步 Tracker（操作极快，避免线程池切换）
        stats, peers = self.tracker.announce(
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

        interval = INTERVAL
        leechers = min(stats["incomplete"], UINT32_MAX)
        seeders = min(stats["complete"], UINT32_MAX)

        # 计算 UDP 响应中 peer 数据的最大字节数（避免 IP 分片）
        peer_entry_size = 18 if client_is_v6 else 6
        max_peer_bytes = max(0, UDP_MTU - UDP_ANNOUNCE_HDR_SIZE)
        max_peers_by_mtu = max_peer_bytes // peer_entry_size

        # 先随机打乱/采样，再按 MTU 截断，确保每个客户端得到随机子集（BEP 15 建议）
        if len(peers) > max_peers_by_mtu:
            peers = random.sample(peers, max_peers_by_mtu)
        else:
            random.shuffle(peers)

        # 根据客户端地址族编码 peer 列表（BEP 15 附录：格式由 UDP 包地址族决定）
        if client_is_v6:
            parts: list[bytes] = []
            for p in peers:
                ip = _normalize_ip(p.ip)
                if ":" not in ip:
                    continue
                try:
                    packed = socket.inet_pton(socket.AF_INET6, ip)
                    parts.append(COMPACT6_STRUCT.pack(packed, p.port))
                except OSError:
                    continue
            peer_blob = b"".join(parts)
        else:
            parts = []
            for p in peers:
                ip = _normalize_ip(p.ip)
                if ":" in ip:
                    continue
                try:
                    packed = socket.inet_pton(socket.AF_INET, ip)
                    parts.append(COMPACT4_STRUCT.pack(packed, p.port))
                except OSError:
                    continue
            peer_blob = b"".join(parts)

        response = UDP_ANNOUNCE_HEADER.pack(
            ACTION_ANNOUNCE, trans_id, interval, leechers, seeders
        ) + peer_blob
        self._sendto(response, addr)

    # ---- Scrape ----
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
            self._sendto(
                UDP_SCRAPE_HEADER.pack(ACTION_SCRAPE, trans_id), addr
            )
            return
        if count > MAX_SCRAPE_HASHES:
            count = MAX_SCRAPE_HASHES

        hashes = [data[16 + i * 20 : 16 + (i + 1) * 20] for i in range(count)]
        files = self.tracker.scrape(hashes)

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
# Flask 应用
# ---------------------------------------------------------------------------
app = Flask(__name__)
tracker = Tracker()
shutdown_event = threading.Event()
_server_instance: BaseWSGIServer | None = None
_udp_transport: asyncio.DatagramTransport | None = None
_udp_loop: asyncio.AbstractEventLoop | None = None
_udp_stop_signal: Any = None
_udp_thread: threading.Thread | None = None
_start_time = time.time()


@app.route("/")
def index() -> Response:
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
            },
        }
    )


@app.route("/announce")
def announce() -> Response:
    try:
        qs = request.query_string
        parsed_qs = _parse_query_string_raw(qs)

        auth_err = _check_announce_key(parsed_qs)
        if auth_err:
            return auth_err

        info_hash = _maybe_hex_to_bytes(_get_first(parsed_qs, "info_hash"))
        peer_id = _maybe_hex_to_bytes(_get_first(parsed_qs, "peer_id"))
        port_bytes = _get_first(parsed_qs, "port")

        err = _validate_hash(info_hash, "info_hash") or _validate_hash(peer_id, "peer_id")
        if err:
            return err
        if not port_bytes:
            return _bencode_error("Missing port", 400)
        try:
            port = int(port_bytes)
            if port < 1 or port > 65535:
                return _bencode_error("Invalid port", 400)
        except (ValueError, TypeError):
            return _bencode_error("Invalid port", 400)

        uploaded = _get_int(parsed_qs, "uploaded", 0)
        downloaded = _get_int(parsed_qs, "downloaded", 0)
        left = _get_int_left(parsed_qs, "left", 0)

        numwant_bytes = _get_first(parsed_qs, "numwant")
        if numwant_bytes is None:
            numwant = 50
        else:
            try:
                numwant = int(numwant_bytes)
            except (ValueError, TypeError):
                return _bencode_error("Invalid numwant parameter", 400)
            if numwant == -1:
                numwant = MAX_NUMWANT
            elif numwant < 0:
                numwant = 0
            numwant = min(numwant, MAX_NUMWANT)

        event_bytes = _get_first(parsed_qs, "event")
        event = event_bytes.decode("ascii", errors="replace") if event_bytes else None
        if event is not None and event not in VALID_EVENTS:
            event = None

        compact_bytes = _get_first(parsed_qs, "compact")
        # BEP 23: compact=1 显式启用 compact 模式；默认返回非 compact 列表
        compact = compact_bytes == b"1"

        # BEP 7: 客户端可声明自己的 IP
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
            ip = _get_client_ip_from_request()

        if not _is_valid_ip(ip):
            ip = "127.0.0.1"

        stats, peers = tracker.announce(
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

        # BEP 3 响应字段
        response_data: dict[bytes, Any] = {
            b"interval": INTERVAL,
            b"min interval": MIN_INTERVAL,
            b"complete": stats["complete"],
            b"incomplete": stats["incomplete"],
            b"downloaded": stats["downloaded"],
        }

        if compact:
            # BEP 7：peers 固定为 IPv4 compact；peers6 为 IPv6 compact
            v4_blob, v6_blob = _encode_compact_peers(peers)
            response_data[b"peers"] = v4_blob
            if v6_blob:
                response_data[b"peers6"] = v6_blob
        else:
            response_data[b"peers"] = [
                {b"peer id": p.peer_id, b"ip": _normalize_ip(p.ip), b"port": p.port}
                for p in peers
            ]

        return Response(bencodepy.encode(response_data), mimetype="text/plain")
    except Exception:
        logger.exception("Announce 处理错误")
        return _bencode_error("Internal tracker error", 500)


@app.route("/scrape")
@app.route("/scrape/", defaults={"extra": ""})
@app.route("/scrape/<path:extra>")
def scrape(extra: str = "") -> Response:
    try:
        qs = request.query_string
        parsed_qs = _parse_query_string_raw(qs)

        auth_err = _check_scrape_key(parsed_qs)
        if auth_err:
            return auth_err

        info_hashes = list(_get_all(parsed_qs, "info_hash"))

        if extra:
            for chunk in extra.strip("/").split("/"):
                chunk = chunk.strip()
                if len(chunk) == 40 and _HEX_RE.match(chunk.encode("ascii")):
                    info_hashes.append(chunk.encode("ascii"))

        if not info_hashes:
            return _bencode_error("Missing info_hash", 400)

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
            return _bencode_error("No valid info_hash", 400)
        if len(unique) > MAX_SCRAPE_HASHES:
            unique = unique[:MAX_SCRAPE_HASHES]

        files = tracker.scrape(unique)
        http_files: dict[bytes, dict[bytes, int]] = {}
        for ih, s in files.items():
            http_files[ih] = {
                b"complete": s[b"seeders"],
                b"downloaded": s[b"completed"],
                b"incomplete": s[b"leechers"],
            }
        return Response(
            bencodepy.encode({b"files": http_files}), mimetype="text/plain"
        )
    except Exception:
        logger.exception("Scrape 处理错误")
        return _bencode_error("Internal tracker error", 500)


@app.route("/add_torrent_info", methods=["POST"])
def add_torrent_info() -> Response:
    auth = _check_api_key_header()
    if auth:
        return auth
    try:
        data = request.get_json(silent=True) or {}
        if "info_hash" not in data:
            return _json_response({"error": "Missing info_hash"}, status=400)
        try:
            info_hash = hex_to_bytes(str(data["info_hash"]))
            if len(info_hash) != 20:
                return _json_response(
                    {"error": "info_hash must be 20 bytes"}, status=400
                )
        except Exception:
            return _json_response({"error": "Invalid info_hash hex"}, status=400)

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
                        update_data[field] = int(val) if val is not None else 0
                    except (ValueError, TypeError):
                        return _json_response(
                            {"error": f"Invalid value for field {field}"}, status=400
                        )

        with tracker.lock:
            info = tracker.torrent_info.get(info_hash)
            if info is not None:
                for field, value in update_data.items():
                    setattr(info, field, value)
            else:
                tracker.torrent_info[info_hash] = TorrentInfo(
                    info_hash=info_hash,
                    name=update_data.get("name", ""),
                    size=update_data.get("size", 0),
                    piece_length=update_data.get("piece_length", 0),
                    creation_date=time.time(),
                    comment=update_data.get("comment"),
                    created_by=update_data.get("created_by"),
                )
            if info_hash not in tracker.torrents:
                tracker.torrents[info_hash] = {}
            if info_hash not in tracker.completed_count:
                tracker.completed_count[info_hash] = 0
        return _json_response({"status": "ok"})
    except Exception:
        logger.exception("add_torrent_info 错误")
        return _json_response({"error": "Internal error"}, status=500)


@app.route("/stats")
def get_all_stats() -> Response:
    auth = _check_api_key_header()
    if auth:
        return auth
    try:
        return _json_response(tracker.get_all_stats(), indent=2)
    except Exception:
        logger.exception("stats 错误")
        return _json_response({"error": "Internal error"}, status=500)


@app.route("/save_state", methods=["POST"])
def save_state() -> Response:
    auth = _check_api_key_header()
    if auth:
        return auth
    tracker.save_state()
    return _json_response({"status": "ok", "message": "Tracker 状态已保存"})


@app.route("/health")
def health() -> Response:
    return _json_response(
        {
            "status": "ok",
            "uptime": time.time() - _start_time,
            "torrents": len(tracker.torrents),
            "udp_port": UDP_PORT,
            "http_port": PORT,
        }
    )


@app.route("/shutdown", methods=["POST"])
def shutdown() -> Response:
    auth = _check_api_key_header()
    if auth:
        return auth
    if not shutdown_event.is_set():
        shutdown_event.set()
    if _server_instance is not None:
        threading.Thread(target=_server_instance.shutdown, daemon=True).start()
    _notify_udp_shutdown()
    return _json_response({"status": "shutting down"})


# ---------------------------------------------------------------------------
# 信号处理与自动保存
# ---------------------------------------------------------------------------
def _notify_udp_shutdown() -> None:
    """线程安全地通知 UDP 事件循环关闭。"""
    global _udp_stop_signal, _udp_loop
    sig = _udp_stop_signal
    loop = _udp_loop
    if sig is not None and loop is not None and loop.is_running():
        loop.call_soon_threadsafe(sig)


def signal_handler(signum: int, frame: object) -> None:
    logger.info("收到信号 %d，正在关闭...", signum)
    if not shutdown_event.is_set():
        shutdown_event.set()
        if _server_instance is not None:
            threading.Thread(target=_server_instance.shutdown, daemon=True).start()
        _notify_udp_shutdown()


def auto_save_loop() -> None:
    while not shutdown_event.is_set():
        shutdown_event.wait(AUTO_SAVE_INTERVAL)
        if not shutdown_event.is_set():
            try:
                tracker.save_state()
            except Exception:
                logger.exception("自动保存失败")


# ---------------------------------------------------------------------------
# 异步 UDP 服务器启动
# ---------------------------------------------------------------------------
async def _start_udp_server(host: str, port: int) -> _AsyncUDPTracker:
    """启动异步 UDP tracker 服务器。"""
    loop = asyncio.get_running_loop()
    global _udp_loop, _udp_stop_signal
    _udp_loop = loop

    sock = _create_udp_socket(host, port)

    protocol = _AsyncUDPTracker(host, port, tracker)

    transport, _ = await loop.create_datagram_endpoint(
        lambda: protocol,
        sock=sock,
    )
    global _udp_transport
    _udp_transport = transport

    logger.info(
        "UDP Tracker 监听于 %s:%d（asyncio 模式，无线程池）",
        host, port,
    )
    if protocol._key_required:
        logger.info("UDP Tracker 已启用 API Key 验证（私有模式）")

    # 启动连接清理任务
    cleanup_task = asyncio.create_task(protocol._cleanup_connections_loop())

    # 使用 asyncio.Event 实现即时关闭通知
    udp_stop_event = asyncio.Event()

    def _signal_udp_stop() -> None:
        if not udp_stop_event.is_set():
            udp_stop_event.set()

    global _udp_stop_signal
    _udp_stop_signal = _signal_udp_stop

    try:
        # 兜底轮询：主路径通过 _notify_udp_shutdown -> call_soon_threadsafe 即时触发
        async def _poll_shutdown() -> None:
            while not shutdown_event.is_set():
                await asyncio.sleep(1.0)
            _signal_udp_stop()

        poll_task = asyncio.create_task(_poll_shutdown())
        await udp_stop_event.wait()
        poll_task.cancel()
        try:
            await poll_task
        except (asyncio.CancelledError, Exception):
            pass
    finally:
        cleanup_task.cancel()
        transport.close()
        try:
            await asyncio.gather(cleanup_task, return_exceptions=True)
        except Exception:
            pass
        _udp_transport = None
        _udp_loop = None
        _udp_stop_signal = None

    return protocol


def _create_udp_socket(host: str, port: int) -> socket.socket:
    """创建 UDP socket（支持双栈）。"""
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
            return None  # 显式 IPv4 -> 走 v4
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


def run_async_udp(host: str, port: int) -> None:
    """在新线程中运行 asyncio 事件循环。"""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(_start_udp_server(host, port))
    except Exception:
        logger.exception("UDP 事件循环异常")
    finally:
        pending = asyncio.all_tasks(loop)
        if pending:
            for task in pending:
                task.cancel()
            loop.run_until_complete(
                asyncio.gather(*pending, return_exceptions=True)
            )
        loop.close()


def run_server() -> None:
    global _server_instance, _udp_thread
    srv = make_server(IP, PORT, app, threaded=True)
    _server_instance = srv

    # 在独立线程中启动 asyncio UDP 服务器（非 daemon，确保干净退出）
    udp_thread = threading.Thread(
        target=run_async_udp, args=(IP, UDP_PORT),
        daemon=False, name="udp-asyncio"
    )
    _udp_thread = udp_thread
    udp_thread.start()

    logger.info("Tracker 服务端运行于 %s:%d (TCP+UDP，UDP 使用 asyncio)", IP, PORT)
    if API_KEY:
        logger.info("管理端点已启用 API 密钥认证")
        if PROTECT_ANNOUNCE:
            logger.info("Announce 端点已启用 API Key 保护（私有模式）")
        if PROTECT_SCRAPE:
            logger.info("Scrape 端点已启用 API Key 保护（私有模式）")
    else:
        logger.warning("API 密钥未设置，管理端点不受保护！")
    try:
        srv.serve_forever()
    finally:
        if not shutdown_event.is_set():
            shutdown_event.set()
        _notify_udp_shutdown()
        logger.info("服务端已关闭")


# ---------------------------------------------------------------------------
# 程序入口
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    server_thread = threading.Thread(
        target=run_server, daemon=False, name="http-server"
    )
    server_thread.start()

    save_thread = threading.Thread(
        target=auto_save_loop, daemon=True, name="auto-save"
    )
    save_thread.start()

    try:
        while server_thread.is_alive():
            server_thread.join(1)
    except KeyboardInterrupt:
        signal_handler(signal.SIGINT, None)
    finally:
        logger.info("正在关闭 Tracker...")
        tracker.stop()
        if server_thread.is_alive():
            server_thread.join(timeout=5)
        if _udp_thread is not None and _udp_thread.is_alive():
            _udp_thread.join(timeout=5)
        tracker.save_state()
        logger.info("Tracker 已停止。")
        sys.exit(0)
