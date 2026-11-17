#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NfcTapLink 电脑端接收服务 v3（nfctap/3）

v3 安全模型（修复 v2.3 审计遗留的完整接管链）：
  - 发布包 / 安装包不含任何长期密钥。首次启动在本机生成 256-bit pair_key，
    只写进本机 config.json；标签写 d=sha256(pair_key)[:16] 与 k=pair_key。
  - k 永不上网。配对是双向 challenge-response：手机证明持有 k，服务端回
    server_proof 证明自己也持有 k。假服务没有 k，无法冒充电脑。
  - token 有状态、随机、绑定来源 IP、10 分钟过期、重启即失效。旧版用随包
    secret 签发无状态 token，拿到发布包就能离线伪造永不过期 token。
  - 上传载荷用 HMAC-SHA256 派生的流密钥异或加密，再用独立 MAC 密钥做
    加密后认证（encrypt-then-MAC）。AAD 绑定 token / 路径 / 时间戳 / nonce /
    文件名 / 密文长度，nonce 一次性。明文 HTTP 被嗅探也拿不到文件内容或 k。
    选这个方案而不是 AES-GCM，是因为浏览器在普通 http://局域网 IP 下没有
    WebCrypto.subtle；三端（Python / Java / JS）都能用同一套 HMAC 原语实现。
  - 发现层只给候选地址，身份由 server_proof 证明；状态页转义 + CSP；
    Host 白名单 / Origin / Sec-Fetch-Site；/api/pair 限速；/api/recent 需 token；
    落盘扩展名白名单；去重改内存 sha256 索引。

用法：
  python receiver.py                       # 启动服务
  python receiver.py --paircode            # 打印标签 URI
  python receiver.py --rotate              # 轮换 k（旧标签失效，需重写）
  python receiver.py --selftest            # 本机端到端自测
  python receiver.py --discovery-selftest  # 发现模块自测

全程本地 / 局域网，不经过云端。
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import html
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import sys
import threading
import time
import urllib.parse
from collections import deque
from collections.abc import Iterator
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import discovery as DISC

VERSION = "3.0.0"          # 线缆协议版本，手机端/网页端会严格比对，勿与产品版本混用
PROTOCOL = "nfctap/3"
PRODUCT_VERSION = "6.2.5"  # 产品发布版本：桌面端 / 安装包 / 说明文档统一
FEATURE_REVERSE_SEND = True

CODE_DIR = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
DATA_DIR = Path(os.environ.get("NFCTAP_DATA_DIR") or Path(__file__).resolve().parent)
try:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
except OSError:
    pass
BASE_DIR = CODE_DIR
RECEIVED_DIR = DATA_DIR / "received"
OUTBOX_DIR = DATA_DIR / "outbox"
CONFIG_PATH = DATA_DIR / "config.json"
LOG_PATH = DATA_DIR / "transfer.log.jsonl"
OUTBOX_META = OUTBOX_DIR / "pending.json"

DEFAULT_PORT = 8765
CHALLENGE_TTL = 60
TOKEN_TTL = 10 * 60
REPLAY_TTL = 300
TS_SKEW = 120
MAX_UPLOAD = 1024 * 1024 * 1024     # 单文件上限 1 GB（收发两端与网页端必须一致）


def _size_text(n: int) -> str:
    if n % (1024 ** 3) == 0:
        return f"{n // 1024 ** 3} GB"
    if n % (1024 ** 2) == 0:
        return f"{n // 1024 ** 2} MB"
    return f"{n} B"


MAX_UPLOAD_LABEL = _size_text(MAX_UPLOAD)
ENVELOPE_OVERHEAD = 3 + 1 + 512 + 16 + 32
MAX_BODY = MAX_UPLOAD + ENVELOPE_OVERHEAD
PAIR_MAX_FAILS = 5
PAIR_WINDOW = 60
LOG_MAX_BYTES = 5 * 1024 * 1024
LOG_KEEP = 5
UPLOAD_CHUNK = 1024 * 1024

# 落盘白名单：EXT_MIME 减去危险 / 活动脚本类。旧版是「黑名单 + 未知扩展名
# 原样保留」，.html/.svg/.docm/.url 都能原样落盘并被桌面端双击打开。
DANGEROUS_EXTS = {
    ".bat", ".cmd", ".com", ".exe", ".msi", ".msp", ".scr", ".pif",
    ".ps1", ".psm1", ".psd1", ".vbs", ".vbe", ".js", ".jse", ".wsf",
    ".wsh", ".hta", ".jar", ".lnk", ".reg", ".cpl", ".dll", ".sys",
    ".svg", ".svgz", ".xhtml", ".mht", ".mhtml",
}
EXT_MIME = {
    ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png",
    ".webp": "image/webp", ".gif": "image/gif", ".bmp": "image/bmp",
    ".heic": "image/heic", ".heif": "image/heif", ".tif": "image/tiff",
    ".tiff": "image/tiff",
    ".doc": "application/msword",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xls": "application/vnd.ms-excel",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".ppt": "application/vnd.ms-powerpoint",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ".pdf": "application/pdf", ".txt": "text/plain", ".md": "text/markdown",
    ".csv": "text/csv", ".rtf": "application/rtf", ".json": "application/json",
    ".xml": "application/xml",
    ".odt": "application/vnd.oasis.opendocument.text",
    ".ods": "application/vnd.oasis.opendocument.spreadsheet",
    ".odp": "application/vnd.oasis.opendocument.presentation",
    ".zip": "application/zip", ".rar": "application/vnd.rar",
    ".7z": "application/x-7z-compressed", ".tar": "application/x-tar",
    ".gz": "application/gzip",
    ".apk": "application/vnd.android.package-archive",
    ".apks": "application/vnd.android.package-archive",
    ".xapk": "application/vnd.android.package-archive",
    ".mp4": "video/mp4", ".mov": "video/quicktime", ".mkv": "video/x-matroska",
    ".avi": "video/x-msvideo", ".webm": "video/webm",
    ".mp3": "audio/mpeg", ".wav": "audio/wav", ".m4a": "audio/mp4",
    ".amr": "audio/amr", ".ogg": "audio/ogg", ".flac": "audio/flac",
    # 以下保留 mime 供显示，但因在 DANGEROUS_EXTS 里，落盘一律 .bin
    ".exe": "application/vnd.microsoft.portable-executable",
    ".msi": "application/x-msi", ".dmg": "application/x-apple-diskimage",
    ".bat": "application/x-bat", ".cmd": "application/x-cmd",
    ".ps1": "application/x-powershell", ".vbs": "application/x-vbs",
    ".js": "text/javascript", ".jar": "application/java-archive",
    ".lnk": "application/x-ms-shortcut", ".reg": "application/x-reg",
    ".hta": "application/x-hta", ".scr": "application/x-screensaver",
    ".dll": "application/x-msdownload", ".sys": "application/x-msdownload",
    ".com": "application/x-msdownload", ".pif": "application/x-msdownload",
    ".cpl": "application/x-msdownload", ".msp": "application/x-msi",
    ".vbe": "application/x-vbs", ".jse": "text/javascript",
    ".wsf": "application/x-wsf", ".wsh": "application/x-wsh",
    ".psm1": "application/x-powershell", ".psd1": "application/x-powershell",
    ".svg": "image/svg+xml",
}
SAFE_EXTS = set(EXT_MIME) - DANGEROUS_EXTS
MIME_EXT: dict[str, str] = {}
for _ext, _mime in EXT_MIME.items():
    MIME_EXT.setdefault(_mime, _ext)

_MAGIC_RULES = (
    (b"\xff\xd8\xff", "image/jpeg"), (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"GIF87a", "image/gif"), (b"GIF89a", "image/gif"), (b"BM", "image/bmp"),
    (b"%PDF-", "application/pdf"), (b"PK\x03\x04", "application/zip"),
    (b"Rar!\x1a\x07", "application/vnd.rar"),
    (b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed"),
    (b"\x1f\x8b", "application/gzip"), (b"ID3", "audio/mpeg"),
    (b"OggS", "audio/ogg"), (b"fLaC", "audio/flac"),
    (b"\x00\x00\x00\x18ftyp", "video/mp4"),
    (b"\x00\x00\x00\x20ftyp", "video/mp4"),
)
_IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp", ".heic",
               ".heif", ".tif", ".tiff"}
_STORE_LOCK = threading.Lock()
LOG_LOCK = _STORE_LOCK
OUTBOX_LOCK = _STORE_LOCK


def _log_archives() -> list[Path]:
    """按编号升序返回轮转档：.1 最新，.5 最老。"""
    paths = [p for p in LOG_PATH.parent.glob(LOG_PATH.name + ".*")
             if p.is_file() and p.name.rsplit(".", 1)[-1].isdigit()]
    return sorted(paths, key=lambda p: int(p.name.rsplit(".", 1)[-1]))


def _rotate_log_locked() -> None:
    """轮转：.1 最新，旧档依次后移；超出 LOG_KEEP 的删除。调用方持 LOG_LOCK。"""
    try:
        if not LOG_PATH.exists() or LOG_PATH.stat().st_size < LOG_MAX_BYTES:
            return
        oldest = LOG_PATH.with_name(LOG_PATH.name + "." + str(LOG_KEEP))
        if oldest.exists():
            oldest.unlink()
        for idx in range(LOG_KEEP - 1, 0, -1):
            src = LOG_PATH.with_name(LOG_PATH.name + "." + str(idx))
            dst = LOG_PATH.with_name(LOG_PATH.name + "." + str(idx + 1))
            if src.exists():
                src.replace(dst)
        LOG_PATH.replace(LOG_PATH.with_name(LOG_PATH.name + ".1"))
    except OSError:
        pass


def append_log(entry: dict) -> None:
    with LOG_LOCK:
        _rotate_log_locked()
        with LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def read_recent(limit: int = 20) -> list[dict]:
    newest_first: list[dict] = []
    with LOG_LOCK:
        # 当前日志优先；不足 limit 时回看轮转档（.1 最新）。每个文件只读尾部。
        for path in [LOG_PATH] + _log_archives():
            if not path.exists():
                continue
            try:
                with path.open("r", encoding="utf-8") as f:
                    for line in reversed(list(deque(f, maxlen=limit))):
                        if not line.strip():
                            continue
                        try:
                            newest_first.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
                        if len(newest_first) >= limit:
                            break
            except OSError:
                continue
            if len(newest_first) >= limit:
                break
    # 与原实现语义一致：最新记录排第一行（桌面端表格 / 状态页都按此顺序展示）。
    return newest_first[:limit]


# --------------------------------------------------------------------------
# 配置与密钥
# --------------------------------------------------------------------------

def device_id_from_key(pair_key: str) -> str:
    """公开设备标识：由本机随机 k 派生，不是机密。"""
    return hashlib.sha256(bytes.fromhex(pair_key)).hexdigest()[:16]


def load_or_create_config() -> dict:
    """读取配置；旧版 secret/pair_code 配置一律视为已泄露并重新生成。"""
    cfg = None
    if CONFIG_PATH.exists():
        try:
            cfg = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            cfg = None
    if not isinstance(cfg, dict) or not cfg.get("pair_key"):
        cfg = {
            "pair_key": secrets.token_hex(32),
            "created_at": datetime.now().isoformat(timespec="seconds"),
            "protocol": PROTOCOL, "version": VERSION,
        }
        cfg["device_id"] = device_id_from_key(cfg["pair_key"])
        CONFIG_PATH.write_text(json.dumps(cfg, ensure_ascii=False, indent=2),
                               encoding="utf-8")
        print(f"[配置] 已生成本机随机密钥 {CONFIG_PATH.name}（仅存本机，不随安装包分发）")
    cfg.setdefault("device_id", device_id_from_key(cfg["pair_key"]))
    return cfg


def rotate_pair_key() -> dict:
    """轮换 k；device_id 随之变化，必须重写物理标签。"""
    cfg = load_or_create_config()
    cfg["pair_key"] = secrets.token_hex(32)
    cfg["device_id"] = device_id_from_key(cfg["pair_key"])
    cfg["rotated_at"] = datetime.now().isoformat(timespec="seconds")
    cfg["protocol"] = PROTOCOL
    cfg["version"] = VERSION
    CONFIG_PATH.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
    return cfg


def key_bytes(cfg: dict) -> bytes:
    return bytes.fromhex(cfg["pair_key"])


def hmac_hex(cfg: dict, text: str) -> str:
    return hmac.new(key_bytes(cfg), text.encode("utf-8"), hashlib.sha256).hexdigest()


def derive_keys(cfg: dict, server_nonce: str, client_nonce: str,
                token: str, ts: int, nonce: str, name: str,
                cipher_len: int) -> tuple[bytes, bytes]:
    """从 k 派生每次上传独立的 (enc_key, mac_key)。

    enc_key 用于 HMAC 计数器模式生成密钥流；mac_key 用于加密后认证。
    两者都由同一会话根密钥加不同 label 派生，域分离，互不复用。
    """
    root = hmac.new(key_bytes(cfg),
                    f"session|{server_nonce}|{client_nonce}|{token}".encode("utf-8"),
                    hashlib.sha256).digest()
    ctx = f"upload|{ts}|{nonce}|{name}|{cipher_len}".encode("utf-8")
    enc = hmac.new(root, b"enc|" + ctx, hashlib.sha256).digest()
    mac = hmac.new(root, b"mac|" + ctx, hashlib.sha256).digest()
    return enc, mac


def _hmac_states(key: bytes) -> tuple:
    """预置 HMAC 的 inner / outer 哈希状态，避免每 32 字节重算一次 key。"""
    if len(key) > 64:
        key = hashlib.sha256(key).digest()
    k = key.ljust(64, b"\0")
    inner = hashlib.sha256(bytes(b ^ 0x36 for b in k))
    outer = hashlib.sha256(bytes(b ^ 0x5C for b in k))
    return inner, outer


def keystream_blocks(key: bytes, n: int) -> Iterator[bytes]:
    """按 32B 块产出 HMAC 计数器密钥流，末块截断到 n，不缓存整段。"""
    inner, outer = _hmac_states(key)
    remaining = n
    counter = 0
    while remaining > 0:
        h = inner.copy()
        h.update(b"KS|" + counter.to_bytes(8, "big"))
        o = outer.copy()
        o.update(h.digest())
        block = o.digest()
        yield block[:remaining] if remaining < len(block) else block
        remaining -= len(block)
        counter += 1


def keystream(key: bytes, n: int) -> bytes:
    """保留整体接口给 seal_upload / 回归脚本；服务端接收走 keystream_blocks。"""
    return b"".join(keystream_blocks(key, n))


def xor_slice(buf: bytearray, start: int, ks: bytes) -> None:
    """把 ks 异或到 buf[start:start+len(ks)]，按 32B 大整数运算，不建切片副本。
    等价于逐字节异或，但大文件时不会被 Python 层 for 循环拖慢。"""
    end = start + len(ks)
    for off in range(start, end, 32):
        n = min(32, end - off)
        plain = int.from_bytes(buf[off:off + n], "big")
        mask = int.from_bytes(ks[off - start:off - start + n], "big")
        buf[off:off + n] = (plain ^ mask).to_bytes(n, "big")


def upload_aad(token: str, ts: int, nonce: str, name: str, cipher_len: int) -> bytes:
    return (f"nfctap/3|POST|/api/upload|{token}|{ts}|{nonce}|{name}|{cipher_len}"
            .encode("utf-8"))


def download_keys(cfg: dict, sn: str, cn: str, token: str, ts: int,
                  nonce: str, outbox_id: str, name: str,
                  data_len: int) -> tuple[bytes, bytes, bytes]:
    """反向发送的独立密钥派生：label 用 download|，与上传 upload| 域分离。"""
    root = hmac.new(key_bytes(cfg),
                    f"session|{sn}|{cn}|{token}".encode("utf-8"),
                    hashlib.sha256).digest()
    ctx = (f"download|{ts}|{nonce}|{outbox_id}|{name}|{data_len}"
           .encode("utf-8"))
    enc = hmac.new(root, b"enc|" + ctx, hashlib.sha256).digest()
    mac = hmac.new(root, b"mac|" + ctx, hashlib.sha256).digest()
    aad = (f"nfctap/3|GET|/api/download|{token}|{ts}|{nonce}|{outbox_id}|"
           f"{name}|{data_len}").encode("utf-8")
    return enc, mac, aad


def seal_download(cfg: dict, sn: str, cn: str, token: str, ts: int,
                  nonce: str, outbox_id: str, name: str,
                  data: bytes) -> bytes:
    """NT3D = "NT3" + nameLen(1) + name + tag(32) + cipher；供手机端解密校验。

    仅用于自检 / 小文件整段封装。服务端下行改走 cipher_chunks + download_tag
    流式发送，线缆字节与此函数完全一致，但 1 GB 文件不需要整段进内存。
    """
    name_b = name.encode("utf-8")
    if not name_b or len(name_b) > 255:
        raise ValueError("文件名 UTF-8 字节数必须在 1..255")
    enc_key, mac_key, aad = download_keys(cfg, sn, cn, token, ts, nonce,
                                          outbox_id, name, len(data))
    ks = keystream(enc_key, len(data))
    cipher = bytes(a ^ b for a, b in zip(data, ks))
    tag = hmac.new(mac_key, aad + cipher, hashlib.sha256).digest()
    return b"NT3" + bytes([len(name_b)]) + name_b + tag + cipher


CIPHER_CHUNK = 1024 * 1024


def cipher_chunks(path: Path, size: int, enc_key: bytes,
                  chunk: int = CIPHER_CHUNK) -> Iterator[bytearray]:
    """流式产出密文块（明文逐块读盘 → 密钥流异或），常数内存。

    密钥流按 32B 一块由 HMAC 计数器生成；这里把小块拼成 ~1MB 再异或一次，
    避免 1 GB 文件时几十万次 Python 层小循环。
    """
    ks_iter = keystream_blocks(enc_key, size)
    done = 0
    with path.open("rb") as f:
        while done < size:
            parts: list[bytes] = []
            n = 0
            while n < chunk:
                try:
                    block = next(ks_iter)
                except StopIteration:
                    break
                parts.append(block)
                n += len(block)
            if not parts:
                break
            ks = b"".join(parts)
            plain = f.read(len(ks))
            if len(plain) != len(ks):
                raise OSError("待发文件在发送过程中被修改")
            buf = bytearray(plain)
            xor_slice(buf, 0, ks)
            done += len(buf)
            yield buf


def download_tag(path: Path, size: int, enc_key: bytes, mac_key: bytes,
                 aad: bytes) -> bytes:
    """tag 位于密文之前，只能先扫一遍密文算出 MAC，再回放发送。"""
    h = hmac.new(mac_key, aad, hashlib.sha256)
    for buf in cipher_chunks(path, size, enc_key):
        h.update(buf)
    return h.digest()


def build_pair_uri(cfg: dict) -> str:
    """v3 标签：稳定设备 ID + 256-bit 配对密钥（无 IP、无端口）。"""
    return ("nfctap://pair?d=" + urllib.parse.quote(cfg["device_id"])
            + "&k=" + urllib.parse.quote(cfg["pair_key"]))


# --------------------------------------------------------------------------
# 网络地址探测
# --------------------------------------------------------------------------

def guess_lan_ip() -> str:
    candidates: list[str] = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("223.5.5.5", 80))
        candidates.append(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            if info[4][0] not in candidates:
                candidates.append(info[4][0])
    except OSError:
        pass
    for ip in candidates:
        if ip.startswith(("127.", "169.254.", "172.24.", "192.168.92.",
                          "192.168.229.", "26.26.")):
            continue
        return ip
    return candidates[0] if candidates else "127.0.0.1"


# --------------------------------------------------------------------------
# 类型判定与落盘命名
# --------------------------------------------------------------------------

def sniff_type(data: bytes) -> str | None:
    for magic, mime in _MAGIC_RULES:
        if data.startswith(magic):
            return mime
    if len(data) >= 12 and data[0:4] == b"RIFF":
        kind = data[8:12]
        return {b"WEBP": "image/webp", b"WAVE": "audio/wav",
                b"AVI ": "video/x-msvideo"}.get(kind)
    if len(data) >= 12 and data[4:8] == b"ftyp":
        brand = data[8:12]
        if brand in (b"heic", b"heix", b"mif1", b"msf1", b"hevc"):
            return "image/heic"
        if brand == b"qt  ":
            return "video/quicktime"
        return "video/mp4"
    return None


_EXT_RE = re.compile(r"\.([A-Za-z0-9]{1,10})$")


def split_name(name: str) -> tuple[str, str]:
    """拆成 (安全 stem, 小写扩展名含点)；路径部分直接丢弃。"""
    base = Path(name or "").name
    base = re.sub(r"[^0-9A-Za-z\u4e00-\u9fff._-]", "_", base)
    base = base.strip("._") or "file"
    m = _EXT_RE.search(base)
    ext, stem = "", base
    if m:
        ext, stem = "." + m.group(1).lower(), base[: m.start()]
    return stem[:60].strip("._") or "file", ext


def resolve_target(head: bytes, declared: str) -> tuple[str, str, str]:
    """落盘 (mime, ext, stem)。v3：白名单 + 图片 magic 校验；只看文件头。"""
    stem, ext = split_name(declared)
    if ext not in SAFE_EXTS:
        return "application/octet-stream", ".bin", stem
    detected = sniff_type(head)
    if ext in _IMAGE_EXTS:
        if detected and detected.startswith("image/"):
            return detected, MIME_EXT.get(detected, ".png"), stem
        if detected is None:
            return "application/octet-stream", ".bin", stem
        return detected, MIME_EXT.get(detected, ".bin"), stem
    return EXT_MIME[ext], ext, stem


_KIND_BY_EXT = {
    "图片": {".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp", ".heic",
            ".heif", ".tif", ".tiff"},
    "文档": {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf",
            ".txt", ".md", ".csv", ".rtf", ".json", ".xml", ".odt", ".ods", ".odp"},
    "压缩包": {".zip", ".rar", ".7z", ".tar", ".gz"},
    "安装包": {".apk", ".apks", ".xapk"},
    "音视频": {".mp4", ".mov", ".mkv", ".avi", ".webm",
              ".mp3", ".wav", ".m4a", ".amr", ".ogg", ".flac"},
}


def kind_of(ext: str) -> str:
    for kind, exts in _KIND_BY_EXT.items():
        if (ext or "").lower() in exts:
            return kind
    return "其他"


def safe_display_name(name: str) -> str:
    stem, ext = split_name(name)
    return stem + ext


def stage_outbox(src: Path, name: str | None = None) -> dict:
    """桌面端「发送到手机」：把选中的文件复制一份到 outbox/ 并登记待发。

    复制而不是引用原路径：用户点击发送后可以移动/删除原文件，服务仍能发出。
    """
    src = Path(src)
    if not src.is_file():
        raise ValueError("所选文件不存在或不是普通文件")
    size = src.stat().st_size
    if size <= 0:
        raise ValueError("不能发送空文件")
    if size > MAX_UPLOAD:
        raise ValueError(f"文件超过 {MAX_UPLOAD_LABEL} 上限")
    display = safe_display_name(name or src.name)
    OUTBOX_DIR.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    with src.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    with OUTBOX_LOCK:
        cancel_outbox_locked()
        staged = OUTBOX_DIR / ("pending-" + secrets.token_hex(8) + ".bin")
        shutil.copyfile(src, staged)
        meta = {
            "id": secrets.token_hex(16), "name": display,
            "bytes": size, "sha256": digest.hexdigest(),
            "mime": EXT_MIME.get(Path(display).suffix.lower(),
                                 "application/octet-stream"),
            "file": staged.name,
            "created_at": datetime.now().isoformat(timespec="seconds"),
            "claimed": False,
        }
        OUTBOX_META.write_text(json.dumps(meta, ensure_ascii=False, indent=2),
                               encoding="utf-8")
    return meta


def read_outbox_locked() -> dict | None:
    try:
        meta = json.loads(OUTBOX_META.read_text(encoding="utf-8"))
        if not isinstance(meta, dict) or not meta.get("id"):
            return None
        target = OUTBOX_DIR / str(meta.get("file", ""))
        if not target.is_file():
            return None
        return meta
    except (OSError, ValueError):
        return None


def cancel_outbox_locked() -> None:
    meta = read_outbox_locked()
    try:
        OUTBOX_META.unlink(missing_ok=True)
    except OSError:
        pass
    if meta:
        try:
            (OUTBOX_DIR / str(meta["file"])).unlink(missing_ok=True)
        except OSError:
            pass


def public_outbox(meta: dict) -> dict:
    return {"id": meta["id"], "name": meta["name"],
            "bytes": meta["bytes"], "mime": meta["mime"],
            "sha256": meta["sha256"]}


def claim_outbox(meta_id: str) -> tuple[str, dict | None]:
    """兼容旧调用：校验并直接标记 claimed。

    注意：下载主流程已改为「先 peek、完整发出后再 claim」，避免手机中途断网
    就把待发文件永久消费掉（那会表现成「电脑发送了，手机再也收不到」）。
    """
    with OUTBOX_LOCK:
        meta = read_outbox_locked()
        if meta is None or meta.get("id") != meta_id:
            return "没有待发文件", None
        if meta.get("claimed"):
            return "这个文件已经被接收过了", None
        meta["claimed"] = True
        meta["claimed_at"] = datetime.now().isoformat(timespec="seconds")
        OUTBOX_META.write_text(json.dumps(meta, ensure_ascii=False, indent=2),
                               encoding="utf-8")
        return "ok", meta


def peek_outbox(meta_id: str) -> tuple[str, dict | None]:
    """只校验、不消费：手机端断开时文件仍留在队列里，下一次碰标签可以重试。"""
    with OUTBOX_LOCK:
        meta = read_outbox_locked()
        if meta is None or meta.get("id") != meta_id:
            return "没有待发文件", None
        if meta.get("claimed"):
            return "这个文件已经被接收过了", None
        return "ok", dict(meta)


def mark_outbox_claimed(meta_id: str) -> bool:
    """响应体完整写出后才调用；中途失败不写，保持待发状态可重试。"""
    with OUTBOX_LOCK:
        meta = read_outbox_locked()
        if meta is None or meta.get("id") != meta_id:
            return False
        meta["claimed"] = True
        meta["claimed_at"] = datetime.now().isoformat(timespec="seconds")
        try:
            OUTBOX_META.write_text(json.dumps(meta, ensure_ascii=False, indent=2),
                                   encoding="utf-8")
        except OSError:
            return False
        return True


def build_hash_index() -> dict[str, str]:
    """启动时流式建立 sha256 → 文件名索引，避免每次上传全量读盘比对。"""
    idx: dict[str, str] = {}
    if not RECEIVED_DIR.exists():
        return idx
    for p in RECEIVED_DIR.iterdir():
        if not p.is_file():
            continue
        h = hashlib.sha256()
        try:
            with p.open("rb") as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    h.update(chunk)
            idx[h.hexdigest()] = p.name
        except OSError:
            continue
    return idx

# --------------------------------------------------------------------------
# HTTP 处理
# --------------------------------------------------------------------------

class State:
    def __init__(self, cfg: dict, host: str, port: int):
        self.cfg = cfg
        self.host = host
        self.port = port
        self.started = time.time()
        self.lock = threading.RLock()
        self.challenges: dict[str, dict] = {}
        self.tokens: dict[str, dict] = {}
        self.nonces: dict[str, float] = {}
        self.pair_fails: dict[str, list[float]] = {}
        self.count_ok = 0
        self.count_dup = 0
        self.count_reject = 0
        self.device_id = cfg["device_id"]
        self.discovery: DISC.DiscoveryService | None = None
        self.ble = None
        self.hotspot = None
        self.all_addresses: list[str] = DISC.local_addresses()
        self.hash_index = build_hash_index()

    def cleanup(self) -> None:
        now = time.time()
        for d, cutoff in ((self.challenges, CHALLENGE_TTL),
                          (self.tokens, TOKEN_TTL),
                          (self.nonces, REPLAY_TTL)):
            for k in list(d):
                rec = d[k]
                t = rec if isinstance(rec, float) else rec.get("ts", 0)
                if now - t > cutoff:
                    del d[k]
        for ip in list(self.pair_fails):
            self.pair_fails[ip] = [t for t in self.pair_fails[ip]
                                   if now - t < PAIR_WINDOW]
            if not self.pair_fails[ip]:
                del self.pair_fails[ip]

    def pair_blocked(self, ip: str) -> bool:
        return len(self.pair_fails.get(ip, [])) >= PAIR_MAX_FAILS

    def pair_failed(self, ip: str) -> None:
        self.pair_fails.setdefault(ip, []).append(time.time())

    def check_token(self, token: str, ip: str) -> tuple[bool, str, dict | None]:
        rec = self.tokens.get(token)
        if rec is None:
            return False, "token 无效或已过期，请重新碰标签配对", None
        if rec["ts"] + TOKEN_TTL < time.time():
            del self.tokens[token]
            return False, "token 已过期，请重新碰标签配对", None
        if rec["ip"] != ip:
            return False, "token 来源地址不匹配", None
        return True, "ok", rec


def host_allowed(value: str) -> bool:
    """Host 只接受 IP 字面量 / localhost，挡 DNS rebinding。"""
    if not value:
        return False
    h = value.strip().lower()
    if h.startswith("["):
        h = h[1:h.find("]")] if "]" in h else h
    elif h.count(":") == 1:
        h = h.rsplit(":", 1)[0]
    if h in ("localhost", "127.0.0.1", "::1"):
        return True
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


class Handler(BaseHTTPRequestHandler):
    server_version = f"NfcTapLink/{VERSION}"
    protocol_version = "HTTP/1.1"

    @property
    def st(self) -> State:
        return self.server.state  # type: ignore[attr-defined]

    def log_request(self, code="-", size="-") -> None:
        # 6.2.2：访问日志只记录脱敏后的路径，任何 ?k= / token / ticket 都不得原文落盘。
        self.log_message('"%s %s" %s %s', self.command, redact_url(self.path), code, size)

    def log_message(self, fmt: str, *args) -> None:
        print(f"[{datetime.now():%H:%M:%S}] {self.client_address[0]} {fmt % args}")

    def _send(self, code: int, body: bytes,
              ctype: str = "application/json; charset=utf-8",
              extra: dict | None = None) -> None:
        extra = dict(extra or {})
        csp = extra.pop("CSP", "default-src 'none'; frame-ancestors 'none'")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", csp)
        for k, v in extra.items():
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, code: int, obj: dict, extra: dict | None = None) -> None:
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                   extra=extra)

    def _reject(self, code: int, msg: str) -> None:
        with self.st.lock:
            self.st.count_reject += 1
        self._json(code, {"ok": False, "error": msg})

    def _guard(self) -> bool:
        host = self.headers.get("Host", "")
        if not host_allowed(host):
            self.close_connection = True
            self._reject(403, "Host 不允许")
            return False
        site = self.headers.get("Sec-Fetch-Site", "")
        if site and site not in ("none", "same-origin"):
            self.close_connection = True
            self._reject(403, "跨站请求被拒绝")
            return False
        origin = self.headers.get("Origin", "")
        if origin and origin not in (f"http://{host}", "null"):
            self.close_connection = True
            self._reject(403, "Origin 不匹配")
            return False
        return True

    def _fail_post(self, code: int, msg: str, *, body_consumed: bool = False,
                   body_read: int = 0) -> None:
        """失败前读掉未消费 body 并关闭连接，避免污染 keep-alive 连接。
        body_read 供流式上传报告「已读了多少字节」，只补读剩余部分。"""
        if not body_consumed:
            try:
                declared = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                declared = 0
            remaining = declared - body_read
            if 0 < remaining <= MAX_BODY + 1024:
                try:
                    self.rfile.read(remaining)
                except (OSError, ValueError):
                    pass
        self.close_connection = True
        self._reject(code, msg)

    # ---- GET ----
    def do_GET(self) -> None:
        if not self._guard():
            return
        u = urllib.parse.urlparse(self.path)

        if u.path in ("/", "/index.html"):
            self._send(200, self._status_page().encode("utf-8"),
                       "text/html; charset=utf-8",
                       {"CSP": "default-src 'none'; style-src 'unsafe-inline'; "
                               "frame-ancestors 'none'"})
            return

        if u.path in ("/tap", "/tap.html"):
            page = BASE_DIR / "tap.html"
            if not page.exists():
                self._reject(404, "tap.html 缺失")
                return
            self._send(200, page.read_bytes(), "text/html; charset=utf-8",
                       {"CSP": "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                               "style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; "
                               "connect-src 'self'; frame-ancestors 'none'"})
            return

        if u.path == "/api/ping":
            self._json(200, {"ok": True, "protocol": PROTOCOL, "version": VERSION,
                             "device_id": self.st.device_id, "time": int(time.time())})
            return

        if u.path == "/api/challenge":
            with self.st.lock:
                self.st.cleanup()
                n = secrets.token_hex(16)
                self.st.challenges[n] = {"ts": time.time(),
                                         "ip": self.client_address[0]}
            self._json(200, {"ok": True, "protocol": PROTOCOL, "version": VERSION,
                             "device_id": self.st.device_id,
                             "server_nonce": n, "ttl": CHALLENGE_TTL})
            return

        if u.path == "/api/info":
            # v3：不再暴露网卡列表、广播地址、device_id 等内部信息。
            self._json(200, {"ok": True, "protocol": PROTOCOL, "version": VERSION,
                             "product_version": PRODUCT_VERSION,
                             "host": self.st.host, "port": self.st.port,
                             "uptime_s": int(time.time() - self.st.started),
                             "received_ok": self.st.count_ok,
                             "duplicate": self.st.count_dup,
                             "rejected": self.st.count_reject,
                             "max_upload_bytes": MAX_UPLOAD,
                             "token_ttl_s": TOKEN_TTL})
            return

        if u.path == "/api/discover":
            # v3：不再返回带签名的完整公告；身份由 server_proof 证明。
            self._json(200, {"ok": True, "protocol": PROTOCOL,
                             "device_id": self.st.device_id,
                             "addresses": DISC.local_addresses(),
                             "port": self.st.port,
                             "multicast": f"{DISC.MCAST_GRP}:{DISC.MCAST_PORT}"})
            return

        if u.path == "/api/recent":
            auth = self.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                self._reject(401, "缺少 Bearer token")
                return
            ok, why, _ = self.st.check_token(auth[7:].strip(), self.client_address[0])
            if not ok:
                self._reject(401, why)
                return
            self._json(200, {"ok": True, "items": read_recent(20)})
            return

        if u.path == "/api/outbox":
            auth = self.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                self._reject(401, "缺少 Bearer token")
                return
            ok, why, _ = self.st.check_token(auth[7:].strip(), self.client_address[0])
            if not ok:
                self._reject(401, why)
                return
            with OUTBOX_LOCK:
                meta = read_outbox_locked()
                pending = None if (meta is None or meta.get("claimed")) else public_outbox(meta)
            self._json(200, {"ok": True, "reverse_send": FEATURE_REVERSE_SEND,
                             "pending": pending})
            return

        if u.path == "/api/download":
            self._handle_download(u)
            return

        self._reject(404, "未知接口")

    def _handle_download(self, u: urllib.parse.ParseResult) -> None:
        """反向发送：手机碰标签后拉取电脑端 outbox 里暂存的加密文件。"""
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            self._reject(401, "缺少 Bearer token")
            return
        token = auth[7:].strip()
        ok, why, rec = self.st.check_token(token, self.client_address[0])
        if not ok:
            self._reject(401, why)
            return
        assert rec is not None
        q = urllib.parse.parse_qs(u.query)
        meta_id = (q.get("id") or [""])[0]
        if not re.fullmatch(r"[0-9a-f]{32}", meta_id):
            self._reject(400, "待发文件 ID 非法")
            return
        nonce = self.headers.get("X-Nonce", "")
        if not nonce or len(nonce) > 64 or not re.fullmatch(r"[A-Za-z0-9_-]+", nonce):
            self._reject(400, "缺少或非法的 X-Nonce")
            return
        try:
            ts = int(self.headers.get("X-Ts", ""))
        except (ValueError, TypeError):
            self._reject(400, "X-Ts 非法")
            return
        if abs(int(time.time()) - ts) > TS_SKEW:
            self._reject(401, "请求时间戳超出允许范围")
            return
        with self.st.lock:
            if nonce in self.st.nonces:
                self._reject(401, "nonce 重放")
                return
            self.st.nonces[nonce] = time.time()
        why, meta = peek_outbox(meta_id)
        if meta is None:
            self._reject(409, why)
            return
        path = OUTBOX_DIR / str(meta["file"])
        name = str(meta.get("name") or "")
        try:
            size = path.stat().st_size
            name_b = name.encode("utf-8")
        except (OSError, UnicodeEncodeError) as exc:
            self._reject(500, f"读取待发文件失败：{getattr(exc, 'strerror', None) or exc}")
            return
        if not name_b or len(name_b) > 255:
            self._reject(500, "待发文件名长度异常")
            return
        enc_key, mac_key, aad = download_keys(self.st.cfg, rec["sn"], rec["cn"],
                                              token, ts, nonce, meta["id"],
                                              name, size)
        try:
            # tag 在密文之前：先扫一遍算 MAC，再回放密文（两遍读盘、常数内存）。
            tag = download_tag(path, size, enc_key, mac_key, aad)
        except OSError as exc:
            self._reject(500, f"读取待发文件失败：{exc.strerror or exc}")
            return
        head = b"NT3" + bytes([len(name_b)]) + name_b + tag
        try:
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(head) + size))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy",
                             "default-src 'none'; frame-ancestors 'none'")
            self.send_header("X-Outbox-Id", meta["id"])
            self.send_header("X-SHA256", meta["sha256"])
            self.end_headers()
            self.wfile.write(head)
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
            return
        delivered = False
        try:
            for buf in cipher_chunks(path, size, enc_key):
                self.wfile.write(buf)
            self.wfile.flush()
            delivered = True
        except (BrokenPipeError, ConnectionResetError, OSError):
            delivered = False
        finally:
            # v6.1.0：日志改为「真正写完响应体之后」再记 sent，连接中途断掉记 failed，
            # 桌面端批量发送才能准确区分单个文件的成功 / 失败。
            entry = {"ts": datetime.now().isoformat(timespec="seconds"),
                     "sha256": meta["sha256"], "file": name,
                     "bytes": size, "mime": meta["mime"],
                     "kind": kind_of(Path(name).suffix.lower()),
                     "ext": Path(name).suffix.lower(),
                     "declared_name": name,
                     "from": self.client_address[0]}
            if delivered:
                with self.st.lock:
                    self.st.count_ok += 1
                # 6.2.4：完整发出响应体后才消费待发文件；中途断开保持待发，
                # 下一次碰标签还能重新接收。
                mark_outbox_claimed(meta["id"])
                entry["result"] = "sent"
            else:
                self.close_connection = True
                entry["result"] = "failed"
                entry["reason"] = "手机端连接中断，文件未送达"
            append_log(entry)

    # ---- POST ----
    def do_POST(self) -> None:
        if not self._guard():
            return
        u = urllib.parse.urlparse(self.path)
        with self.st.lock:
            self.st.cleanup()
        if u.path == "/api/pair":
            self._handle_pair()
        elif u.path == "/api/upload":
            self._handle_upload()
        else:
            self._fail_post(404, "未知接口")

    def _read_json(self, limit: int = 4096) -> dict | None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if length <= 0 or length > limit:
            return None
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None

    def _handle_pair(self) -> None:
        ip = self.client_address[0]
        if self.st.pair_blocked(ip):
            self._fail_post(429, "配对失败次数过多，请稍后再试")
            return
        obj = self._read_json()
        if not obj:
            self._fail_post(400, "请求体不是合法 JSON", body_consumed=True)
            self.st.pair_failed(ip)
            return
        sn = str(obj.get("server_nonce", ""))
        cn = str(obj.get("client_nonce", ""))
        did = str(obj.get("device_id", ""))
        proof = str(obj.get("proof", ""))
        if not (sn and cn and did and proof) or did != self.st.device_id:
            self._fail_post(400, "配对参数不完整或设备 ID 不符", body_consumed=True)
            self.st.pair_failed(ip)
            return
        with self.st.lock:
            ch = self.st.challenges.get(sn)
            if ch is None or ch["ip"] != ip:
                self._fail_post(401, "challenge 无效或来源不匹配", body_consumed=True)
                self.st.pair_failed(ip)
                return
            del self.st.challenges[sn]
            if time.time() - ch["ts"] > CHALLENGE_TTL:
                self._fail_post(401, "challenge 已过期", body_consumed=True)
                self.st.pair_failed(ip)
                return
            want = hmac_hex(self.st.cfg, f"client|{sn}|{cn}|{did}")
            if not hmac.compare_digest(proof, want):
                self._fail_post(401, "配对证明不匹配", body_consumed=True)
                self.st.pair_failed(ip)
                return
            token = secrets.token_urlsafe(32)
            self.st.tokens[token] = {"ts": time.time(), "ip": ip, "sn": sn, "cn": cn}
            server_proof = hmac_hex(self.st.cfg, f"server|{sn}|{cn}|{token}")
        self._json(200, {"ok": True, "protocol": PROTOCOL, "token": token,
                         "expires_in": TOKEN_TTL, "server_proof": server_proof,
                         "device_id": self.st.device_id,
                         "upload_url": f"http://{self.st.host}:{self.st.port}/api/upload",
                         "endpoints": [f"http://{a}:{self.st.port}"
                                       for a in DISC.local_addresses()],
                         "max_upload_bytes": MAX_UPLOAD})

    def _handle_upload(self) -> None:
        ip = self.client_address[0]
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            self._fail_post(401, "缺少 Bearer token")
            return
        token = auth[7:].strip()
        with self.st.lock:
            ok, why, rec = self.st.check_token(token, ip)
        if not ok:
            self._fail_post(401, why)
            return
        assert rec is not None
        nonce = self.headers.get("X-Nonce", "")
        ts_s = self.headers.get("X-Ts", "")
        if not nonce or len(nonce) > 64 or not re.fullmatch(r"[A-Za-z0-9_-]+", nonce):
            self._fail_post(400, "缺少或非法的 X-Nonce")
            return
        try:
            ts = int(ts_s)
        except (ValueError, TypeError):
            self._fail_post(400, "X-Ts 非法")
            return
        if abs(int(time.time()) - ts) > TS_SKEW:
            self._fail_post(401, "请求时间戳超出允许范围")
            return
        with self.st.lock:
            if nonce in self.st.nonces:
                self._fail_post(401, "nonce 重放")
                return
            self.st.nonces[nonce] = time.time()
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._fail_post(400, "Content-Length 非法")
            return
        if length <= 0:
            self._fail_post(400, "空请求体")
            return
        if length > MAX_BODY:
            self._fail_post(413, f"加密载荷超过 {MAX_BODY // 1024 // 1024} MB 上限")
            return
        # 流式：先读 4+nameLen+32B 的头部/MAC，密钥流按 1MB 块生成并写到临时文件。
        # 常数内存、常数密钥流；MAC 覆盖全部密文，验不过就删临时文件。
        consumed = 0

        def read_exact(n: int) -> bytes | None:
            nonlocal consumed
            try:
                buf = self.rfile.read(n)
            except (OSError, ValueError):
                return None
            consumed += len(buf)
            return buf if len(buf) == n else None

        def fail(code: int, msg: str, *, body_consumed: bool = False) -> None:
            self._fail_post(code, msg, body_consumed=body_consumed,
                            body_read=consumed)

        magic = read_exact(3)
        if magic != b"NT3":
            fail(400, "加密载荷格式错误")
            return
        nl_b = read_exact(1)
        if nl_b is None or nl_b[0] == 0:
            fail(400, "文件名编码或载荷长度错误")
            return
        name_len = nl_b[0]
        cipher_len = length - 4 - name_len - 32
        if cipher_len <= 0 or cipher_len > MAX_UPLOAD:
            fail(400 if cipher_len <= 0 else 413,
                 "空密文" if cipher_len <= 0 else "明文文件超过大小上限")
            return
        name_b = read_exact(name_len)
        if name_b is None:
            fail(400, "请求体不完整")
            return
        try:
            declared = name_b.decode("utf-8")
        except UnicodeDecodeError:
            fail(400, "文件名编码错误")
            return
        tag = read_exact(32)
        if tag is None:
            fail(400, "请求体不完整")
            return

        aad = upload_aad(token, ts, nonce, declared, cipher_len)
        enc_key, mac_key = derive_keys(self.st.cfg, rec["sn"], rec["cn"],
                                       token, ts, nonce, declared, cipher_len)
        try:
            RECEIVED_DIR.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            fail(500, "电脑端无法创建 received 目录："
                      f"{exc.strerror or exc}。请检查目录权限或安全软件拦截："
                      f"{RECEIVED_DIR}")
            return
        verifier = hmac.new(mac_key, aad, hashlib.sha256)
        ks_iter = keystream_blocks(enc_key, cipher_len)
        digest = hashlib.sha256()
        head = b""
        total = 0
        tmp = RECEIVED_DIR / (".upload-" + secrets.token_hex(12) + ".part")
        ok = False
        try:
            with tmp.open("wb") as f:
                remaining = cipher_len
                while remaining > 0:
                    chunk = read_exact(min(UPLOAD_CHUNK, remaining))
                    if chunk is None:
                        fail(400, "请求体不完整")
                        return
                    remaining -= len(chunk)
                    verifier.update(chunk)
                    plain = bytearray(chunk)
                    off = 0
                    while off < len(plain):
                        ks = next(ks_iter)
                        xor_slice(plain, off, ks)
                        off += len(ks)
                    data = bytes(plain)
                    if not head:
                        head = data[:16]
                    digest.update(data)
                    f.write(data)
                    total += len(data)
            if not hmac.compare_digest(tag, verifier.digest()):
                fail(401, "完整性校验失败", body_consumed=True)
                return
            if total > MAX_UPLOAD:
                fail(413, "明文文件超过大小上限", body_consumed=True)
                return
            ok = True
        except OSError as exc:
            fail(500, "电脑端无法写入 received 目录："
                      f"{exc.strerror or exc}。请检查目录权限或安全软件拦截："
                      f"{RECEIVED_DIR}", body_consumed=True)
            return
        finally:
            if not ok:
                try:
                    tmp.unlink(missing_ok=True)
                except OSError:
                    pass

        mime, ext, stem = resolve_target(head, declared)
        sha = digest.hexdigest()
        with self.st.lock:
            existing = self.st.hash_index.get(sha)
            if existing and (RECEIVED_DIR / existing).is_file():
                try:
                    tmp.unlink(missing_ok=True)
                except OSError:
                    pass
                self.st.count_dup += 1
                entry = {"ts": datetime.now().isoformat(timespec="seconds"),
                         "result": "duplicate", "sha256": sha,
                         "file": existing, "bytes": total, "mime": mime,
                         "kind": kind_of(ext), "ext": ext,
                         "declared_name": declared, "from": ip}
                append_log(entry)
                self._json(200, {"ok": True, "duplicate": True,
                                 "file": existing, "sha256": sha})
                return
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            final_name = f"{stamp}-{sha[:12]}-{stem}{ext}"
            target = RECEIVED_DIR / final_name
            if target.exists():
                final_name = f"{stamp}-{sha[:12]}-{secrets.token_hex(3)}-{stem}{ext}"
                target = RECEIVED_DIR / final_name
            try:
                tmp.replace(target)
            except OSError as exc:
                try:
                    tmp.unlink(missing_ok=True)
                except OSError:
                    pass
                self._json(500, {
                    "ok": False,
                    "error": "电脑端无法写入 received 目录："
                             f"{exc.strerror or exc}。请检查目录权限或安全软件拦截："
                             f"{RECEIVED_DIR}"})
                return
            self.st.hash_index[sha] = final_name
            self.st.count_ok += 1
        entry = {"ts": datetime.now().isoformat(timespec="seconds"),
                 "result": "saved", "sha256": sha, "file": final_name,
                 "bytes": total, "mime": mime, "kind": kind_of(ext),
                 "ext": ext, "declared_name": declared, "from": ip}
        append_log(entry)
        print(f"[接收] {final_name}  {total:,} 字节  "
              f"{kind_of(ext)}/{mime}  sha256={sha[:16]}…")
        self._json(200, {"ok": True, "duplicate": False, "file": final_name,
                         "bytes": total, "sha256": sha, "mime": mime})

    def do_OPTIONS(self) -> None:
        if not self._guard():
            return
        self.send_response(204)
        self.send_header("Allow", "GET, POST, OPTIONS")
        self.send_header("Content-Length", "0")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; frame-ancestors 'none'")
        self.end_headers()

    # ---- 状态页 ----
    def _status_page(self) -> str:
        addrs = html.escape(", ".join(DISC.local_addresses()))
        uri_hint = "python receiver.py --paircode"
        disc_on = self.st.discovery is not None
        disc_note = (f"自动发现已开启：UDP 组播 {html.escape(DISC.MCAST_GRP)}:"
                     f"{DISC.MCAST_PORT} + 广播；已应答查询 "
                     f"{self.st.discovery.queries} 次。"
                     if disc_on else "自动发现已关闭（--no-discovery）。")
        rows = []
        for it in read_recent(20):
            badge = {"saved": "已保存", "duplicate": "重复跳过"}.get(
                it.get("result", ""), "—")
            cells = [it.get("ts", ""), badge, it.get("file", ""),
                     f"{it.get('bytes', 0):,}", it.get("mime", ""),
                     it.get("from", "")]
            rows.append("<tr>" + "".join(
                f"<td>{html.escape(str(v))}</td>" for v in cells) + "</tr>")
        tbody = "".join(rows) or '<tr><td colspan=6 class=empty>暂无传输记录</td></tr>'
        host = html.escape(f"{self.st.host}:{self.st.port}")
        return f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NfcTapLink 接收端</title>
<style>
:root{{--bg:#111418;--panel:#1a1f26;--line:#2c343f;--txt:#e6e9ee;--dim:#8d97a5;--ok:#4ade80;--warn:#fbbf24}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--txt);font:14px/1.6 -apple-system,"Segoe UI","Microsoft YaHei",sans-serif}}
.wrap{{max-width:920px;margin:0 auto;padding:32px 20px 60px}}
h1{{font-size:20px;margin:0 0 4px;letter-spacing:.5px}}
.sub{{color:var(--dim);font-size:12px;margin-bottom:24px}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:24px}}
.card{{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px}}
.card .k{{color:var(--dim);font-size:11px}} .card .v{{font-size:19px;margin-top:4px;font-weight:600}}
.dot{{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--ok);margin-right:6px}}
.box{{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:18px;margin-bottom:20px}}
.box h2{{font-size:14px;margin:0 0 12px;color:var(--dim);font-weight:600;letter-spacing:.5px}}
code{{background:#0d1014;border:1px solid var(--line);border-radius:6px;padding:8px 10px;display:block;word-break:break-all;font:12px/1.5 Consolas,monospace;color:#9ae6b4}}
table{{width:100%;border-collapse:collapse;font-size:12px}}
th,td{{text-align:left;padding:8px 6px;border-bottom:1px solid var(--line)}}
th{{color:var(--dim);font-weight:500}} td:nth-child(3){{font-family:Consolas,monospace;word-break:break-all}}
td.empty{{text-align:center;color:var(--dim);padding:24px}}
.note{{color:var(--dim);font-size:12px;line-height:1.8}} .note b{{color:var(--warn);font-weight:600}}
footer{{margin-top:28px;color:#5c6572;font-size:11px;border-top:1px solid var(--line);padding-top:14px}}
</style></head><body><div class="wrap">
<h1><span class=dot></span>NfcTapLink 接收端 · 运行中</h1>
<div class=sub>产品 {PRODUCT_VERSION} · 协议 {PROTOCOL} / {VERSION} · 全程本地局域网，不经过云端</div>
<div class=cards>
<div class=card><div class=k>监听地址</div><div class=v>{host}</div></div>
<div class=card><div class=k>已接收</div><div class=v>{self.st.count_ok}</div></div>
<div class=card><div class=k>重复跳过</div><div class=v>{self.st.count_dup}</div></div>
<div class=card><div class=k>拒绝请求</div><div class=v>{self.st.count_reject}</div></div>
</div>
<div class=box><h2>安全模型</h2><div class=note>
本机密钥在首次启动时随机生成，安装包不含密钥；标签含配对密钥 <code>k</code>，
碰标签后手机与电脑做双向挑战应答，<b>k 不会在网络上传输</b>。<br>
上传 / 反向发送内容用会话密钥做 HMAC 计数器流加密与防篡改认证，绑定路径 /
时间 / nonce / 文件名 / 长度，明文 HTTP 下也不会泄露文件内容；发现公告只提供候选地址，不证明身份。<br>
当前可达地址：{addrs}<br>{disc_note}
</div></div>
<div class=box><h2>标签 URI</h2><div class=note>
本机控制台执行 <code style="display:inline;padding:2px 5px">{uri_hint}</code>
或在桌面端「服务与设置」页复制。<b>标签 URI 含配对密钥，属凭据，不在网页展示。</b><br>
轮换密钥后必须重写物理标签，旧标签立即失效。
</div></div>
<div class=box><h2>最近传输</h2>
<table><thead><tr><th>时间</th><th>结果</th><th>文件</th><th>字节</th><th>类型</th><th>来源</th></tr></thead>
<tbody>{tbody}</tbody></table></div>
<div class=box><h2>接口</h2><div class=note>
GET <code style="display:inline;padding:2px 5px">/api/ping</code> 探测 ·
GET <code style="display:inline;padding:2px 5px">/api/challenge</code> 取挑战 ·
POST <code style="display:inline;padding:2px 5px">/api/pair</code> 双向认证换 token ·
POST <code style="display:inline;padding:2px 5px">/api/upload</code> 加密上传 ·
GET <code style="display:inline;padding:2px 5px">/api/outbox</code> 探测电脑待发文件（需 token） ·
GET <code style="display:inline;padding:2px 5px">/api/download</code> 加密下载（需 token） ·
GET <code style="display:inline;padding:2px 5px">/api/recent</code> 最近记录（需 token）
</div></div>
<footer>NfcTapLink · 本地服务，无遥测、无云端。文件保存在 received/ 目录。</footer>
</div></body></html>"""

def build_pair_uri_v2_legacy(cfg: dict, with_candidates: bool = True) -> str:
    """旧 v2 标签格式（仅供迁移排障；不应在新标签上使用）。"""
    pair_code = cfg.get("pair_code", cfg.get("pair_key", "")[:12].upper())
    uri = ("nfctap://pair?d=" + urllib.parse.quote(DISC.device_id(cfg))
           + "&k=" + urllib.parse.quote(pair_code))
    if with_candidates:
        ips = DISC.local_addresses()
        if ips:
            uri += "&c=" + urllib.parse.quote(",".join(ips))
    return uri


_SENSITIVE_QUERY_KEYS = {"k", "key", "pair_key", "token", "ticket", "code", "secret"}


def redact_url(raw: str) -> str:
    """访问日志脱敏：查询串里的密钥类参数一律替换为 ***。"""
    try:
        parts = urllib.parse.urlsplit(raw)
    except ValueError:
        return raw
    if not parts.query:
        return raw
    out = []
    changed = False
    for key, val in urllib.parse.parse_qsl(parts.query, keep_blank_values=True):
        if key.lower() in _SENSITIVE_QUERY_KEYS:
            out.append((key, "***"))
            changed = changed or val != "***"
        else:
            out.append((key, val))
    if not changed:
        return raw
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path,
                                    urllib.parse.urlencode(out), parts.fragment))


def build_tap_url(host: str, port: int) -> str:
    """免安装浏览器方案地址。

    6.2.2 起不再把配对密钥放进查询串：k 只允许由用户在页面输入框手动输入，
    既不进入浏览器历史 / 代理日志，也不会被服务端访问日志记录。
    """
    return f"http://{host}:{port}/tap.html"


# --------------------------------------------------------------------------
# 启动 / 自测
# --------------------------------------------------------------------------

class _ExclusiveHTTPServer(ThreadingHTTPServer):
    """Windows 下禁止端口复用，避免两个实例同时监听同一端口。"""
    allow_reuse_address = sys.platform != "win32"


def make_server(host: str, port: int, cfg: dict,
                bind_host: str | None = None,
                discovery: DISC.DiscoveryService | None = None) -> ThreadingHTTPServer:
    RECEIVED_DIR.mkdir(parents=True, exist_ok=True)
    srv = _ExclusiveHTTPServer((bind_host or host, port), Handler)
    srv.daemon_threads = True
    st = State(cfg, host, port)
    st.discovery = discovery
    srv.state = st  # type: ignore[attr-defined]
    return srv


def print_banner(host: str, port: int, cfg: dict, discovery_on: bool) -> None:
    print("=" * 78)
    print("  NfcTapLink 电脑端接收服务  v" + PRODUCT_VERSION + " / " + PROTOCOL + " (" + VERSION + ")")
    print("=" * 78)
    print(f"  状态页        http://{host}:{port}/")
    print(f"  设备 ID       {cfg['device_id']}")
    print(f"  可达地址      {', '.join(DISC.local_addresses())}")
    print(f"  自动发现      {'开启' if discovery_on else '关闭'}")
    print(f"  NFC 标签 URI  <hidden: 含配对密钥，请用 --paircode 在本机查看>")
    print(f"  浏览器上传URL <hidden: 含配对密钥，请用 --paircode 在本机查看>")
    print(f"  配对密钥      <hidden: 64 hex，仅本机 config.json / 物理标签>")
    print(f"  保存目录      {RECEIVED_DIR}")
    print(f"  单文件上限    {MAX_UPLOAD_LABEL}；会话有效期 {TOKEN_TTL // 60} 分钟")
    print("  安全：安装包不含密钥；k 不上网；双向认证 + 加密上传")
    print("  按 Ctrl+C 停止")
    print("=" * 78)


def seal_upload(cfg: dict, server_nonce: str, client_nonce: str, token: str,
                ts: int, nonce: str, name: str, data: bytes) -> bytes:
    """构造 v3 上传载荷。供自测、回归脚本与浏览器/手机端算法交叉验证。"""
    name_b = name.encode("utf-8")
    if len(name_b) > 255:
        cut = 255
        while cut > 0 and (name_b[cut] & 0xC0) == 0x80:
            cut -= 1
        name_b = name_b[:cut]
        name = name_b.decode("utf-8")
    enc_key, mac_key = derive_keys(cfg, server_nonce, client_nonce, token,
                                   ts, nonce, name, len(data))
    ks = keystream(enc_key, len(data))
    cipher = bytes(a ^ b for a, b in zip(data, ks))
    aad = upload_aad(token, ts, nonce, name, len(cipher))
    tag = hmac.new(mac_key, aad + cipher, hashlib.sha256).digest()
    return b"NT3" + bytes([len(name_b)]) + name_b + tag + cipher


def selftest(host: str, port: int) -> int:
    """本机端到端自测：挑战应答 → 有状态 token → 加密上传 → 防重放。"""
    import base64
    import http.client

    cfg = load_or_create_config()
    srv = make_server("127.0.0.1", port, cfg, bind_host="127.0.0.1")
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    time.sleep(0.2)
    results: list[tuple[str, bool, str]] = []

    def req(method: str, path: str, body: bytes | None = None,
            headers: dict | None = None) -> tuple[int, dict, dict]:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=8)
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse()
        raw = r.read()
        hdr = {k.lower(): v for k, v in r.getheaders()}
        c.close()
        try:
            return r.status, json.loads(raw), hdr
        except json.JSONDecodeError:
            return r.status, {"raw": raw[:200].decode("utf-8", "replace")}, hdr

    try:
        code, obj, hdr = req("GET", "/api/info")
        results.append(("服务可探测", code == 200 and obj.get("ok") is True, str(obj)[:100]))
        results.append(("CSP 响应头", "content-security-policy" in hdr, str(hdr.get("content-security-policy", ""))))
        code, obj, _ = req("GET", "/api/info", headers={"Host": "evil.example.com"})
        results.append(("伪造 Host 被拒", code == 403, str(obj)[:100]))
        code, obj, _ = req("GET", "/api/recent")
        results.append(("未鉴权 recent 被拒", code == 401, str(obj)[:100]))
        code, obj, _ = req("GET", "/api/discover")
        results.append(("discover 不含签名公告", code == 200 and "sig" not in obj
                        and "announce" not in obj, str(obj)[:120]))

        code, obj, _ = req("GET", "/api/challenge")
        sn = obj.get("server_nonce", "")
        did = obj.get("device_id", "")
        results.append(("取到 challenge", code == 200 and bool(sn) and did == cfg["device_id"],
                        str(obj)[:120]))
        cn = secrets.token_hex(16)
        k = key_bytes(cfg)
        proof = hmac.new(k, f"client|{sn}|{cn}|{did}".encode(), hashlib.sha256).hexdigest()
        body = json.dumps({"server_nonce": sn, "client_nonce": cn,
                           "device_id": did, "proof": proof}).encode()
        code, obj, _ = req("POST", "/api/pair", body,
                           {"Content-Type": "application/json"})
        token = obj.get("token", "")
        sp = obj.get("server_proof", "")
        want_sp = hmac.new(k, f"server|{sn}|{cn}|{token}".encode(), hashlib.sha256).hexdigest()
        results.append(("双向配对成功", code == 200 and bool(token)
                        and hmac.compare_digest(sp, want_sp), str(obj)[:140]))
        bad_body = json.dumps({"server_nonce": sn, "client_nonce": cn,
                               "device_id": did, "proof": "00" * 32}).encode()
        code, obj, _ = req("POST", "/api/pair", bad_body,
                           {"Content-Type": "application/json"})
        results.append(("错误 proof 被拒", code == 401, str(obj)[:100]))
        _k = b"selftest-key" * 3
        _ref = hmac.new(_k, b"KS|" + (0).to_bytes(8, "big"),
                        hashlib.sha256).digest()
        _got = next(iter(keystream_blocks(_k, 32)))
        results.append(("密钥流与 HMAC 参考实现一致", _got == _ref,
                        _got.hex()[:16]))

        text = f"自测说明 {time.time_ns()}".encode("utf-8")
        name = "自测说明.txt"
        nonce = secrets.token_hex(12)
        ts = int(time.time())
        envelope = seal_upload(cfg, sn, cn, token, ts, nonce, name, text)
        h = {"Authorization": "Bearer " + token, "Content-Type": "application/octet-stream",
             "X-Nonce": nonce, "X-Ts": str(ts)}
        code, obj, _ = req("POST", "/api/upload", envelope, h)
        results.append(("加密文件按扩展名接收",
                        code == 200 and obj.get("ok") and obj.get("file", "").endswith(".txt"),
                        str(obj)[:160]))
        code, obj, _ = req("POST", "/api/upload", envelope, h)
        results.append(("nonce 重放被拒", code == 401, str(obj)[:100]))
        code, obj, _ = req("POST", "/api/upload", b"not-encrypted",
                           {"Authorization": "Bearer " + token,
                            "Content-Type": "application/octet-stream",
                            "X-Nonce": secrets.token_hex(12),
                            "X-Ts": str(int(time.time()))})
        results.append(("明文上传被拒", code == 400 and obj.get("error") == "加密载荷格式错误",
                        str(obj)[:100]))
        tampered = bytearray(envelope)
        tampered[-1] ^= 1
        code, obj, _ = req("POST", "/api/upload", bytes(tampered),
                           {"Authorization": "Bearer " + token,
                            "Content-Type": "application/octet-stream",
                            "X-Nonce": secrets.token_hex(12), "X-Ts": str(int(time.time()))})
        results.append(("密文篡改被拒", code == 401, str(obj)[:100]))

        # 危险扩展名一律降级 .bin（白名单之外）
        evil_name = "poc.html"
        evil = b"<script>alert(1)</script>"
        nonce2 = secrets.token_hex(12)
        ts2 = int(time.time())
        env2 = seal_upload(cfg, sn, cn, token, ts2, nonce2, evil_name, evil)
        h2 = {"Authorization": "Bearer " + token, "Content-Type": "application/octet-stream",
              "X-Nonce": nonce2, "X-Ts": str(ts2)}
        code, obj, _ = req("POST", "/api/upload", env2, h2)
        results.append(("未知/危险扩展名降级 .bin",
                        code == 200 and obj.get("file", "").endswith(".bin"), str(obj)[:160]))

        # 状态页转义：日志里注入 HTML，页面不应原样输出
        entry = {"ts": "2026-11-14T12:00:00", "result": "saved",
                 "file": "a<img src=x onerror=alert(1)>.txt", "bytes": 1,
                 "mime": "text/plain", "from": "127.0.0.1"}
        append_log(entry)
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=8)
        c.request("GET", "/")
        r = c.getresponse()
        page = r.read().decode("utf-8", "replace")
        c.close()
        results.append(("状态页 HTML 转义", "<img src=x" not in page
                        and "&lt;img" in page, "escaped"))

        # PNG magic 图片落盘（1x1 合法 PNG）
        png = base64.b64decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")
        png_name = f"自测图片-{int(time.time_ns())}.png"
        nonce3 = secrets.token_hex(12)
        ts3 = int(time.time())
        env3 = seal_upload(cfg, sn, cn, token, ts3, nonce3, png_name, png)
        h3 = {"Authorization": "Bearer " + token, "Content-Type": "application/octet-stream",
              "X-Nonce": nonce3, "X-Ts": str(ts3)}
        code, obj, _ = req("POST", "/api/upload", env3, h3)
        results.append(("合法 PNG 图片落盘",
                        code == 200 and obj.get("file", "").endswith(".png"), str(obj)[:160]))
        # 多块流式上传：2.5MB 且末块非 32B 对齐，验证密钥流分块与临时文件 rename。
        big = (b"NfcTapLink-stream-" * 160000)[:UPLOAD_CHUNK * 2 + 123]
        nonce4 = secrets.token_hex(12)
        ts4 = int(time.time())
        env4 = seal_upload(cfg, sn, cn, token, ts4, nonce4, "大文件自检.bin", big)
        h4 = {"Authorization": "Bearer " + token, "Content-Type": "application/octet-stream",
              "X-Nonce": nonce4, "X-Ts": str(ts4)}
        code, obj, _ = req("POST", "/api/upload", env4, h4)
        # 重复跑自测会命中内容去重；duplicate 时同样校验既有文件字节一致。
        big_ok = code == 200 and obj.get("ok") and obj.get("sha256") == hashlib.sha256(big).hexdigest()
        if big_ok:
            saved = RECEIVED_DIR / obj["file"]
            big_ok = saved.exists() and saved.read_bytes() == big
        results.append(("多块流式上传字节一致", big_ok, str(obj)[:160]))

        # 反向发送：暂存 -> outbox -> 加密下载 -> claimed -> 幂等拒绝。
        src4 = DATA_DIR / ("反向自测-" + str(time.time_ns()) + ".txt")
        src4.write_bytes(f"reverse-send test {time.time_ns()}".encode("utf-8"))
        meta4 = stage_outbox(src4)
        code, obj, _ = req("GET", "/api/outbox", None,
                           {"Authorization": "Bearer " + token})
        pending = obj.get("pending") if isinstance(obj.get("pending"), dict) else {}
        results.append(("反向发送 outbox 探测到待发文件",
                        code == 200 and obj.get("ok") and obj.get("reverse_send")
                        and pending.get("id") == meta4["id"]
                        and pending.get("name") == meta4["name"],
                        str(obj)[:160]))
        nonce5 = secrets.token_hex(12)
        ts5 = int(time.time())
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=8)
        c.request("GET", f"/api/download?id={meta4['id']}",
                  headers={"Authorization": "Bearer " + token,
                           "X-Nonce": nonce5, "X-Ts": str(ts5)})
        r = c.getresponse()
        body5 = r.read()
        oid5 = r.getheader("X-Outbox-Id")
        c.close()
        plain5 = None
        name5 = ""
        if r.status == 200 and oid5 == meta4["id"]:
            name_len5 = body5[3]
            name5 = body5[4:4 + name_len5].decode("utf-8")
            tag5 = body5[4 + name_len5:4 + name_len5 + 32]
            cipher5 = body5[4 + name_len5 + 32:]
            enc5, mac5, aad5 = download_keys(
                cfg, sn, cn, token, ts5, nonce5, meta4["id"], name5, len(cipher5))
            want5 = hmac.new(mac5, aad5 + cipher5, hashlib.sha256).digest()
            if hmac.compare_digest(tag5, want5):
                ks5 = keystream(enc5, len(cipher5))
                plain5 = bytes(a ^ b for a, b in zip(cipher5, ks5))
        want_sha5 = hashlib.sha256(src4.read_bytes()).hexdigest()
        got_sha5 = hashlib.sha256(plain5 or b"").hexdigest()
        results.append(("反向发送加密下载且内容一致",
                        plain5 is not None and got_sha5 == want_sha5
                        and name5 == meta4["name"], str(r.status)))
        code, obj, _ = req("GET", f"/api/download?id={meta4['id']}", None,
                           {"Authorization": "Bearer " + token,
                            "X-Nonce": secrets.token_hex(12),
                            "X-Ts": str(int(time.time()))})
        results.append(("同一待发文件二次下载被拒",
                        code == 409, str(obj)[:100]))
        code, obj, _ = req("GET", "/api/outbox", None,
                           {"Authorization": "Bearer " + token})
        results.append(("接收后 outbox 不再展示待发送",
                        code == 200 and not obj.get("pending"), str(obj)[:120]))
        results.append(("单文件上限为 1 GB",
                        MAX_UPLOAD == 1024 ** 3 and MAX_UPLOAD_LABEL == "1 GB",
                        f"{MAX_UPLOAD_LABEL} / {MAX_UPLOAD} 字节"))
        src4.unlink(missing_ok=True)

        # 日志轮转：临时降低阈值写两条，确认 .1 生成且 read_recent 能跨文件回看。
        old_max = LOG_MAX_BYTES
        try:
            globals()["LOG_MAX_BYTES"] = 1
            append_log({"ts": "2026-11-14T00:00:00", "result": "saved",
                        "file": "轮转前.logtest", "bytes": 1, "mime": "text/plain",
                        "from": "127.0.0.1"})
            append_log({"ts": "2026-11-14T00:00:01", "result": "saved",
                        "file": "轮转后.logtest", "bytes": 1, "mime": "text/plain",
                        "from": "127.0.0.1"})
            rotated = LOG_PATH.with_name(LOG_PATH.name + ".1").exists()
            names = [it.get("file") for it in read_recent(10)]
            results.append(("日志轮转且可跨档回看",
                            rotated and "轮转前.logtest" in names
                            and "轮转后.logtest" in names, str(names[:3])))
        finally:
            globals()["LOG_MAX_BYTES"] = old_max

        code, obj, _ = req("GET", "/api/recent", headers={"Authorization": "Bearer " + token})
        results.append(("带 token 可查 recent", code == 200 and obj.get("ok"), str(obj)[:100]))
    finally:
        srv.shutdown()
        srv.server_close()

    print("\n=== v3 端到端自测结果 ===")
    for name, ok, detail in results:
        print(f"  [{'通过' if ok else '失败'}] {name}  {detail}")
    passed = sum(1 for _, ok, _ in results if ok)
    print(f"  ---- {passed}/{len(results)} 通过 ----\n")
    return 0 if passed == len(results) else 1


def discovery_selftest() -> int:
    """本机 UDP 发现往返自测（不起 HTTP 服务）。"""
    cfg = load_or_create_config()
    svc = DISC.DiscoveryService(cfg, DEFAULT_PORT, on_event=lambda m: print("[发现]", m))
    svc.start()
    time.sleep(0.5)
    try:
        replies = DISC.query_once(cfg["device_id"], timeout=1.5)
        ok = any(isinstance(obj, dict) and obj.get("id") == cfg["device_id"]
                 for obj, _ in replies)
        print(f"发现自测：收到 {len(replies)} 条公告，设备 ID 匹配={ok}")
        return 0 if ok else 1
    finally:
        svc.stop()


def main() -> int:
    ap = argparse.ArgumentParser(description="NfcTapLink 电脑端接收服务 v3")
    ap.add_argument("--host", default=None, help="对外广告地址，默认自动探测局域网 IP")
    ap.add_argument("--bind", default=None, help="实际监听地址，默认 0.0.0.0")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--paircode", action="store_true", help="打印标签 URI 与浏览器 URL 后退出")
    ap.add_argument("--rotate", action="store_true", help="轮换配对密钥（旧标签立即失效）")
    ap.add_argument("--rotate-quiet", action="store_true",
                    help="轮换配对密钥但不打印含密钥的 URI（供自动化调用）")
    ap.add_argument("--selftest", action="store_true", help="本机端到端自测")
    ap.add_argument("--discovery-selftest", action="store_true", help="UDP 发现自测")
    ap.add_argument("--no-discovery", action="store_true", help="关闭 UDP 自动发现")
    ap.add_argument("--no-ble", action="store_true", help="关闭 BLE 广播发现")
    ap.add_argument("--hotspot", action="store_true", help="启动时开启 Windows 移动热点")
    ap.add_argument("--hotspot-restore", action="store_true", help="退出时恢复热点原状态")
    ap.add_argument("--hotspot-info", action="store_true", help="只读打印热点状态后退出")
    args = ap.parse_args()

    cfg = load_or_create_config()
    host = args.host or guess_lan_ip()

    if args.discovery_selftest:
        return discovery_selftest()
    if args.rotate or args.rotate_quiet:
        cfg = rotate_pair_key()
        if not args.rotate_quiet:
            print(f"新标签 URI：{build_pair_uri(cfg)}")
            print(f"新浏览器 URL：{build_tap_url(host, args.port)}")
            print("  浏览器打开后，在页面输入框手动粘贴标签 URI 中的 k=（不再通过 URL 传递）。")
        print("  已轮换本机配对密钥；device_id 已变化，旧标签必须重写，运行中的服务需重启。")
        return 0
    if args.paircode:
        print(build_pair_uri(cfg))
        print(build_tap_url(host, args.port))
        print("  浏览器方案：打开上面的 URL，在页面输入框手动粘贴标签 URI 中的 k=。")
        return 0
    if args.selftest:
        return selftest(host, args.port + 1)

    hotspot = None
    if args.hotspot or args.hotspot_restore or args.hotspot_info:
        try:
            from hotspot import HotspotController
            hotspot = HotspotController(on_event=lambda m: print(m))
        except Exception as e:
            print(f"[热点] 不可用：{e!r}")
            hotspot = None
    if args.hotspot_info:
        if hotspot:
            print(json.dumps(hotspot.info(), ensure_ascii=False, indent=2))
        return 0
    if args.hotspot and hotspot:
        r = hotspot.start()
        if not r.get("ok"):
            print(f"[热点] 未能开启：{r}，继续以现有网络运行")

    discovery_on = not args.no_discovery
    svc = None
    if discovery_on:
        svc = DISC.DiscoveryService(cfg, args.port,
                                    on_event=lambda m: print(f"[发现] {m}"))
        svc.start()

    ble = None
    if not args.no_ble:
        try:
            from ble_announcer import BleAnnouncer
            ble = BleAnnouncer(cfg, args.port, DISC.local_addresses,
                               on_event=lambda m: print(f"[BLE] {m}"))
            ble.start()
        except Exception as e:
            print(f"[BLE] 广播不可用：{e!r}")
            ble = None

    bind = args.bind or ("0.0.0.0" if discovery_on else host)
    try:
        srv = make_server(host, args.port, cfg, bind_host=bind, discovery=svc)
    except OSError as e:
        print(f"[错误] 无法监听 {bind}:{args.port} -> {e}")
        if svc:
            svc.stop()
        if ble:
            ble.stop()
        return 1
    srv.state.ble = ble          # type: ignore[attr-defined]
    srv.state.hotspot = hotspot  # type: ignore[attr-defined]
    print_banner(host, args.port, cfg, discovery_on)
    print(f"  BLE 广播      {'开启' if ble else '关闭/不可用'}")
    print(f"  移动热点      {hotspot.status() if hotspot else '未启用'}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[停止] 服务已关闭")
    finally:
        srv.server_close()
        if svc:
            svc.stop()
        if ble:
            ble.stop()
        if hotspot and args.hotspot_restore:
            hotspot.restore()
    return 0


if __name__ == "__main__":
    sys.exit(main())
