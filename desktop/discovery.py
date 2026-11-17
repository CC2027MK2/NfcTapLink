# -*- coding: utf-8 -*-
"""NfcTapLink 自动发现协议（nfctap-discovery/3）。

设计目标：去掉标签里写死的 IP，让手机在任意局域网里自动找到电脑。

v3 安全边界（重要）：
  - 公告**没有签名**，也不再声称证明电脑身份。它只是「某台自称这个
    device_id 的主机在这些 IP 上」的候选提示。
  - device_id = sha256(pair_key)[:16] 是公开标识，写在标签里，不是机密。
  - 攻击者可以伪造公告/假 /api/ping，但拿不到标签里的 k，算不出
    /api/pair 的 server_proof，手机端会拒绝它，不会把文件交出去。
  - 真正收紧信任靠两步：① 候选地址先用 /api/ping 粗筛 device_id；
    ② /api/pair 做双向 challenge-response，并校验 server_proof。

报文（UTF-8 JSON，单行，<= 1400 B）：
  查询 {"t":"q","v":3,"id":"<device_id 或 *>"}
  公告 {"t":"a","v":3,"id":"...","ips":["192.168.1.10",...],
        "port":8765,"proto":"http","ts":<unix>}

零第三方依赖，只用标准库。
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import re
import socket
import struct
import subprocess
import sys
import threading
import time
from typing import Callable

MCAST_GRP = "224.0.0.167"   # 与 LocalSend 默认值一致，理由见模块注释

# ipconfig 结果缓存：见 _windows_ifaces() 里的说明。
_IFACE_LOCK = threading.Lock()
_IFACE_CACHE: list[tuple[str, str]] | None = None
_IFACE_TS = 0.0
_IFACE_TTL = 10.0
MCAST_PORT = 53317
ANNOUNCE_INTERVAL = 5       # 秒；碰标签是短会话，比 Syncthing 的 30–60 s 更密
MAX_AGE = 30                # 公告有效期（秒），防重放
PROTO_VERSION = 3

# 虚拟网卡 / 链路本地 / 隧道网段，公告里不带，避免手机去连一个到不了的地址
_SKIP_PREFIXES = (
    "127.", "169.254.", "26.26.",
    "192.168.92.", "192.168.229.",   # VMware 默认虚拟网段（VMnet8 / VMnet1）
    "172.17.",                        # Hyper-V 默认虚拟网段（Default Switch）
)


# --------------------------------------------------------------------------
# 身份与报文
# --------------------------------------------------------------------------

def device_id(cfg: dict) -> str:
    """公开设备标识：由本机随机 pair_key 派生，不随 IP / 网段变化。"""
    if "device_id" in cfg:
        return cfg["device_id"]
    return hashlib.sha256(bytes.fromhex(cfg["pair_key"])).hexdigest()[:16]


def canonical(obj: dict) -> bytes:
    """固定字段顺序的序列化，仅用于 UDP 报文确定性编码。"""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def make_announcement(cfg: dict, port: int, ips: list[str] | None = None) -> dict:
    """构造无签名公告。v3 中身份由 /api/pair 的 server_proof 证明。"""
    return {
        "t": "a", "v": PROTO_VERSION,
        "id": device_id(cfg),
        "ips": ips if ips is not None else local_addresses(),
        "port": port, "proto": "http", "ts": int(time.time()),
    }


def verify_announcement(obj: dict, cfg: dict) -> tuple[bool, str]:
    """只校验结构与新鲜度；不把公告当身份证明。"""
    if not isinstance(obj, dict):
        return False, "不是对象"
    if obj.get("t") != "a" or obj.get("v") != PROTO_VERSION:
        return False, "类型或版本不匹配"
    if obj.get("id") != device_id(cfg):
        return False, "设备 ID 不匹配"
    try:
        age = int(time.time()) - int(obj["ts"])
    except (KeyError, ValueError, TypeError):
        return False, "缺少有效时间戳"
    if age < -5 or age > MAX_AGE:
        return False, f"公告已过期（age={age}s）"
    try:
        port = int(obj["port"])
        if not (1 <= port <= 65535):
            raise ValueError
    except (KeyError, ValueError, TypeError):
        return False, "端口非法"
    ips = obj.get("ips")
    if not isinstance(ips, list) or not ips:
        return False, "缺少候选地址列表"
    for ip in ips:
        try:
            ipaddress.IPv4Address(ip)
        except (ipaddress.AddressValueError, TypeError):
            return False, f"非法 IPv4：{ip!r}"
    return True, "ok"


def make_query(target_id: str = "*") -> dict:
    return {"t": "q", "v": PROTO_VERSION, "id": target_id}


# --------------------------------------------------------------------------
# 本机地址枚举
# --------------------------------------------------------------------------

def _windows_ifaces() -> list[tuple[str, str]]:
    """从 ipconfig 解析 (IPv4, 子网掩码)，用于算定向广播地址。

    Windows 标准库拿不到 netmask；本机实测 ipconfig 输出为 GBK，需按 GBK 解码。
    解析失败就返回空列表，调用方会退回全局广播，不影响主流程。

    2026-11-13 冻结版踩坑：PyInstaller --windowed（GUI 子系统）下进程没有控制台，
    subprocess 继承的 stdin/stdio 句柄会让 ipconfig 挂起，表现为 /api/info 超时。
    显式给 stdin=DEVNULL + CREATE_NO_WINDOW，避免创建控制台与无效句柄继承。
    """
    # 2026-11-13 桌面 GUI 踩坑：/api/info 会连调 local_addresses() 与
    # broadcast_addresses()，GUI 每 2 s 又调一次；每次都起一个 ipconfig
    # 子进程，多个请求并发时 3 s 内回不来，表现为 /api/info 超时。
    # GUI 子系统下起子进程的代价尤其高。这里加 10 s TTL 缓存 + 单飞锁，
    # 冷启动只跑一次；网卡变化最多 10 s 后自动生效。
    global _IFACE_CACHE, _IFACE_TS
    now = time.monotonic()
    with _IFACE_LOCK:
        if _IFACE_CACHE is not None and now - _IFACE_TS < _IFACE_TTL:
            return list(_IFACE_CACHE)
    try:
        kw = {"capture_output": True, "timeout": 8,
              "stdin": subprocess.DEVNULL}
        if sys.platform == "win32":
            kw["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        raw = subprocess.run(["ipconfig"], **kw).stdout
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return []
    txt = None
    for enc in ("gbk", "utf-8", "mbcs"):
        try:
            txt = raw.decode(enc)
            break
        except (UnicodeDecodeError, LookupError):
            continue
    if txt is None:
        txt = raw.decode("utf-8", "replace")
    pairs: list[tuple[str, str]] = []
    cur_ip = None
    for line in txt.splitlines():
        m = re.search(r"IPv4[^:：]*[:：]\s*([\d.]+)", line)
        if m:
            cur_ip = m.group(1)
            continue
        m = re.search(r"(?:Subnet Mask|子网掩码)[^:：]*[:：]\s*([\d.]+)", line)
        if m and cur_ip:
            pairs.append((cur_ip, m.group(1)))
            cur_ip = None
    with _IFACE_LOCK:
        _IFACE_CACHE = list(pairs)
        _IFACE_TS = time.monotonic()
    return pairs


def local_addresses(include_virtual: bool = False) -> list[str]:
    """本机所有可通告的 IPv4，按「最可能是真局域网」排序。

    排序依据：先按默认路由出口地址（UDP connect 不发包），再按网卡枚举顺序。
    过滤 loopback / APIPA / 已知虚拟网卡网段。
    """
    ordered: list[str] = []

    def add(ip: str) -> None:
        if ip not in ordered and (include_virtual or not ip.startswith(_SKIP_PREFIXES)):
            ordered.append(ip)

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("223.5.5.5", 80))   # 不发包，只让系统选路由
        add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            add(info[4][0])
    except OSError:
        pass
    for ip, _mask in _windows_ifaces():
        add(ip)
    return ordered


def broadcast_addresses() -> list[str]:
    """每个物理接口的链路定向广播地址；拿不到掩码时用全局广播。"""
    out: list[str] = []
    for ip, mask in _windows_ifaces():
        if ip.startswith(_SKIP_PREFIXES):
            continue
        try:
            net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
            b = str(net.broadcast_address)
            if b not in out:
                out.append(b)
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            continue
    if not out:
        out.append("255.255.255.255")
    return out


# --------------------------------------------------------------------------
# 电脑端发现服务
# --------------------------------------------------------------------------

class DiscoveryService:
    """UDP 组播 + 定向广播的公告 / 应答服务（电脑端常驻，单线程即可）。

    收：任何查询或公告 → 单播回一条完整公告（借鉴 LocalSend 的双向 register，
    但用 UDP 单播，因为手机端此时没有 HTTP server）。
    发：每 ANNOUNCE_INTERVAL 秒，对每个本机接口设 IP_MULTICAST_IF 后发组播，
        再对每个接口发链路定向广播。
    """

    def __init__(self, cfg: dict, port: int,
                 on_event: Callable[[str], None] | None = None):
        self.cfg = cfg
        self.port = port
        self.on_event = on_event or (lambda _s: None)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.sock: socket.socket | None = None
        self.queries = 0
        self.announced = 0

    def _log(self, msg: str) -> None:
        self.on_event(msg)

    def _announcement_bytes(self) -> bytes:
        return canonical(make_announcement(self.cfg, self.port))

    def _open(self) -> socket.socket:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.bind(("", MCAST_PORT))
        for ip in local_addresses(include_virtual=True):
            try:
                s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                             struct.pack("=4s4s", socket.inet_aton(MCAST_GRP),
                                         socket.inet_aton(ip)))
            except OSError:
                pass
        s.settimeout(0.5)
        return s

    def _send_all(self, s: socket.socket) -> None:
        data = self._announcement_bytes()
        ips = local_addresses()
        for ip in ips:
            try:
                s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                             socket.inet_aton(ip))
                s.sendto(data, (MCAST_GRP, MCAST_PORT))
            except OSError:
                pass
        for bcast in broadcast_addresses():
            try:
                s.sendto(data, (bcast, MCAST_PORT))
            except OSError:
                pass
        self.announced += 1
        self._log(f"公告 #{self.announced}：组播 {MCAST_GRP} + 广播 {broadcast_addresses()}，"
                  f"候选地址 {ips}")

    def _run(self) -> None:
        try:
            s = self._open()
        except OSError as e:
            self._log(f"发现服务启动失败：{e}")
            return
        self.sock = s
        self._log(f"发现服务已启动 UDP {MCAST_PORT}，设备 ID {device_id(self.cfg)}")
        last = 0.0
        while not self._stop.is_set():
            now = time.time()
            if now - last >= ANNOUNCE_INTERVAL:
                self._send_all(s)
                last = now
            try:
                data, addr = s.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                obj = json.loads(data.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                continue
            if not isinstance(obj, dict) or obj.get("v") != PROTO_VERSION:
                continue
            # 只响应查询；对别人的公告不回复，避免组播风暴。
            if obj.get("t") != "q":
                continue
            want = obj.get("id", "*")
            if want not in ("*", device_id(self.cfg)):
                continue
            self.queries += 1
            try:
                s.sendto(self._announcement_bytes(), addr)
                self._log(f"收到查询 #{self.queries} 来自 {addr[0]}:{addr[1]}，已单播应答")
            except OSError:
                pass
        try:
            for ip in local_addresses(include_virtual=True):
                try:
                    s.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP,
                                 struct.pack("=4s4s", socket.inet_aton(MCAST_GRP),
                                             socket.inet_aton(ip)))
                except OSError:
                    pass
        finally:
            s.close()
        self._log("发现服务已停止")

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="nfctap-discovery")
        self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=timeout)


def query_once(target_id: str = "*", timeout: float = 1.5) -> list[tuple[dict, tuple]]:
    """发一次查询并收集应答（供本机自测 / 诊断用）。

    真实手机端在 Android 里实现同样逻辑：MulticastLock + DatagramSocket。
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.settimeout(0.4)
    try:
        s.bind(("", 0))
        data = canonical(make_query(target_id))
        for ip in local_addresses():
            try:
                s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                             socket.inet_aton(ip))
                s.sendto(data, (MCAST_GRP, MCAST_PORT))
            except OSError:
                pass
        for bcast in broadcast_addresses():
            try:
                s.sendto(data, (bcast, MCAST_PORT))
            except OSError:
                pass
        out: list[tuple[dict, tuple]] = []
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                raw, addr = s.recvfrom(2048)
                obj = json.loads(raw.decode("utf-8"))
                if isinstance(obj, dict):
                    out.append((obj, addr))
            except socket.timeout:
                continue
            except (ValueError, UnicodeDecodeError):
                continue
        return out
    finally:
        s.close()


if __name__ == "__main__":
    import sys
    from pathlib import Path
    cfg_path = Path(__file__).resolve().parent / "config.json"
    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    if len(sys.argv) > 1 and sys.argv[1] == "query":
        print("设备 ID:", device_id(cfg))
        print("本机地址:", local_addresses())
        print("广播地址:", broadcast_addresses())
        replies = query_once()
        print(f"收到 {len(replies)} 条应答")
        for obj, addr in replies:
            print(" ", addr, verify_announcement(obj, cfg), obj.get("ips"))
    else:
        svc = DiscoveryService(cfg, 8765, on_event=lambda m: print("[发现]", m))
        svc.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            svc.stop()
