# -*- coding: utf-8 -*-
"""NfcTapLink · BLE 广播发现（电脑端，WinRT BluetoothLEAdvertisementPublisher）。

为什么需要它：UDP 组播/广播不跨 /24，两端落在不同网段时（如 192.168.1.x 与 192.168.2.x）
单播互通但组播增量为 0。BLE 广播不依赖 IP 网络，可跨网段、跨 AP 隔离。
BLE 只做发现，文件仍走局域网 HTTP。

广播载荷（ManufacturerData，CompanyId 0xFFFE，24 B）：
  0-1   magic        b"NT"
  2-9   device_id    8 B（sha256(pair_key)[:16] 的前 8 字节）
  10-13 IPv4         4 B
  14-15 port         2 B 大端
  16-19 ts           4 B unix 秒（低位）
  20-23 reserved     4 B（v3 起不再放签名）

v3 安全边界：BLE 广播是公开的、无签名，只作候选地址提示。
手机端先按 device_id / 时间粗筛，再用 /api/pair 的 server_proof 做真正认证。

状态判定（6.0.1 起）：
  - 以 publisher.status 为准：Started 才算「已开启」，Waiting 表示蓝牙被关，
    广播会一直等下，用户打开蓝牙后自动恢复；
  - 单次启动/刷新失败不再永久判死：后台按 3 s → 6 s → … → 30 s 退避重试；
  - 刷新失败时若旧广播仍在跑，保留旧广播，只在日志里记一笔；
  - 失败原因分类成 winrt_missing / no_ipv4 / no_adapter / radio_off /
    no_peripheral / start_failed，界面据此给一句原因 + 一句建议。

依赖：winrt-Windows.Devices.Bluetooth / winrt-Windows.Devices.Bluetooth.Advertisement
/ winrt-Windows.Storage.Streams（Python 3.13 用 winrt-* 分包）。
"""
from __future__ import annotations

import hashlib
import struct
import threading
import time
from typing import Callable

COMPANY_ID = 0xFFFE
MAGIC = b"NT"
PAYLOAD_LEN = 24
REFRESH_INTERVAL = 20   # 秒，重建广播以刷新时间戳与 IP
RETRY_MIN = 3.0         # 启动失败后的首次重试间隔
RETRY_MAX = 30.0        # 重试间隔上限

# 失败原因 → (一句原因, 一句建议)。界面直接用这两句，不堆技术名词。
REASONS: dict[str, tuple[str, str]] = {
    "winrt_missing": ("系统缺少蓝牙组件",
                      "重新运行安装包修复安装；局域网发现仍可正常使用"),
    "no_ipv4": ("没有可用的局域网地址",
                "先连上 Wi-Fi 或有线网络，再重新开启服务"),
    "no_adapter": ("没有找到蓝牙适配器",
                   "确认电脑的蓝牙已打开；没有蓝牙时可继续用局域网发现"),
    "radio_off": ("蓝牙已关闭",
                  "在系统设置里打开蓝牙，广播会自动恢复"),
    "no_peripheral": ("这台电脑的蓝牙不支持广播",
                      "换一个支持广播的蓝牙适配器；局域网发现仍可正常使用"),
    "start_failed": ("蓝牙广播启动失败",
                     "重启程序或蓝牙驱动后再试；局域网发现仍可正常使用"),
    "starting": ("正在启动蓝牙广播", "请稍候，通常一两秒内完成"),
    "stopped": ("蓝牙广播已停止", "重新开启接收服务即可恢复"),
}

_STATUS_NAMES = {0: "Created", 1: "Waiting", 2: "Started",
                 3: "Stopping", 4: "Stopped", 5: "Aborted"}


def build_payload(cfg: dict, ip: str, port: int) -> bytes:
    """构造 24 字节无签名广播载荷。v3 身份由 /api/pair 证明，不靠 BLE。"""
    did = cfg.get("device_id") or hashlib.sha256(
        bytes.fromhex(cfg["pair_key"])).hexdigest()[:16]
    dev = bytes.fromhex(did)
    ipb = bytes(int(x) for x in ip.split("."))
    body = (MAGIC + dev + ipb + struct.pack(">H", port)
            + struct.pack("<I", int(time.time()) & 0xFFFFFFFF))
    assert len(body) == 20, len(body)
    return body + b"\x00\x00\x00\x00"


def parse_payload(data: bytes, max_age: int = 60):
    """解析广播载荷并校验新鲜度，返回 dict 或 None。不做身份判断。"""
    if len(data) != PAYLOAD_LEN or data[:2] != MAGIC:
        return None
    body = data[:20]
    ts = struct.unpack("<I", body[16:20])[0]
    age = int(time.time()) & 0xFFFFFFFF
    if age - ts > max_age:
        return None
    return {
        "device_id": body[2:10].hex(),
        "ip": ".".join(str(b) for b in body[10:14]),
        "port": struct.unpack(">H", body[14:16])[0],
        "ts": ts,
    }


def _brief(err: BaseException, limit: int = 160) -> str:
    """把异常压成一行人能读的摘要，避免界面被堆栈撑爆。"""
    text = f"{type(err).__name__}: {err}".replace("\r", " ").replace("\n", " ")
    return text[:limit]


class BleAnnouncer:
    """常驻 BLE 广播；对象必须被持有，否则 WinRT publisher 会被回收。"""

    def __init__(self, cfg: dict, port: int,
                 ips_fn: Callable[[], list[str]],
                 on_event: Callable[[str], None] | None = None):
        self.cfg = cfg
        self.port = port
        self.ips_fn = ips_fn
        self.log = on_event or (lambda _s: None)
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self.pub = None
        self.started_at = 0.0
        self._reason = "starting"      # 最近一次失败原因
        self._detail = ""              # 原始错误摘要
        self._retrying = False
        self._next_delay = RETRY_MIN

    # ------------------------------------------------------------------
    # 对外状态
    # ------------------------------------------------------------------
    def _status_name(self, pub=None) -> str:
        pub = self.pub if pub is None else pub
        if pub is None:
            return ""
        try:
            return _STATUS_NAMES.get(int(pub.status), str(pub.status))
        except Exception:
            return ""

    def _evaluate(self) -> tuple[bool, str, str]:
        """只认 publisher 的真实状态；没起来时才用记录下来的失败原因。"""
        if self.pub is None:
            return False, (self._reason or "starting"), self._detail
        st = self._status_name()
        if st == "Started":
            return True, "", ""
        if st == "Waiting":
            return False, "radio_off", ""
        if st in ("Created", "Stopping"):
            return False, self._reason or "starting", self._detail
        return False, self._reason or "start_failed", self._detail

    @property
    def alive(self) -> bool:
        with self._lock:
            return self._evaluate()[0]

    def snapshot(self) -> dict:
        """给界面/自检用的一份完整状态，随时可读，不会阻塞。"""
        with self._lock:
            alive, reason, detail = self._evaluate()
            status = self._status_name()
            retrying = self._retrying
            started_at = self.started_at
        short, advice = REASONS.get(reason, ("", ""))
        return {
            "enabled": True,
            "alive": alive,
            "reason": reason,
            "reason_text": short,
            "advice": advice,
            "detail": detail,
            "status": status,
            "retrying": retrying,
            "started_at": started_at,
        }

    # ------------------------------------------------------------------
    # WinRT 调用
    # ------------------------------------------------------------------
    def _make(self, ip: str):
        from winrt.windows.devices.bluetooth.advertisement import (
            BluetoothLEAdvertisementPublisher, BluetoothLEManufacturerData)
        from winrt.windows.storage.streams import DataWriter

        payload = build_payload(self.cfg, ip, self.port)
        dw = DataWriter()
        dw.write_bytes(payload)
        md = BluetoothLEManufacturerData()
        md.company_id = COMPANY_ID
        md.data = dw.detach_buffer()

        pub = BluetoothLEAdvertisementPublisher()
        pub.advertisement.manufacturer_data.append(md)
        pub.start()
        return pub

    def _probe_adapter(self, timeout: float = 3.0) -> dict:
        """在线程里查适配器与外设角色能力，带硬超时，绝不卡住界面。"""
        res: dict = {}

        def work():
            try:
                import asyncio
                from winrt.windows.devices.bluetooth import BluetoothAdapter

                async def go():
                    return await BluetoothAdapter.get_default_async()

                adapter = asyncio.run(go())
                res["adapter"] = adapter
                res["peripheral"] = (bool(adapter.is_peripheral_role_supported)
                                     if adapter is not None else False)
            except Exception as e:       # WinRT 不可用 / 驱动异常
                res["error"] = e

        t = threading.Thread(target=work, daemon=True, name="nfctap-ble-probe")
        t.start()
        t.join(timeout)
        if t.is_alive():
            res["timeout"] = True
        return res

    def _classify(self, err: BaseException) -> tuple[str, str]:
        """把启动异常归到用户能理解的原因上。"""
        if isinstance(err, ImportError):
            return "winrt_missing", _brief(err)
        probe = self._probe_adapter()
        if probe.get("timeout") or probe.get("error"):
            return "start_failed", _brief(err)
        if probe.get("adapter") is None:
            return "no_adapter", _brief(err)
        if not probe.get("peripheral"):
            return "no_peripheral", _brief(err)
        return "start_failed", _brief(err)

    # ------------------------------------------------------------------
    # 后台循环
    # ------------------------------------------------------------------
    def _set_error(self, reason: str, detail: str):
        with self._lock:
            self._reason, self._detail = reason, detail

    def _drop_pub(self, reason: str, detail: str):
        old = self.pub
        with self._lock:
            self.pub = None
            self._reason, self._detail = reason, detail
            self.started_at = 0.0
        if old is not None:
            try:
                old.stop()
            except Exception:
                pass

    def _try_start(self) -> bool:
        try:
            ips = self.ips_fn() or []
        except Exception as e:
            self._set_error("no_ipv4", _brief(e))
            self.log(f"BLE 未启动：读取本机地址失败（{_brief(e)}）")
            return False
        if not ips:
            self._set_error("no_ipv4", "")
            self.log("BLE 未启动：没有可用的局域网 IPv4")
            return False

        ip = ips[0]
        try:
            pub = self._make(ip)
        except Exception as e:
            reason, detail = self._classify(e)
            self._set_error(reason, detail)
            short, advice = REASONS[reason]
            self.log(f"BLE 未启动：{short}（{detail}）。建议：{advice}")
            return False

        # 给 WinRT 一点时间把状态从 Created 推进到 Started / Waiting。
        deadline = time.time() + 0.6
        while time.time() < deadline and not self._stop.is_set():
            if self._status_name(pub) in ("Waiting", "Started", "Stopped", "Aborted"):
                break
            time.sleep(0.05)

        st = self._status_name(pub)
        if st in ("Stopped", "Aborted") or st == "":
            try:
                pub.stop()
            except Exception:
                pass
            reason, detail = self._classify(
                RuntimeError(f"publisher.status={st or 'unknown'}"))
            self._set_error(reason, detail)
            short, advice = REASONS[reason]
            self.log(f"BLE 未启动：{short}（{detail}）。建议：{advice}")
            return False

        with self._lock:
            self.pub = pub
            self.started_at = time.time()
            self._reason, self._detail = "", ""
        # 状态可能先短暂停在 Waiting 再进 Started，多等一会儿再下结论。
        st = self._status_name()
        deadline = time.time() + 0.4
        while st == "Waiting" and time.time() < deadline:
            time.sleep(0.05)
            st = self._status_name()
        if st == "Waiting":
            self.log("蓝牙广播等待蓝牙打开：广播已就绪，打开蓝牙后自动开始")
        else:
            self.log(f"BLE 广播已启动：CompanyId=0x{COMPANY_ID:04X}、"
                     f"IP={ip}:{self.port}、载荷 {PAYLOAD_LEN} B")
        return True

    def _refresh(self):
        try:
            ips = self.ips_fn() or []
        except Exception:
            ips = []
        if not ips:
            self.log("局域网地址消失，暂停蓝牙广播，恢复后自动重试")
            self._drop_pub("no_ipv4", "")
            return

        old = self.pub
        try:
            new = self._make(ips[0])
        except Exception as e:
            if self._status_name(old) == "Started":
                # 关键：旧广播还在跑就不算不可用，等下个周期再试。
                self.log(f"BLE 刷新失败，保留当前广播（{_brief(e)}）")
                return
            reason, detail = self._classify(e)
            self._drop_pub(reason, detail)
            short, advice = REASONS[reason]
            self.log(f"BLE 广播中断：{short}（{detail}）。建议：{advice}")
            return

        with self._lock:
            self.pub = new
            self._reason, self._detail = "", ""
        try:
            old.stop()
        except Exception:
            pass
        self.log(f"BLE 广播已刷新：IP={ips[0]} ts={int(time.time())}")

    def _run(self):
        backoff = RETRY_MIN
        while not self._stop.is_set():
            if self.pub is None:
                if not self._try_start():
                    with self._lock:
                        self._retrying = True
                    if self._stop.wait(backoff):
                        break
                    backoff = min(RETRY_MAX, max(RETRY_MIN, backoff * 2))
                    continue
                with self._lock:
                    self._retrying = False
                backoff = RETRY_MIN

            if self._status_name() == "Waiting":
                # 蓝牙关着时 publisher 会一直等，不重建，打开后自动生效。
                if self._stop.wait(5):
                    break
                continue

            if self._stop.wait(REFRESH_INTERVAL):
                break
            self._refresh()

        old = self.pub
        with self._lock:
            self.pub = None
            self._reason, self._detail = "stopped", ""
        if old is not None:
            try:
                old.stop()
            except Exception:
                pass
        self.log("BLE 广播已停止")

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="nfctap-ble")
        self._thread.start()

    def stop(self, timeout: float = 3.0):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=timeout)
        old = self.pub
        if old is not None:
            try:
                old.stop()
            except Exception:
                pass
        with self._lock:
            self.pub = None
            self._reason, self._detail = "stopped", ""


if __name__ == "__main__":
    import json
    import sys
    from pathlib import Path
    from discovery import local_addresses

    cfg = json.loads((Path(__file__).resolve().parent / "config.json")
                     .read_text(encoding="utf-8"))
    if len(sys.argv) > 1 and sys.argv[1] == "selftest":
        p = build_payload(cfg, "192.168.1.10", 8765)
        print("载荷长度", len(p), "hex", p.hex())
        r = parse_payload(p)
        print("解析", r)
        assert r and r["ip"] == "192.168.1.10" and r["port"] == 8765
        assert p[20:] == b"\x00\x00\x00\x00"
        print("自测通过：v3 无签名广播，身份交由 /api/pair 校验")
        sys.exit(0)

    a = BleAnnouncer(cfg, 8765, local_addresses,
                     on_event=lambda m: print("[BLE]", m))
    a.start()
    try:
        while True:
            time.sleep(2)
            print("状态", a.snapshot())
    except KeyboardInterrupt:
        a.stop()
