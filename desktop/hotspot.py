# -*- coding: utf-8 -*-
"""NfcTapLink · Windows 移动热点自动化（WinRT NetworkOperatorTetheringManager）。

用途：当 UDP 组播 / BLE / 缓存 / 引导候选全部找不到电脑时，
把电脑变成 Wi-Fi 热点，让手机与电脑回到同一二层网络。
Windows ICS 的完整模式固定使用 192.168.137.0/24，网关 192.168.137.1
（微软 Win32 文档），手机首次连接后由系统自动重连，之后完全无感。

实测要点（Windows 11，winrt_probe.py）：
  TetheringOperationalState = 2 表示热点未开启；
  ClientCount / MaxClientCount 反映当前连接数与上限；
  AP SSID 与密码由系统「移动热点」设置决定。
  → API 可用，且开热点走的是无线网卡，不影响有线网卡当前的地址。

安全边界：开启热点属于系统级网络改动。本模块**不会**自行开启，
必须由 receiver.py 的 --hotspot 显式参数或用户调用触发；
服务退出时若热点是本进程开启的，会按 --hotspot-restore 恢复原状态。

依赖：winrt-Windows.Networking.Connectivity /
      winrt-Windows.Networking.NetworkOperators / winrt-runtime
"""
from __future__ import annotations

import asyncio
from typing import Callable

STATE_NAMES = {0: "Unknown", 1: "On", 2: "Off", 3: "InTransition"}


class HotspotController:
    def __init__(self, on_event: Callable[[str], None] | None = None):
        self.log = on_event or (lambda _s: None)
        self._mgr = None
        self._opened_by_us = False

    def _manager(self):
        if self._mgr is None:
            from winrt.windows.networking.connectivity import NetworkInformation
            from winrt.windows.networking.networkoperators import (
                NetworkOperatorTetheringManager)
            prof = NetworkInformation.get_internet_connection_profile()
            if prof is None:
                raise RuntimeError("没有可用的 Internet ConnectionProfile")
            self._mgr = NetworkOperatorTetheringManager.create_from_connection_profile(prof)
            self.log(f"热点 Profile：{prof.profile_name}")
        return self._mgr

    def status(self) -> str:
        try:
            st = int(self._manager().tethering_operational_state)
            return STATE_NAMES.get(st, str(st))
        except Exception as e:
            return "不可用: " + repr(e)

    def info(self) -> dict:
        try:
            m = self._manager()
            cfg = m.get_current_access_point_configuration()
            return {
                "ok": True,
                "state": self.status(),
                "ssid": cfg.ssid,
                "max_clients": m.max_client_count,
                "clients": m.client_count,
                "gateway": "192.168.137.1",
                "note": "Windows ICS 固定网段 192.168.137.0/24；手机首次连接需输密码或扫码",
            }
        except Exception as e:
            return {"ok": False, "error": repr(e)}

    def start(self) -> dict:
        async def work():
            r = await self._manager().start_tethering_async()
            return r

        try:
            before = self.status()
            result = asyncio.run(work())
            after = self.status()
            self._opened_by_us = before != "On" and after == "On"
            msg = f"StartTetheringAsync 返回 {result}，状态 {before} → {after}"
            self.log("[热点] " + msg)
            return {"ok": after == "On", "before": before, "after": after,
                    "result": str(result), "opened_by_us": self._opened_by_us}
        except Exception as e:
            self.log(f"[热点] 启动失败：{e!r}")
            return {"ok": False, "error": repr(e)}

    def stop(self) -> dict:
        async def work():
            return await self._manager().stop_tethering_async()

        try:
            before = self.status()
            result = asyncio.run(work())
            after = self.status()
            self.log(f"[热点] StopTetheringAsync 返回 {result}，状态 {before} → {after}")
            return {"ok": after == "Off", "before": before, "after": after,
                    "result": str(result)}
        except Exception as e:
            return {"ok": False, "error": repr(e)}

    def restore(self) -> dict | None:
        """只在本进程确实开启了热点时才关闭，避免误关用户原本开着的热点。"""
        if not self._opened_by_us:
            return None
        return self.stop()


if __name__ == "__main__":
    import json
    import sys
    h = HotspotController(on_event=lambda m: print(m))
    if len(sys.argv) > 1 and sys.argv[1] == "on":
        print(json.dumps(h.start(), ensure_ascii=False, indent=2))
    elif len(sys.argv) > 1 and sys.argv[1] == "off":
        print(json.dumps(h.stop(), ensure_ascii=False, indent=2))
    else:
        print(json.dumps(h.info(), ensure_ascii=False, indent=2))
