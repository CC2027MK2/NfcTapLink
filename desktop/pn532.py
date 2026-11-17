#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PN532 HSU / UART 驱动（仅用 pyserial，无其他依赖）

面向 CH340(USB 转串口) + PN532 模块，实测参数：
  - 端口 COM7，VID:PID = 1A86:7523 (wch.cn CH340)
  - 波特率 115200, 8N1, 无流控
  - 固件回包 GetFirmwareVersion: 00 00 FF 06 FA D5 03 32 01 06 07 E8 00
    → LEN=06 LCS=FA；body=D5 03 32 01 06 07；DCS=E8；tail=00
    → PD = 03 32 01 06 07：IC=0x32(PN532) / Ver=0x01 / Rev=0x06 → 固件 v1.6
      / Support=0x07（位义未从一手手册核实，不解读）
    - 注意：E8 是 DCS 校验和，不是功能位图。初版探测脚本曾误读，已更正。

帧格式（PN532 User Manual, HSU）：
  00 00 FF LEN LCS TFI PD0..PDn DCS 00
  LEN = 1(TFI) + n(PD)，LCS 使 LEN+LCS=0 (mod 256)
  TFI = D4(host→PN532) / D5(PN532→host)
  DCS 使 TFI+PD0..+PDn+DCS=0 (mod 256)
  ACK 帧 = 00 00 FF 00 FF 00

NTAG21x / MIFARE Ultralight（Type 2 Tag）命令经 InDataExchange 透传：
  READ  30 <page>            → 16 字节（连续 4 页）
  WRITE A2 <page> <4 bytes>  → 4-bit ACK，PN532 映射为 1 字节 0x0A
"""
from __future__ import annotations

import time
from typing import Optional

import serial

TFI_HOST = 0xD4
TFI_PN532 = 0xD5
ACK_FRAME = bytes.fromhex("0000FF00FF00")
WAKEUP = bytes([0x55, 0x55] + [0x00] * 14)


class PN532Error(Exception):
    pass


def _checksum(data: bytes) -> int:
    return (-sum(data)) & 0xFF


def build_frame(pd: bytes) -> bytes:
    """pd 为 PD0..PDn（不含 TFI）。"""
    body = bytes([TFI_HOST]) + pd
    length = len(body)
    lcs = (-length) & 0xFF
    dcs = _checksum(body)
    return bytes([0x00, 0x00, 0xFF, length & 0xFF, lcs]) + body + bytes([dcs, 0x00])


def hexs(b: bytes) -> str:
    return " ".join(f"{x:02X}" for x in b) if b else "(空)"


class PN532:
    def __init__(self, port: str = "COM7", baud: int = 115200,
                 timeout: float = 1.0, wakeup: bool = True):
        self.port = port
        self.baud = baud
        self.ser = serial.Serial(port, baudrate=baud, timeout=timeout,
                                 bytesize=serial.EIGHTBITS,
                                 parity=serial.PARITY_NONE,
                                 stopbits=serial.STOPBITS_ONE,
                                 rtscts=False, dsrdtr=False)
        self.ser.reset_input_buffer()
        self.ser.reset_output_buffer()
        if wakeup:
            self.wake()
        self.tg: Optional[int] = None

    def close(self) -> None:
        if self.ser and self.ser.is_open:
            self.ser.close()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    # ---------------- 底层收发 ----------------
    def wake(self) -> None:
        self.ser.write(WAKEUP)
        self.ser.flush()
        time.sleep(0.02)
        self.ser.reset_input_buffer()

    def _read_exact(self, n: int, timeout: float = 1.5) -> bytes:
        out = b""
        deadline = time.monotonic() + timeout
        while len(out) < n and time.monotonic() < deadline:
            chunk = self.ser.read(n - len(out))
            if chunk:
                out += chunk
            else:
                time.sleep(0.01)
        return out

    def command(self, pd: bytes, timeout: float = 1.5,
                expect_ack: bool = True) -> bytes:
        """发命令帧，返回响应帧的 PD0..PDn（已去掉 TFI/DCS/尾）。"""
        frame = build_frame(pd)
        self.ser.reset_input_buffer()
        self.ser.write(frame)
        self.ser.flush()

        if expect_ack:
            ack = self._read_exact(6, timeout)
            if ack != ACK_FRAME:
                raise PN532Error(f"ACK 异常: 期望 {hexs(ACK_FRAME)}，实收 {hexs(ack)}")

        # 读响应头 5 字节：00 00 FF LEN LCS
        head = self._read_exact(5, timeout)
        if len(head) < 5:
            raise PN532Error(f"响应头超时（收到 {len(head)} 字节）: {hexs(head)}")
        if head[0:3] != b"\x00\x00\xFF":
            raise PN532Error(f"响应前导错误: {hexs(head)}")
        length, lcs = head[3], head[4]
        if (length + lcs) & 0xFF != 0:
            raise PN532Error(f"LCS 校验失败: LEN={length:02X} LCS={lcs:02X}")
        if length > 255:
            raise PN532Error(f"LEN 越界: {length}")

        rest = self._read_exact(length + 2, timeout)  # TFI + PD + DCS + 尾 00
        if len(rest) < length + 2:
            raise PN532Error(f"响应体不完整: 需要 {length + 2}，实收 {len(rest)}")
        tfi = rest[0]
        if tfi != TFI_PN532:
            raise PN532Error(f"TFI 非 D5: {tfi:02X}")
        body = rest[:length]              # TFI + PD
        dcs = rest[length]
        tail = rest[length + 1]
        if (sum(body) + dcs) & 0xFF != 0:
            raise PN532Error(f"DCS 校验失败: {hexs(body)} DCS={dcs:02X}")
        if tail != 0x00:
            raise PN532Error(f"帧尾非 00: {tail:02X}")
        return body[1:]                   # 去掉 TFI，返回 PD

    # ---------------- 高层命令 ----------------
    def get_firmware_version(self) -> dict:
        pd = self.command(bytes([0x02]))
        if len(pd) < 4 or pd[0] != 0x03:
            raise PN532Error(f"GetFirmwareVersion 响应异常: {hexs(pd)}")
        return {"ic": pd[1], "ver": pd[2], "rev": pd[3],
                "support": pd[4] if len(pd) > 4 else None,
                "raw": pd}

    def sam_configuration(self, mode: int = 0x01) -> bool:
        pd = self.command(bytes([0x14, mode, 0x00, 0x00]))
        return len(pd) >= 1 and pd[0] == 0x15

    def in_list_passive_target(self, max_tg: int = 1, br_ty: int = 0x00) -> Optional[dict]:
        """br_ty=0x00 → ISO/IEC 14443A 106 kbps（NTAG21x 属于此类）。"""
        pd = self.command(bytes([0x4A, max_tg, br_ty]), timeout=2.0)
        if len(pd) < 2 or pd[0] != 0x4B:
            raise PN532Error(f"InListPassiveTarget 响应异常: {hexs(pd)}")
        nb_tg = pd[1]
        if nb_tg < 1:
            return None
        # 每个目标: Tg(1) SENS_RES(2) SEL_RES(1) NFCIDLen(1) NFCID(n)
        off = 2
        tg = pd[off]; off += 1
        sens = pd[off:off + 2]; off += 2
        sel = pd[off]; off += 1
        uid_len = pd[off]; off += 1
        uid = pd[off:off + uid_len]; off += uid_len
        self.tg = tg
        return {"tg": tg, "atqa": sens, "sak": sel,
                "uid": uid, "uid_hex": uid.hex().upper(),
                "ats": pd[off:]}

    def in_data_exchange(self, data: bytes, tg: int = 1) -> tuple[int, bytes]:
        """返回 (status, 响应数据)。status=0x00 为成功。"""
        pd = self.command(bytes([0x40, tg]) + data, timeout=1.5)
        if len(pd) < 1 or pd[0] != 0x41:
            raise PN532Error(f"InDataExchange 响应异常: {hexs(pd)}")
        return pd[1], pd[2:]

    # ---------------- NTAG21x / Type 2 Tag ----------------
    def tag_read(self, page: int) -> bytes:
        """READ 命令返回连续 4 页共 16 字节。"""
        status, data = self.in_data_exchange(bytes([0x30, page & 0xFF]))
        if status != 0x00:
            raise PN532Error(f"READ page {page} 失败, status={status:02X}")
        if len(data) < 16:
            raise PN532Error(f"READ page {page} 数据不足 16 字节: {hexs(data)}")
        return data[:16]

    def tag_write_page(self, page: int, four: bytes) -> bool:
        """WRITE 一页 4 字节；成功时 PN532 返回 4-bit ACK(0x0A)。"""
        if len(four) != 4:
            raise ValueError("NTAG21x 每页必须 4 字节")
        status, data = self.in_data_exchange(bytes([0xA2, page & 0xFF]) + four)
        if status != 0x00:
            raise PN532Error(f"WRITE page {page} 失败, status={status:02X} 数据={hexs(data)}")
        # 4-bit ACK 0x0A；部分固件回空或 0x00/0x0A 混合，只把明确 NAK 当失败
        if data and data[0] in (0x00, 0x01, 0x04, 0x05):
            raise PN532Error(f"WRITE page {page} 被标签 NAK: {hexs(data)}")
        return True

    def tag_read_pages(self, start: int, count: int) -> bytes:
        """按 4 页一组读取，返回 count 页的连续字节。"""
        out = b""
        p = start
        while len(out) < count * 4:
            out += self.tag_read(p)
            p += 4
        return out[:count * 4]


def describe_ic(ic: int) -> str:
    """只给能确认的映射，不猜位义。"""
    return {0x32: "PN532", 0x33: "PN533"}.get(ic, f"未知 IC 0x{ic:02X}")


def describe_firmware(ver: int, rev: int) -> str:
    return f"v{ver}.{rev}"
