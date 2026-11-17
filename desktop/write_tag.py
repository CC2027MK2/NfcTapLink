#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
电脑端写 NFC 标签工具（CH340 + PN532 HSU，115200 8N1）

用途：把 NfcTapLink 的配对信息写进空白 NTAG21x 贴纸，不依赖手机、不依赖 PC/SC。

命令：
  python write_tag.py --inspect              只识别标签、读关键页（只读）
  python write_tag.py --backup               把用户区内容备份到 tag_backup/（只读）
  python write_tag.py --dry-run              只算要写的字节，不写标签
  python write_tag.py --write                 写入（自动先备份，写后逐页回读比对）
  python write_tag.py --write --scheme http   写免安装方案的 http:// URL
  python write_tag.py --verify                按手机端逻辑解析当前 NDEF

方案参数默认从 receiver.py 的 config.json 读取；也可 --host / --port / --code 覆盖。

安全约束：
  - 只写 page 4 起的 NDEF 区，绝不碰 page 0-3（UID/CC/lock）与配置页；
  - 写入前检查 CC byte3（访问权限）与静态锁位；
  - 每次写入前自动备份到 tag_backup/<stem>_vNN_时间戳.json；
  - 先写 03 00 置空 TLV，再写完整内容，避免手机读到半写状态。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path

from pn532 import PN532, PN532Error, hexs

BASE = Path(__file__).resolve().parent
BACKUP_DIR = BASE / "tag_backup"
# v3：与 receiver / 桌面端共用同一份本机配置（默认 %LOCALAPPDATA%\NfcTapLink），
# 不再从脚本目录单独读一份 config.json，避免写标签时与运行中的服务失配。
CONFIG_PATH = Path(os.environ.get("NFCTAP_DATA_DIR") or BASE) / "config.json"

# NFC Forum URI RTD identifier codes（NFCForum-TS-RTD_URI_1.0）
URI_PREFIXES = [
    (0x01, "http://www."),
    (0x02, "https://www."),
    (0x03, "http://"),
    (0x04, "https://"),
    (0x05, "tel:"),
    (0x06, "mailto:"),
]

# Type 2 Tag NDEF 区起始页
NDEF_START_PAGE = 4


# --------------------------------------------------------------------------
# NDEF 编码
# --------------------------------------------------------------------------

def encode_uri_record(uri: str) -> bytes:
    """生成单条 NDEF URI 记录（MB=1 ME=1 SR=1 TNF=0x01）。"""
    code, rest = 0x00, uri
    for c, p in URI_PREFIXES:
        if uri.startswith(p):
            if len(p) > len(rest) or code == 0x00:
                code, rest = c, uri[len(p):]
            break
    payload = bytes([code]) + rest.encode("utf-8")
    if len(payload) > 255:
        raise ValueError("URI 超过 255 字节，需改成长记录格式（本工具未实现）")
    # header: MB(0x80)|ME(0x40)|SR(0x10)|TNF(0x01) = 0xD1
    return bytes([0xD1, 0x01, len(payload), 0x55]) + payload


def encode_tlv(ndef: bytes) -> bytes:
    """Type 2 Tag TLV：03 <len> <NDEF> FE（terminator）。"""
    if len(ndef) < 255:
        return bytes([0x03, len(ndef)]) + ndef + bytes([0xFE])
    # 3 字节长度格式：FF + 2 字节大端
    return bytes([0x03, 0xFF, (len(ndef) >> 8) & 0xFF, len(ndef) & 0xFF]) + ndef + bytes([0xFE])


def uri_fingerprint(uri: str) -> str:
    """仅输出 URI 的短指纹，避免在日志/复验脚本里传播含 k 的完整 URI。"""
    return "URI-SHA256:" + hashlib.sha256(uri.encode("utf-8")).hexdigest()[:16]


def decode_ndef_uri(ndef: bytes) -> str | None:
    """按 Android NdefRecord.createUri 的对端逻辑解析，用于交叉验证。"""
    if len(ndef) < 5:
        return None
    hdr, tlen, plen = ndef[0], ndef[1], ndef[2]
    if not (hdr & 0x80 and hdr & 0x40 and hdr & 0x10):
        return None
    if (hdr & 0x07) != 0x01:
        return None
    off = 3 + tlen
    rtype = ndef[3:3 + tlen]
    if rtype != b"U":
        return None
    payload = ndef[off:off + plen]
    if not payload:
        return None
    code, rest = payload[0], payload[1:].decode("utf-8", "replace")
    for c, p in URI_PREFIXES:
        if c == code:
            return p + rest
    return None if code != 0x00 else rest


def parse_tlv(pages: bytes) -> tuple[bytes, str]:
    """从 page 4 起的字节流里找出 NDEF Message TLV，返回 (ndef, 说明)。"""
    if len(pages) < 2:
        return b"", "数据不足"
    t = pages[0]
    if t == 0x00:
        return b"", "NULL TLV"
    if t == 0x03:
        if pages[1] == 0xFF:
            length = (pages[2] << 8) | pages[3]
            start = 4
        else:
            length = pages[1]
            start = 2
        ndef = pages[start:start + length]
        return ndef, f"NDEF TLV，长度 {length} 字节"
    if t == 0x01:
        # Lock Control TLV，跳过它再找 03
        if len(pages) < 5:
            return b"", "Lock Control TLV 不完整"
        skip = 2 + pages[1]
        sub = parse_tlv(pages[skip:])
        return sub[0], f"Lock Control TLV({skip} 字节) → {sub[1]}"
    if t == 0xFE:
        return b"", "空（Terminator TLV）"
    return b"", f"未知 TLV 类型 0x{t:02X}"


# --------------------------------------------------------------------------
# 标签识别与备份
# --------------------------------------------------------------------------

CC_NDEF_SIZE = {0x12: ("NTAG213", 144, 137),
                0x3E: ("NTAG215", 496, 492),
                0x6D: ("NTAG216", 872, 868)}


def inspect_tag(n: PN532) -> dict:
    t = n.in_list_passive_target()
    if t is None:
        raise PN532Error("未检测到标签，请把贴纸放在读卡器感应区")
    head = n.tag_read_pages(0, 6)       # page 0..5
    cc = head[12:16]
    model, ndef_area, max_msg = CC_NDEF_SIZE.get(cc[2], ("未知", cc[2] * 8, None))
    return {
        "uid": t["uid_hex"], "atqa": hexs(t["atqa"]), "sak": t["sak"],
        "cc": hexs(cc), "cc_byte2": cc[2], "cc_byte3": cc[3],
        "model": model, "ndef_area": ndef_area, "max_ndef_message": max_msg,
        "access": "可自由读写" if cc[3] == 0x00 else f"受限(0x{cc[3]:02X})",
        "static_lock": hexs(head[8:12]),
        "pages_0_5": [hexs(head[i * 4:i * 4 + 4]) for i in range(6)],
        "tg": t["tg"],
    }


def read_user_pages(n: PN532, ndef_area: int) -> bytes:
    """读 NDEF 区（page 4 起，覆盖 ndef_area 字节，按 4 页一组）。"""
    pages_needed = (ndef_area + 3) // 4
    return n.tag_read_pages(NDEF_START_PAGE, pages_needed)


def backup_tag(info: dict, data: bytes, note: str = "") -> Path:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    existing = sorted(BACKUP_DIR.glob("tag_v*.json"))
    n = len(existing) + 1
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    path = BACKUP_DIR / f"tag_v{n:02d}_{ts}.json"
    obj = {
        "version": n,
        "time": datetime.now().isoformat(timespec="seconds"),
        "note": note or "写入前备份",
        "tag": info,
        "ndef_area_hex": data.hex().upper(),
        "ndef_area_len": len(data),
    }
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


# --------------------------------------------------------------------------
# 写入
# --------------------------------------------------------------------------

def write_tlv(n: PN532, tlv: bytes, ndef_area: int) -> int:
    """把 TLV 从 page 4 起按 4 字节对齐写入，返回写入页数。"""
    if len(tlv) > ndef_area:
        raise ValueError(f"TLV {len(tlv)} 字节超过 NDEF 区 {ndef_area} 字节")
    padded = tlv + b"\x00" * ((-len(tlv)) % 4)
    page_count = len(padded) // 4

    # 1) 先置空 NDEF TLV，防止手机在写入过程中读到半截消息
    n.tag_write_page(NDEF_START_PAGE, bytes([0x03, 0x00, 0x00, 0x00]))

    # 2) 逐页写入
    for i in range(page_count):
        page = NDEF_START_PAGE + i
        chunk = padded[i * 4:i * 4 + 4]
        n.tag_write_page(page, chunk)
    return page_count


def verify_written(n: PN532, tlv: bytes, ndef_area: int) -> tuple[bool, str]:
    """逐页回读比对，并做 NDEF 语义解析。"""
    got = read_user_pages(n, ndef_area)
    padded = tlv + b"\x00" * ((-len(tlv)) % 4)
    if got[:len(padded)] != padded:
        for i, (a, b) in enumerate(zip(got[:len(padded)], padded)):
            if a != b:
                return False, f"page {NDEF_START_PAGE + i // 4} 第 {i % 4} 字节不一致：期望 {b:02X}，实读 {a:02X}"
        return False, f"长度不足：期望 {len(padded)}，实读 {len(got)}"
    ndef, desc = parse_tlv(got)
    uri = decode_ndef_uri(ndef) if ndef else None
    return True, f"{len(padded)} 字节逐字节一致；{desc}；解析 URI = {uri}"


# --------------------------------------------------------------------------
# 配置
# --------------------------------------------------------------------------

def load_pair_config(args) -> tuple[str, int, str]:
    cfg = {}
    if CONFIG_PATH.exists():
        cfg = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    code = args.code or cfg.get("pair_key")
    if not code:
        raise ValueError("缺少配对密钥：先运行 receiver.py 生成 config.json，或用 --code 指定")
    host = args.host
    if not host:
        try:
            os.environ["NFCTAP_DATA_DIR"] = str(CONFIG_PATH.parent)
            from receiver import guess_lan_ip
            host = guess_lan_ip()
        except Exception:
            host = "192.168.1.10"
    return host, args.port, code


def build_uri(scheme: str, host: str, port: int, code: str) -> str:
    if scheme == "nfctap":
        return f"nfctap://pair?h={host}&p={port}&k={code}"
    if scheme == "http":
        return f"http://{host}:{port}/tap?k={code}"
    raise ValueError(f"未知 scheme: {scheme}")


def build_v3_uri() -> str:
    """v3 标签：由 receiver.build_pair_uri 统一生成，避免字段漂移。"""
    # receiver 在 import 时根据 NFCTAP_DATA_DIR 计算配置路径，必须在 import 前设好。
    os.environ["NFCTAP_DATA_DIR"] = str(CONFIG_PATH.parent)
    from receiver import build_pair_uri, load_or_create_config
    return build_pair_uri(load_or_create_config())


def build_v2_uri(with_candidates: bool) -> str:
    """v2 标签（旧协议兼容）：设备 ID + 配对码（+ 可选引导候选）。"""
    os.environ["NFCTAP_DATA_DIR"] = str(CONFIG_PATH.parent)
    from receiver import build_pair_uri_v2_legacy, load_or_create_config
    return build_pair_uri_v2_legacy(load_or_create_config(), with_candidates)


# --------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="电脑端写 NFC 标签（CH340 + PN532）")
    ap.add_argument("--port-com", default="COM7", help="串口，默认 COM7")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--inspect", action="store_true", help="只识别标签（只读）")
    ap.add_argument("--backup", action="store_true", help="备份标签内容（只读）")
    ap.add_argument("--dry-run", action="store_true", help="只算字节，不写")
    ap.add_argument("--write", action="store_true", help="写入标签")
    ap.add_argument("--verify", action="store_true", help="解析当前 NDEF（只读）")
    ap.add_argument("--scheme", default="nfctap-v3",
                    choices=["nfctap-v3", "nfctap-v2", "nfctap-v2-pure", "nfctap", "http"],
                    help=("nfctap-v3=设备ID+256bit配对密钥（默认，v3 协议）；"
                          "其余为旧协议兼容，仅供迁移排障"))
    ap.add_argument("--host", default=None, help="电脑局域网 IP，默认自动探测")
    ap.add_argument("--port", type=int, default=8765, help="服务端口")
    ap.add_argument("--code", default=None, help="配对码，默认读 config.json")
    ap.add_argument("--uri", default=None, help="直接指定要写的完整 URI（覆盖其它参数）")
    args = ap.parse_args()

    if not any([args.inspect, args.backup, args.dry_run, args.write, args.verify]):
        args.inspect = True

    print("=" * 70)
    print("  NfcTapLink · 电脑端写标签（PN532 HSU / CH340）")
    print("=" * 70)
    print(f"  串口 {args.port_com} @ {args.baud} 8N1")

    try:
        with PN532(args.port_com, args.baud) as n:
            fw = n.get_firmware_version()
            print(f"  芯片 PN532 固件 v{fw['ver']}.{fw['rev']}  (IC=0x{fw['ic']:02X}, Support=0x{fw['support']:02X})")
            n.sam_configuration()
            info = inspect_tag(n)
            print(f"  标签 {info['model']}  UID={info['uid']}  CC={info['cc']}")
            print(f"  NDEF 区 {info['ndef_area']} 字节，单条消息上限 {info['max_ndef_message']} 字节，{info['access']}")
            print(f"  静态锁位 {info['static_lock']}  ATQA={info['atqa']} SAK=0x{info['sak']:02X}")
            print("-" * 70)

            # 纯只读的 inspect / verify：直接读当前 NDEF 后返回。
            # 2026-11-13 修复：原先 --verify 会继续往下走到写入准备流程，
            # 打印一个「待写 URI」（默认 v1 格式、根本不打算写）并额外生成
            # 一份备份，容易让人误判标签被改过。现在只读路径彻底早退。
            if (args.verify and not args.write) or (
                    args.inspect and not any([args.backup, args.dry_run, args.write, args.verify])):
                print("  前 6 页：")
                for i, p in enumerate(info["pages_0_5"]):
                    print(f"    page {i:02d}: {p}")
                data = read_user_pages(n, info["ndef_area"])
                ndef, desc = parse_tlv(data)
                print(f"  当前 NDEF：{desc}")
                if ndef:
                    parsed = decode_ndef_uri(ndef)
                    print(f"  解析 URI：{uri_fingerprint(parsed) if parsed else None}")
                if args.verify:
                    print("  （只读复验，未写入任何页、未生成备份）")
                return 0

            if args.uri:
                uri = args.uri
            elif args.scheme == "nfctap-v3":
                uri = build_v3_uri()
            elif args.scheme == "nfctap-v2":
                uri = build_v2_uri(True)
            elif args.scheme == "nfctap-v2-pure":
                uri = build_v2_uri(False)
            else:
                uri = build_uri(args.scheme, *load_pair_config(args))
            ndef = encode_uri_record(uri)
            tlv = encode_tlv(ndef)
            print(f"  待写 URI   {'<hidden: 含配对密钥>' if '&k=' in uri else uri}")
            print(f"  NDEF 记录  {len(ndef)} 字节  {hexs(ndef[:24])}{' ...' if len(ndef) > 24 else ''}")
            print(f"  TLV        {len(tlv)} 字节  {hexs(tlv[:24])}{' ...' if len(tlv) > 24 else ''}")
            print(f"  占用页数   {(len(tlv) + 3) // 4} 页（page 4 起）")
            if info["max_ndef_message"] and len(ndef) > info["max_ndef_message"]:
                print(f"  [错误] NDEF 超过该标签上限 {info['max_ndef_message']} 字节")
                return 1
            print("-" * 70)

            if args.dry_run and not args.write:
                print("  dry-run：未写入任何页。")
                return 0

            # 写入前备份（版本链）
            data_before = read_user_pages(n, info["ndef_area"])
            ndef_before, desc_before = parse_tlv(data_before)
            parsed_before = decode_ndef_uri(ndef_before) if ndef_before else None
            print(f"  写入前状态：{desc_before}" + (
                f" / {uri_fingerprint(parsed_before)}" if parsed_before else ""))
            bp = backup_tag(info, data_before, note=f"写入前备份；即将写入 scheme={args.scheme}")
            print(f"  已备份 → {bp.relative_to(BASE)}")

            if args.verify and not args.write:
                print(f"  当前 NDEF 解析：{uri_fingerprint(parsed_before) if parsed_before else '(无)'}")
                return 0

            if not args.write:
                return 0

            if info["cc_byte3"] != 0x00:
                print(f"  [错误] CC byte3=0x{info['cc_byte3']:02X}，标签只读，拒绝写入。")
                return 1
            # 静态锁位：page2 的 byte2/3 非 0 表示部分页被锁
            lock_bytes = info["static_lock"].split()[2:]
            if any(x != "00" for x in lock_bytes):
                print(f"  [警告] 静态锁位非 0（{info['static_lock']}），某些页可能已永久锁定。")

            print("  正在写入…")
            pages = write_tlv(n, tlv, info["ndef_area"])
            print(f"  已写 {pages} 页，逐页回读校验…")
            ok, msg = verify_written(n, tlv, info["ndef_area"])
            # 逐页回读结果里可能包含完整 URI（含 k），只打印结论不打印原文。
            print(f"  [{'通过' if ok else '失败'}] {'逐字节一致，NDEF 语义解析通过' if ok else msg}")
            if not ok:
                return 1
            print(f"  内容指纹     {uri_fingerprint(uri)}")
            print(f"  备份留在 {bp.relative_to(BASE)}，需要回退可用它逐页写回。")
            return 0
    except PN532Error as e:
        print(f"  [错误] {e}")
        return 1
    except Exception as e:
        print(f"  [错误] {type(e).__name__}: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
