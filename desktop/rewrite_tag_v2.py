# -*- coding: utf-8 -*-
"""把物理 NTAG215 标签写入 / 重写为 v3（无 IP，靠 BLE/UDP + 双向认证）。

流程（每一步都可核验）：
  1. 只读 --inspect 确认标签在位、识别型号与当前 NDEF
  2. 调用 write_tag.py --scheme nfctap-v3 --write
     （内部自动备份写入前内容到 tag_backup/、逐页回读校验）
  3. **独立进程**再跑一次 --inspect，确认解析出的 URI 与预期一致
  4. 打印结果；任何一步失败都不继续

用法：
  python rewrite_tag_v3.py            # dry-run，只检查与预览，不写
  python rewrite_tag_v3.py --write    # 真正写入
"""
import argparse
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

BASE = Path(__file__).resolve().parent
CONFIG_DIR = Path(os.environ.get("NFCTAP_DATA_DIR") or (
    Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "NfcTapLink"))
PY = sys.executable
WRITE_TAG = BASE / "write_tag.py"
sys.path.insert(0, str(BASE))


def uri_fingerprint(uri: str) -> str:
    import hashlib
    return "URI-SHA256:" + hashlib.sha256(uri.encode("utf-8")).hexdigest()[:16]


def run(*args, timeout=90):
    env = dict(os.environ)
    env["NFCTAP_DATA_DIR"] = str(CONFIG_DIR)
    return subprocess.run([PY, str(WRITE_TAG), *args],
                          capture_output=True, timeout=timeout, env=env)


def text(r):
    return (r.stdout + r.stderr).decode("utf-8", "replace")


def expected_uri():
    sys.path.insert(0, str(BASE))
    os.environ["NFCTAP_DATA_DIR"] = str(CONFIG_DIR)
    import receiver
    return receiver.build_pair_uri(receiver.load_or_create_config())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true", help="真正写入；默认 dry-run")
    a = ap.parse_args()

    uri = expected_uri()
    print("=" * 72)
    print("  NfcTapLink · 物理标签重写为 v3（无 IP + 双向认证）")
    print("=" * 72)
    print("  目标 URI   <hidden: 含配对密钥>")
    print(f"  模式       {'实际写入' if a.write else 'dry-run（不写）'}")
    print("-" * 72)

    # ---- 1 只读识别 ----
    r = run("--inspect")
    t = text(r)
    if "ACK 异常" in t or "标签" not in t:
        print("[停止] 读卡器无响应，标签未识别。")
        print("       请确认 PN532 板已上电（USB 重新插拔）、NTAG215 放在感应区，")
        print("       再运行本脚本。未对标签做任何改动。")
        for line in t.splitlines():
            if "错误" in line or "ACK" in line:
                print("       " + line.strip())
        return 2
    print("[1/3] 标签识别成功")
    for line in t.splitlines():
        if any(k in line for k in ("标签 NTAG", "当前 NDEF", "解析 URI", "静态锁位")):
            print("      " + line.strip())
    current = next((l.split("解析 URI：", 1)[1].strip()
                    for l in t.splitlines() if "解析 URI：" in l), "(无)")
    print(f"      当前内容指纹: {current}")
    if current == uri_fingerprint(uri):
        print("[完成] 标签已经是目标 v3 内容，无需重写。")
        return 0

    # ---- 2 写入 ----
    args = ["--scheme", "nfctap-v3"]
    if a.write:
        args.append("--write")
    else:
        args.append("--dry-run")
    r = run(*args)
    t2 = text(r)
    for line in t2.splitlines():
        if any(k in line for k in ("待写 URI", "NDEF 记录", "TLV", "占用页数",
                                   "写入前状态", "已备份", "正在写入", "已写",
                                   "[通过]", "[失败]", "[错误]", "dry-run")):
            print("      " + line.strip())
    if r.returncode != 0:
        print(f"[停止] write_tag.py 返回 {r.returncode}，未确认写入成功。")
        return 1
    if not a.write:
        print("\n[2/3] dry-run 通过。确认无误后运行：python rewrite_tag_v2.py --write（文件名保留）")
        return 0
    print("[2/3] 写入完成，逐页回读通过，写入前内容已备份到 tag_backup/")

    # ---- 3 独立进程复验 ----
    r3 = run("--inspect")
    t3 = text(r3)
    got = next((l.split("解析 URI：", 1)[1].strip()
                for l in t3.splitlines() if "解析 URI：" in l), None)
    print(f"[3/3] 独立进程复验：{'内容指纹与本机配置一致' if got == uri_fingerprint(uri) else '不一致'}")
    if got != uri_fingerprint(uri):
        print("[失败] 回读与本机配置不一致")
        return 1
    print("\n=== 完成 ===")
    print("  标签已写入 v3 纯无 IP 内容（含配对密钥，URI 不打印）")
    print("  之后换 Wi-Fi / 换网段都不用重写标签；")
    print("  电脑端需运行 python receiver.py（默认开 BLE 广播）。")
    print(f"  完成时间 {datetime.now().isoformat(timespec='seconds')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
