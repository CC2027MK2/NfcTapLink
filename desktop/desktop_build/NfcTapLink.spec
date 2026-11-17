# -*- mode: python ; coding: utf-8 -*-
"""NfcTapLink 打包脚本。

BLE 依赖 WinRT 投影包。每个投影目录下真正的实现是 `_table.pywinrt`
数据文件（运行时由 winrt-runtime 读取），PyInstaller 的 import 图看不到它，
只写 hiddenimports 会出现「模块在、表不在」的假成功。这里显式把 winrt
全部数据文件收进包，并在缺表时直接中止构建，不靠运气。
"""
from PyInstaller.utils.hooks import collect_data_files

WINRT_MODULES = [
    'winrt',
    'winrt.windows.foundation',
    'winrt.windows.foundation.collections',
    'winrt.windows.storage.streams',
    'winrt.windows.devices.enumeration',
    'winrt.windows.devices.radios',
    'winrt.windows.devices.bluetooth',
    'winrt.windows.devices.bluetooth.advertisement',
    'winrt.windows.devices.bluetooth.genericattributeprofile',
    'winrt.windows.networking.connectivity',
    'winrt.windows.networking.networkoperators',
]

winrt_datas = collect_data_files('winrt')
_have = {src.replace('\\', '/').lower() for src, _dest in winrt_datas}
_need = 'winrt/windows/devices/bluetooth/advertisement/_table.pywinrt'
if not any(p.endswith(_need) for p in _have):
    raise SystemExit(
        '构建中止：未收集到 winrt 蓝牙广播的 _table.pywinrt。'
        '请先在构建环境执行 pip install -r requirements.txt')

a = Analysis(
    ['../desktop_app.py'],
    pathex=[],
    binaries=[],
    datas=winrt_datas + [('../tap.html', '.'), ('nfctap.ico', '.')],
    hiddenimports=['ble_announcer', 'hotspot'] + WINRT_MODULES,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='NfcTapLink',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['nfctap.ico'],
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='NfcTapLink',
)
