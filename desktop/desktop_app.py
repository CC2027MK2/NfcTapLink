#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NfcTapLink · Windows 桌面端 v1.0（PySide6，零第三方 GUI 依赖之外的库）

功能：
  1. 一体化：窗口内直接启动/停止接收服务（UDP 发现 + BLE 广播 + HTTP 接收），
     不必再手动跑 python receiver.py；
  2. 「接收文件」页：左侧表格展示 transfer.log.jsonl（时间/结果/文件名/字节/类型/来源），
     右侧实时预览（图片直接显示，其它类型显示文件信息），双击打开对应文件；
     按住已保存的文件可拖出到微信/钉钉/资源管理器；
  3. 「发送文件」页：拖入或选择文件入队，点一次「发送」按顺序逐个发给手机，
     显示 1/3 进度，结束后汇总成功 / 失败（失败项可直接重试），单文件上限 1 GB；
  4. 「服务与设置」页：端口、数据目录、BLE 开关、开机自启开关、设备 ID、标签 URI（可复制）、关于。
     页签顺序：接收文件 / 发送文件 / 服务与设置。

数据目录默认 %LOCALAPPDATA%\\NfcTapLink，与程序安装目录分离，
避免装到 Program Files 后无写权限。可用 --data-dir 覆盖。

自检模式：NfcTapLink.exe --selftest
  不弹界面，启动服务 → HTTP 自检 → 把结果写入 <数据目录>/selftest_result.json → 退出。
  用于验证 PyInstaller 打包后 BLE/WinRT 与接收服务仍然可用。
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from string import Template

# PyInstaller --windowed 下 sys.stdout/stderr 可能是 None，
# receiver.py 的日志 print 与桌面端的提示 print 都会抛 AttributeError。
if sys.stdout is None:
    sys.stdout = io.StringIO()
if sys.stderr is None:
    sys.stderr = io.StringIO()

# —— 必须在 import receiver 之前设好数据目录 ——
_pre = [a for a in sys.argv if not a.startswith("-")]
_data_override = None
if "--data-dir" in sys.argv:
    i = sys.argv.index("--data-dir")
    if i + 1 < len(sys.argv):
        _data_override = sys.argv[i + 1]
DATA_DIR = Path(_data_override or (
    Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "NfcTapLink"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
os.environ["NFCTAP_DATA_DIR"] = str(DATA_DIR)

import receiver as R                     # noqa: E402
import discovery as D                    # noqa: E402

APP_NAME = "一碰传 · 桌面端"
APP_VERSION = R.PRODUCT_VERSION
# 随包手机端 APK 的版本：本版桌面端升版不改手机端，单独标注实际版本
MOBILE_VERSION = "6.2.3"

# v3：Windows 上双击这些扩展名 = 执行，不是「打开查看」。服务端 v3 已改
# 落盘白名单，但历史文件 / 手工放进 received 的文件仍可能带原扩展名。
DANGEROUS_SUFFIXES = {
    ".bat", ".cmd", ".com", ".exe", ".msi", ".msp", ".scr", ".pif",
    ".ps1", ".psm1", ".psd1", ".vbs", ".vbe", ".js", ".jse", ".wsf",
    ".wsh", ".hta", ".jar", ".lnk", ".reg", ".cpl", ".dll", ".sys",
    ".svg", ".svgz", ".xhtml", ".mht", ".mhtml", ".html", ".htm",
}

SAFE_SUFFIXES = R.SAFE_EXTS


def ensure_config():
    """v3：不再从安装包复制任何种子密钥。

    首次启动由 receiver.load_or_create_config() 在本机生成随机 pair_key，
    标签 URI 从桌面端「服务与设置」页复制后写入 NFC 标签。安装包因此
    不含任何长期凭据，拿到安装包也无法伪造 token 或冒充电脑。
    """
    R.load_or_create_config()


ensure_config()


# --------------------------------------------------------------------------
# 开机自启（HKCU\Software\Microsoft\Windows\CurrentVersion\Run，用户级，无需管理员）
# --------------------------------------------------------------------------
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_VALUE = "NfcTapLink"
STARTUP_FLAG = "--startup"


def autostart_command() -> str:
    """注册表里要写的命令行，永远取当前运行程序的实际路径。"""
    if getattr(sys, "frozen", False):
        return f'"{Path(sys.executable)}" {STARTUP_FLAG}'
    return f'"{Path(sys.executable)}" "{Path(__file__).resolve()}" {STARTUP_FLAG}'


def autostart_entry() -> str | None:
    """返回注册表里的真实自启动命令行；没有该值返回 None。"""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as k:
            val, _ = winreg.QueryValueEx(k, RUN_VALUE)
            return str(val)
    except (ImportError, OSError):
        return None


def autostart_enabled() -> bool:
    return autostart_entry() is not None


def set_autostart(on: bool) -> None:
    """开：用当前 exe 的实际路径写入/覆盖；关：删除该值。"""
    import winreg
    if on:
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, RUN_KEY, 0,
                                winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, RUN_VALUE, 0, winreg.REG_SZ, autostart_command())
        return
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0,
                            winreg.KEY_SET_VALUE) as k:
            winreg.DeleteValue(k, RUN_VALUE)
    except FileNotFoundError:
        pass


try:
    from PySide6.QtCore import (
        Qt, QTimer, QSize, QRectF, QPoint, QPointF, QVariantAnimation,
        QEasingCurve, QMimeData, QUrl, QFileInfo,
    )
    from PySide6.QtGui import (
        QIcon, QPixmap, QFont, QColor, QPalette, QPainter, QPen, QBrush,
        QPolygonF, QPainterPath, QFontMetrics, QAction, QDrag,
    )
    from PySide6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QGridLayout, QLabel, QPushButton, QTableWidget, QTableWidgetItem,
        QSplitter, QSpinBox, QLineEdit,
        QStatusBar, QMessageBox, QAbstractItemView, QHeaderView, QFrame,
        QSizePolicy, QStackedWidget, QButtonGroup,
        QStyle, QAbstractButton, QFileDialog,
        QSystemTrayIcon, QMenu, QFileIconProvider, QScrollArea,
    )
    HAS_QT = True
except Exception as _qt_err:          # 自检模式可不依赖 Qt
    HAS_QT = False
    QT_IMPORT_ERROR = repr(_qt_err)


# --------------------------------------------------------------------------
# 设计令牌（与手机端共用同一套，勿在别处自创第二套色值）
# --------------------------------------------------------------------------
class C:
    BG = "#0F1115"          # 背景
    PANEL = "#161A21"       # 浮动面板
    CARD = "#1B2029"        # 卡片
    LINE = "#262C38"        # 描边
    DIV = "#20252F"         # 分隔
    TXT = "#E8EBF2"         # 主文字
    TXT2 = "#9AA3B5"        # 次文字
    TXT3 = "#6B7280"        # 弱文字
    TEAL = "#4FD1C5"        # 主色
    INDIGO = "#7C8CF8"      # 次色
    OK = "#3DD68C"
    WARN = "#F5A524"
    DANGER = "#F04438"
    FIELD = "#12161D"       # 输入框底
    HOVER = "#212734"
    PRESSED = "#181D25"


R_CTRL = 10
R_CARD = 16
S = 8                        # 间距基数

_QSS = Template("""
QWidget#Root, QMainWindow { background: $bg; }
QDialog, QMessageBox { background: $panel; }

QLabel { color: $txt; background: transparent; }
QLabel[role="display"] { font-size: 20px; font-weight: 600; }
QLabel[role="title"] { font-size: 16px; font-weight: 600; }
QLabel[role="label"] { font-size: 12px; color: $txt3; }
QLabel[role="sub"] { font-size: 12px; color: $txt2; }
QLabel[role="hint"] { font-size: 12px; color: $txt3; }
QLabel[role="stat"] { font-size: 20px; font-weight: 600; }
QLabel[role="mono"] {
    font-family: "Consolas", "Cascadia Mono", "JetBrains Mono", monospace;
    font-size: 13px; color: $txt;
}

QFrame#Panel { background: $panel; border: 1px solid $line; border-radius: 16px; }
QFrame#Card { background: $card; border: 1px solid $line; border-radius: 16px; }
QFrame#Stage { background: $bg; border: 1px solid $div; border-radius: 12px; }
QFrame#Pill { background: $panel; border: 1px solid $line; border-radius: 999px; }
QFrame#Segmented { background: $panel; border: 1px solid $line; border-radius: 999px; }
QFrame#Divider { background: $div; border: none; min-height: 1px; max-height: 1px; }
QFrame#Tag { background: #232A36; border: none; border-radius: 999px; }

QPushButton {
    background: $card; color: $txt; border: 1px solid $line;
    border-radius: 10px; padding: 7px 16px; font-size: 14px;
}
QPushButton:hover { background: $hover; border-color: #313A49; }
QPushButton:pressed { background: $pressed; }
QPushButton:disabled { color: $txt3; background: #151A21; border-color: $div; }

QPushButton[variant="primary"] {
    background: $teal; border-color: $teal; color: #062A28; font-weight: 600;
}
QPushButton[variant="primary"]:hover { background: #66DCD2; border-color: #66DCD2; }
QPushButton[variant="primary"]:pressed { background: #40BFB4; border-color: #40BFB4; }
QPushButton[variant="primary"]:disabled {
    background: #1C3230; border-color: #1C3230; color: #5C7C79;
}

QPushButton[variant="danger"] {
    background: transparent; border-color: rgba(240, 68, 56, 0.45); color: $danger;
}
QPushButton[variant="danger"]:hover {
    background: rgba(240, 68, 56, 0.08); border-color: rgba(240, 68, 56, 0.75);
}

QPushButton[variant="ghost"] {
    background: transparent; border-color: transparent; color: $txt2; padding: 7px 12px;
}
QPushButton[variant="ghost"]:hover { background: $card; color: $txt; }
QPushButton[variant="ghost"]:pressed { background: $pressed; }

QPushButton[variant="seg"] {
    background: transparent; border: none; border-radius: 999px;
    padding: 7px 20px; color: $txt2; font-size: 14px;
}
QPushButton[variant="seg"]:hover { color: $txt; background: rgba(255, 255, 255, 0.04); }
QPushButton[variant="seg"]:checked { background: #293140; color: $txt; font-weight: 600; }

QPushButton#StepBtn {
    background: transparent; border: 1px solid $line; border-radius: 10px;
    color: $txt2; font-size: 15px; padding: 0; min-width: 28px; max-width: 28px;
    min-height: 28px; max-height: 28px;
}
QPushButton#StepBtn:hover { background: $card; color: $txt; border-color: #313A49; }

QLineEdit {
    background: $field; border: 1px solid $line; border-radius: 10px;
    padding: 7px 12px; color: $txt; font-size: 14px;
    selection-background-color: rgba(79, 209, 197, 0.35);
}
QLineEdit:hover { border-color: #313A49; }
QLineEdit:focus { border-color: rgba(79, 209, 197, 0.65); background: #141A21; }
QLineEdit[readOnly="true"] { color: $txt2; }
QLineEdit[mono="true"] {
    font-family: "Consolas", "Cascadia Mono", "JetBrains Mono", monospace;
    font-size: 13px;
}

QSpinBox {
    background: $field; border: 1px solid $line; border-radius: 10px;
    padding: 0 8px; color: $txt; font-size: 14px;
    selection-background-color: rgba(79, 209, 197, 0.35);
}
QSpinBox:hover { border-color: #313A49; }
QSpinBox:focus { border-color: rgba(79, 209, 197, 0.65); }
QSpinBox::up-button, QSpinBox::down-button { width: 0; height: 0; border: none; }

QTableWidget {
    background: transparent; border: none; gridline-color: transparent;
    font-size: 14px; color: $txt;
    selection-background-color: rgba(79, 209, 197, 0.10);
    selection-color: $txt;
}
QTableWidget::item { border-bottom: 1px solid $div; padding: 0 8px; }
QTableWidget::item:hover { background: rgba(255, 255, 255, 0.025); }
QHeaderView::section {
    background: transparent; color: $txt3; border: none;
    border-bottom: 1px solid $line; padding: 8px; font-size: 12px; font-weight: 600;
}
QTableCornerButton::section { background: transparent; border: none; }

QListWidget {
    background: transparent; border: none; outline: 0;
    font-size: 14px; color: $txt;
}
QListWidget::item { border-radius: 10px; margin: 2px 0; }
QListWidget::item:hover { background: rgba(255, 255, 255, 0.03); }
QListWidget::item:selected { background: rgba(79, 209, 197, 0.10); color: $txt; }

QScrollBar:vertical { background: transparent; width: 10px; margin: 4px 2px; }
QScrollBar::handle:vertical { background: #2E3542; border-radius: 5px; min-height: 32px; }
QScrollBar::handle:vertical:hover { background: #3A4351; }
QScrollBar:horizontal { background: transparent; height: 10px; margin: 2px 4px; }
QScrollBar::handle:horizontal { background: #2E3542; border-radius: 5px; min-width: 32px; }
QScrollBar::handle:horizontal:hover { background: #3A4351; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; border: none; }
QScrollBar::add-page, QScrollBar::sub-page { background: transparent; }

QSplitter::handle { background: transparent; }

QStatusBar {
    background: $bg; color: $txt3; border-top: 1px solid $div; font-size: 12px;
}
QStatusBar::item { border: none; }
QStatusBar QLabel { color: $txt3; font-size: 12px; }

QToolTip {
    background: $card; color: $txt; border: 1px solid $line;
    padding: 6px 8px; border-radius: 8px; font-size: 12px;
}

QMessageBox QLabel { color: $txt; font-size: 14px; }
QMessageBox QPushButton { min-width: 72px; }

QFrame#DropZone {
    background-color: $bg;
    border: 2px dashed $teal;
    border-radius: 18px;
}
QFrame#DropZone QLabel { background: transparent; }
""")

# 布局器对空白的行距贡献（HTML <div> 自带 leading，不设这里会把说明文字叠成一团）
_SPACING_QSS = """
QLabel { margin-top: 2px; margin-bottom: 2px; }
"""

QSS = _QSS.substitute(
    bg=C.BG, panel=C.PANEL, card=C.CARD, line=C.LINE, div=C.DIV,
    txt=C.TXT, txt2=C.TXT2, txt3=C.TXT3, teal=C.TEAL, indigo=C.INDIGO,
    ok=C.OK, warn=C.WARN, danger=C.DANGER,
    hover=C.HOVER, pressed=C.PRESSED, field=C.FIELD,
) + _SPACING_QSS


def apply_theme(app):
    """统一暗色主题：Fusion 风格 + 中文字体回退链 + 调色板 + QSS。"""
    app.setStyle("Fusion")
    f = QFont()
    f.setFamilies(["Microsoft YaHei UI", "Microsoft YaHei", "PingFang SC",
                   "Noto Sans CJK SC", "Source Han Sans SC", "Segoe UI"])
    f.setPixelSize(14)
    app.setFont(f)

    pal = QPalette()
    pal.setColor(QPalette.Window, QColor(C.BG))
    pal.setColor(QPalette.WindowText, QColor(C.TXT))
    pal.setColor(QPalette.Base, QColor(C.FIELD))
    pal.setColor(QPalette.AlternateBase, QColor(C.CARD))
    pal.setColor(QPalette.Text, QColor(C.TXT))
    pal.setColor(QPalette.Button, QColor(C.CARD))
    pal.setColor(QPalette.ButtonText, QColor(C.TXT))
    pal.setColor(QPalette.Highlight, QColor(79, 209, 197, 70))
    pal.setColor(QPalette.HighlightedText, QColor(C.TXT))
    pal.setColor(QPalette.ToolTipBase, QColor(C.CARD))
    pal.setColor(QPalette.ToolTipText, QColor(C.TXT))
    pal.setColor(QPalette.PlaceholderText, QColor(C.TXT3))
    for grp in (QPalette.Disabled,):
        pal.setColor(grp, QPalette.Text, QColor(C.TXT3))
        pal.setColor(grp, QPalette.WindowText, QColor(C.TXT3))
        pal.setColor(grp, QPalette.ButtonText, QColor(C.TXT3))
    app.setPalette(pal)
    app.setStyleSheet(QSS)


# --------------------------------------------------------------------------
# 线性图标（1.5px 描边，24 格内手绘，无外部图标资源）
# --------------------------------------------------------------------------
_ICON_CACHE: dict = {}


def line_icon(name: str, color: str = C.TXT2, size: int = 18) -> QIcon:
    key = (name, color, size)
    cached = _ICON_CACHE.get(key)
    if cached is not None:
        return cached

    dpr = 3
    pm = QPixmap(size * dpr, size * dpr)
    pm.setDevicePixelRatio(dpr)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing, True)
    p.scale(size / 24.0, size / 24.0)
    pen = QPen(QColor(color), 1.5 * 24.0 / size)
    pen.setCapStyle(Qt.RoundCap)
    pen.setJoinStyle(Qt.RoundJoin)
    p.setPen(pen)
    p.setBrush(Qt.NoBrush)

    if name == "play":
        p.drawPolygon(QPolygonF([QPointF(8, 5), QPointF(19, 12), QPointF(8, 19)]))
    elif name == "stop":
        p.drawRoundedRect(QRectF(7, 7, 10, 10), 2, 2)
    elif name == "folder":
        path = QPainterPath()
        path.moveTo(3.5, 17.5)
        path.lineTo(3.5, 6.8)
        path.quadTo(3.5, 5.5, 4.8, 5.5)
        path.lineTo(8.8, 5.5)
        path.lineTo(11.0, 8.0)
        path.lineTo(19.2, 8.0)
        path.quadTo(20.5, 8.0, 20.5, 9.3)
        path.lineTo(20.5, 17.2)
        path.quadTo(20.5, 18.5, 19.2, 18.5)
        path.lineTo(4.8, 18.5)
        path.quadTo(3.5, 18.5, 3.5, 17.5)
        p.drawPath(path)
    elif name == "refresh":
        p.drawArc(QRectF(4, 4, 16, 16), 45 * 16, 270 * 16)
        p.drawLine(QPointF(16.2, 4.4), QPointF(20.0, 6.4))
        p.drawLine(QPointF(20.0, 6.4), QPointF(18.1, 10.2))
    elif name == "copy":
        p.drawRoundedRect(QRectF(8.5, 3.5, 12, 14), 2.5, 2.5)
        p.drawRoundedRect(QRectF(3.5, 6.5, 12, 14), 2.5, 2.5)
    elif name == "broadcast":
        p.setBrush(QBrush(QColor(color)))
        p.drawEllipse(QRectF(4.6, 16.6, 2.8, 2.8))
        p.setBrush(Qt.NoBrush)
        for r in (6.0, 10.0, 14.0):
            p.drawArc(QRectF(6 - r, 18 - r, 2 * r, 2 * r), 0, 90 * 16)
    elif name == "file":
        path = QPainterPath()
        path.moveTo(6, 3.5)
        path.lineTo(13.5, 3.5)
        path.lineTo(19, 9)
        path.lineTo(19, 20.5)
        path.lineTo(6, 20.5)
        path.closeSubpath()
        p.drawPath(path)
        path2 = QPainterPath()
        path2.moveTo(13.5, 3.5)
        path2.lineTo(13.5, 9)
        path2.lineTo(19, 9)
        p.drawPath(path2)
        p.drawLine(QPointF(9, 13), QPointF(16, 13))
        p.drawLine(QPointF(9, 16.5), QPointF(16, 16.5))
    elif name == "image":
        p.drawRoundedRect(QRectF(3.5, 5, 17, 14), 3, 3)
        p.drawEllipse(QRectF(7.2, 8.2, 2.6, 2.6))
        p.drawPolyline(QPolygonF([QPointF(4.6, 16.6), QPointF(9, 12),
                                  QPointF(12.4, 15.4), QPointF(15.4, 12.4),
                                  QPointF(19.4, 16.4)]))
    elif name == "archive":
        p.drawRoundedRect(QRectF(3.5, 7, 17, 13), 2.5, 2.5)
        p.drawLine(QPointF(3.5, 11), QPointF(20.5, 11))
        p.drawRoundedRect(QRectF(9.5, 11, 5, 3.5), 1, 1)
    elif name == "package":
        path = QPainterPath()
        path.moveTo(4, 14)
        path.lineTo(4, 18)
        path.quadTo(4, 20, 6, 20)
        path.lineTo(18, 20)
        path.quadTo(20, 20, 20, 18)
        path.lineTo(20, 14)
        p.drawPath(path)
        p.drawLine(QPointF(12, 4), QPointF(12, 14))
        p.drawPolyline(QPolygonF([QPointF(8.2, 10.2), QPointF(12, 14), QPointF(15.8, 10.2)]))
    elif name == "media":
        p.drawEllipse(QRectF(3.5, 3.5, 17, 17))
        p.drawPolygon(QPolygonF([QPointF(10.4, 8.8), QPointF(15.8, 12), QPointF(10.4, 15.2)]))
    elif name == "inbox":
        p.drawRoundedRect(QRectF(3.5, 5, 17, 14), 3, 3)
        p.drawPolyline(QPolygonF([QPointF(4, 12.5), QPointF(8.5, 12.5),
                                  QPointF(10, 15), QPointF(14, 15),
                                  QPointF(15.5, 12.5), QPointF(20, 12.5)]))
    elif name == "shield":
        path = QPainterPath()
        path.moveTo(12, 3)
        path.lineTo(20, 6)
        path.lineTo(20, 12)
        path.quadTo(20, 17.5, 12, 21)
        path.quadTo(4, 17.5, 4, 12)
        path.lineTo(4, 6)
        path.closeSubpath()
        p.drawPath(path)
        p.drawPolyline(QPolygonF([QPointF(8.6, 12), QPointF(11, 14.4), QPointF(15.6, 9.4)]))
    else:
        p.drawRoundedRect(QRectF(4, 4, 16, 16), 3, 3)

    p.end()
    ic = QIcon(pm)
    _ICON_CACHE[key] = ic
    return ic


_KIND_ICON = {"图片": "image", "文档": "file", "压缩包": "archive",
              "安装包": "package", "音视频": "media", "其他": "file"}


def kind_icon(kind: str, color: str = C.TXT2, size: int = 20) -> QIcon:
    return line_icon(_KIND_ICON.get(kind, "file"), color, size)


# --------------------------------------------------------------------------
# 通用小组件
# --------------------------------------------------------------------------
def role_lbl(text: str, role: str, parent=None) -> QLabel:
    lb = QLabel(text, parent)
    lb.setProperty("role", role)
    lb.setWordWrap(False)          # 标签短，不换行
    return lb


def hint_lbl(text: str) -> QLabel:
    """说明性小字：可换行，行高 1.5。一律走这里，不用 QSS 的 line-height——
    那个属性在 Qt 里被解析成换行，会让整行文字互相叠压。"""
    return wrap_par(text, C.TXT3, 12)


def sub_lbl(text: str) -> QLabel:
    """次级单行文字（状态、开关标签）：不换行，行高 1.5。"""
    lb = QLabel(html_par(text, C.TXT2, 12))
    lb.setWordWrap(False)
    return lb


def hr() -> QFrame:
    f = QFrame()
    f.setObjectName("Divider")
    f.setFixedHeight(1)
    return f


def html_par(text: str, color: str = C.TXT3, size: int = 12) -> str:
    body = text.replace("\n", "<br>")
    return (f'<div style="line-height:150%;color:{color};'
            f'font-size:{size}px;">{body}</div>')


class WrapLabel(QLabel):
    """可换行标签：行高 1.5 的富文本，最小高度按行数估算。

    关键约束：Qt 布局对「富文本 QLabel 按 heightForWidth 给高」的支持
    不可靠（真机上出现过 hint 被压扁裁字、控件被挤没）。这里不用
    heightForWidth，改为「按文字行数给最小高度」——多给一点余量，
    保证不裁字。
    """

    LINE_H = 24           # 一行：12px 文字 + 150% 行距 + margin

    def __init__(self, text: str = "", parent=None):
        super().__init__(text, parent)
        self.setWordWrap(True)
        self.setMinimumWidth(1)
        self.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Minimum)
        self._sync_min_h()

    def setText(self, text: str):
        super().setText(text)
        self._sync_min_h()
        self.updateGeometry()

    def _sync_min_h(self):
        fm = self.fontMetrics()
        plain = re.sub(r"<[^>]+>", "", self.text())
        w = self.width()
        if w <= 0:
            w = 320
        lines = 0
        for para in plain.splitlines() or [""]:
            lines += max(1, -(-fm.horizontalAdvance(para) // w))
        self.setMinimumHeight(lines * self.LINE_H + 8)

    def resizeEvent(self, e):
        super().resizeEvent(e)
        self._sync_min_h()


def wrap_par(text: str, color: str = C.TXT3, size: int = 12) -> WrapLabel:
    """说明文字 / 状态文字统一走这里：富文本行高 1.5，随宽度换行不裁字。"""
    return WrapLabel(html_par(text, color, size))


class Dot(QWidget):
    """状态色点：带一圈很淡的光晕，不做大色块。"""

    def __init__(self, size: int = 8, color: str = C.TXT3, parent=None):
        super().__init__(parent)
        self._size = size
        self._color = QColor(color)
        self.setFixedSize(size + 6, size + 6)

    def set_color(self, color: str):
        self._color = QColor(color)
        self.update()

    def paintEvent(self, _e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        halo = QColor(self._color)
        halo.setAlpha(52)
        p.setPen(Qt.NoPen)
        p.setBrush(halo)
        p.drawEllipse(QRectF(0, 0, self.width(), self.height()))
        p.setBrush(self._color)
        off = (self.width() - self._size) / 2.0
        p.drawEllipse(QRectF(off, off, self._size, self._size))
        p.end()


class StatusPill(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("Pill")
        lay = QHBoxLayout(self)
        lay.setContentsMargins(10, 4, 14, 4)
        lay.setSpacing(6)
        self.dot = Dot(8, C.DANGER)
        self.text = QLabel("服务已停止")
        self.text.setStyleSheet(f"color:{C.TXT2};font-size:12px;")
        lay.addWidget(self.dot)
        lay.addWidget(self.text)
        self.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Fixed)

    def set_state(self, running: bool, port: int | None = None):
        self.dot.set_color(C.OK if running else C.DANGER)
        txt = "服务运行中" if running else "服务已停止"
        if running and port:
            txt += f" · {port}"
        self.text.setText(txt)


class ElideLabel(QLabel):
    """单行省略标签：宽度不够时右侧出省略号，tooltip 里给全文。"""

    def __init__(self, text: str = "", color: str = C.TXT, size: int = 13,
                 mono: bool = False, parent=None):
        super().__init__(text, parent)
        self._color = QColor(color)
        f = QFont()
        f.setPixelSize(size)
        if mono:
            f.setFamilies(["Consolas", "Cascadia Mono", "JetBrains Mono"])
        self.setFont(f)
        self.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Fixed)
        self.setToolTip(text)

    def setText(self, text: str):
        super().setText(text)
        self.setToolTip(text)

    def set_color(self, color: str):
        self._color = QColor(color)
        self.update()

    def paintEvent(self, _e):
        p = QPainter(self)
        p.setPen(self._color)
        fm = self.fontMetrics()
        txt = fm.elidedText(self.text(), Qt.ElideRight, self.width())
        p.drawText(self.rect(), int(Qt.AlignLeft | Qt.AlignVCenter), txt)
        p.end()


class LogoMark(QWidget):
    def __init__(self, size: int = 40, parent=None):
        super().__init__(parent)
        self.setFixedSize(size, size)

    def paintEvent(self, _e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        w = self.width()
        p.setPen(QPen(QColor(C.LINE), 1))
        p.setBrush(QColor(C.CARD))
        p.drawRoundedRect(QRectF(0.5, 0.5, w - 1, w - 1), 12, 12)

        s = w / 24.0
        p.scale(s, s)
        p.translate(0, 0)
        pen = QPen(QColor(C.TEAL), 1.5 * 24.0 / w)
        pen.setCapStyle(Qt.RoundCap)
        p.setPen(pen)
        p.setBrush(Qt.NoBrush)
        cx, cy = 8.6, 16.0
        p.setBrush(QBrush(QColor(C.TEAL)))
        p.drawEllipse(QRectF(cx - 1.4, cy - 1.4, 2.8, 2.8))
        p.setBrush(Qt.NoBrush)
        for r in (5.2, 8.6, 12.0):
            p.drawArc(QRectF(cx - r, cy - r, 2 * r, 2 * r), 0, 90 * 16)
        p.end()


class ToggleSwitch(QAbstractButton):
    """44×24 的滑动开关，160ms 动效。"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setCheckable(True)
        self.setFixedSize(44, 24)
        self.setCursor(Qt.PointingHandCursor)
        self.setFocusPolicy(Qt.TabFocus)
        self._pos = 0.0
        self._anim = QVariantAnimation(self)
        self._anim.setDuration(160)
        self._anim.setEasingCurve(QEasingCurve.OutCubic)
        self._anim.valueChanged.connect(self._on_value)
        self.toggled.connect(self._animate)

    def _on_value(self, v):
        self._pos = float(v)
        self.update()

    def _animate(self, on: bool):
        self._anim.stop()
        self._anim.setStartValue(self._pos)
        self._anim.setEndValue(1.0 if on else 0.0)
        self._anim.start()

    def setChecked(self, checked: bool):      # noqa: N802 (Qt 命名)
        super().setChecked(checked)
        self._pos = 1.0 if checked else 0.0
        self.update()

    def paintEvent(self, _e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        r = QRectF(0.5, 0.5, self.width() - 1, self.height() - 1)
        if self.isChecked():
            track = QColor(C.TEAL)
        else:
            track = QColor("#2A3140")
        p.setPen(QPen(QColor(C.LINE) if not self.isChecked() else QColor(C.TEAL), 1))
        p.setBrush(track)
        p.drawRoundedRect(r, r.height() / 2, r.height() / 2)

        d = 18.0
        x = 3.0 + self._pos * (self.width() - d - 6.0)
        p.setPen(Qt.NoPen)
        p.setBrush(QColor("#E8EBF2") if self.isChecked() else QColor("#C7CEDA"))
        p.drawEllipse(QRectF(x, 3.0, d, d))

        if self.hasFocus():
            p.setBrush(Qt.NoBrush)
            p.setPen(QPen(QColor(79, 209, 197, 110), 1))
            p.drawRoundedRect(r.adjusted(-1, -1, 1, 1), r.height() / 2 + 1, r.height() / 2 + 1)
        p.end()


class EmptyState(QWidget):
    def __init__(self, icon: str, title: str, desc: str = "", foot: str = "",
                 parent=None):
        super().__init__(parent)
        v = QVBoxLayout(self)
        v.setContentsMargins(24, 24, 24, 24)
        v.setSpacing(0)
        v.addStretch(1)

        ic = QLabel()
        ic.setPixmap(line_icon(icon, C.TXT3, 32).pixmap(32, 32))
        ic.setAlignment(Qt.AlignCenter)
        v.addWidget(ic)
        v.addSpacing(16)

        t = QLabel(title)
        t.setProperty("role", "title")
        t.setAlignment(Qt.AlignCenter)
        v.addWidget(t)
        v.addSpacing(8)

        if desc:
            d = QLabel(html_par(desc, C.TXT3, 12))
            d.setWordWrap(True)
            d.setAlignment(Qt.AlignCenter)
            d.setFixedWidth(360)
            v.addWidget(d, 0, Qt.AlignHCenter)

        if foot:
            v.addSpacing(16)
            f = QLabel(html_par(foot, C.TXT3, 12))
            f.setWordWrap(True)
            f.setAlignment(Qt.AlignCenter)
            f.setFixedWidth(360)
            v.addWidget(f, 0, Qt.AlignHCenter)

        v.addStretch(1)


def _drag_chip(paths: list[Path]) -> QPixmap:
    """拖出时跟随光标的图：文件图标 + 文件名（多选显示数量）。"""
    label = paths[0].name if len(paths) == 1 else f"{len(paths)} 个文件"
    f = QFont()
    f.setPixelSize(13)
    fm = QFontMetrics(f)
    w = max(140, min(320, 44 + fm.horizontalAdvance(label) + 24))
    pm = QPixmap(w, 46)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing, True)
    p.setPen(QPen(QColor(C.LINE), 1))
    p.setBrush(QColor(22, 26, 33, 235))
    p.drawRoundedRect(QRectF(0.5, 0.5, w - 1, 45), 10, 10)
    icon = QFileIconProvider().icon(QFileInfo(str(paths[0])))
    icon.paint(p, QRectF(10, 11, 24, 24).toRect())
    p.setFont(f)
    p.setPen(QColor(C.TXT))
    p.drawText(QRectF(42, 0, w - 54, 46), Qt.AlignVCenter | Qt.AlignLeft,
               fm.elidedText(label, Qt.ElideMiddle, int(w - 54)))
    p.end()
    return pm


class FileDragTable(QTableWidget):
    """接收记录表：按住已保存的行拖出，发起标准 Windows 文件拖拽。

    只认列 2（文件名）上存的本地路径；单击 / 双击行为沿用 QTableWidget，
    位移超过系统拖拽阈值才启动拖拽，避免误触。
    """

    NAME_COL = 2

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._press_pos: QPoint | None = None
        self._dragging = False
        self.setAcceptDrops(False)
        self.viewport().setAcceptDrops(False)

    def _row_paths(self, rows) -> list[Path]:
        out: list[Path] = []
        for r in rows:
            item = self.item(r, self.NAME_COL)
            p = item.data(Qt.UserRole) if item is not None else None
            if not p:
                continue
            path = Path(str(p))
            if path.is_file() and path not in out:
                out.append(path)
        return out

    def mousePressEvent(self, e):
        if e.button() == Qt.LeftButton:
            self._press_pos = e.position().toPoint()
            self._dragging = False
        super().mousePressEvent(e)

    def mouseMoveEvent(self, e):
        if (self._press_pos is not None and not self._dragging
                and (e.buttons() & Qt.LeftButton)
                and (e.position().toPoint() - self._press_pos).manhattanLength()
                >= QApplication.startDragDistance()):
            rows = sorted({i.row() for i in self.selectedIndexes()})
            if not rows:
                idx = self.indexAt(self._press_pos)
                rows = [idx.row()] if idx.isValid() else []
            paths = self._row_paths(rows)
            if paths:
                self._dragging = True
                self._press_pos = None
                self._start_drag(paths)
                return
        super().mouseMoveEvent(e)

    def mouseReleaseEvent(self, e):
        self._press_pos = None
        super().mouseReleaseEvent(e)

    def _start_drag(self, paths: list[Path]):
        mime = QMimeData()
        # 只放 file URL：微信 / 钉钉 / 资源管理器拿到的是文件本身
        mime.setUrls([QUrl.fromLocalFile(str(p)) for p in paths])
        drag = QDrag(self)
        drag.setMimeData(mime)
        drag.setPixmap(_drag_chip(paths))
        drag.setHotSpot(QPoint(20, 23))
        drag.exec(Qt.CopyAction)


def _fmt_size(n: int) -> str:
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "—"
    if n < 1024:
        return f"{int(n)} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    if n < 1024 * 1024 * 1024:
        return f"{n / 1024 / 1024:.1f} MB"
    return f"{n / 1024 / 1024 / 1024:.2f} GB"


def _fmt_ts(ts) -> str:
    s = str(ts or "").strip()
    if not s:
        return "—"
    try:
        return datetime.fromisoformat(s).strftime("%m-%d %H:%M")
    except ValueError:
        return s[5:16].replace("T", " ") if len(s) >= 16 else s


# --------------------------------------------------------------------------
# 服务控制器
# --------------------------------------------------------------------------
class ServerController:
    """在后台线程跑 HTTP 服务，外加 UDP 发现与 BLE 广播。"""

    def __init__(self, log=print):
        self.log = log
        self.srv = None
        self.svc = None
        self.ble = None
        self.hotspot = None
        self.thread = None
        self.cfg = None
        self.port = 8765
        self.use_ble = True
        self.ble_error = ""
        self.running = False

    def start(self, port: int = 8765, use_ble: bool = True) -> tuple[bool, str]:
        if self.running:
            return True, "服务已在运行"
        self.port, self.use_ble = port, use_ble
        try:
            self.cfg = R.load_or_create_config()
            host = R.guess_lan_ip()

            self.svc = D.DiscoveryService(
                self.cfg, port, on_event=lambda m: self.log("[发现] " + m))
            self.svc.start()

            if use_ble:
                try:
                    from ble_announcer import BleAnnouncer
                    self.ble = BleAnnouncer(
                        self.cfg, port, D.local_addresses,
                        on_event=lambda m: self.log("[BLE] " + m))
                    self.ble.start()
                    # WinRT 首次初始化可能较慢，等足 1 s 再判定 alive，
                    # 否则自检会把「还没起来」误报成「BLE 不可用」。
                    time.sleep(1.0)
                except Exception as e:
                    self.ble_error = f"{type(e).__name__}: {e}"
                    self.log("[BLE] 组件未加载，已降级为局域网发现：" + self.ble_error)
                    self.ble = None

            self.srv = R.make_server(host, port, self.cfg,
                                     bind_host="0.0.0.0", discovery=self.svc)
            self.srv.state.ble = self.ble
            self.thread = threading.Thread(target=self.srv.serve_forever,
                                           daemon=True, name="nfctap-http")
            self.thread.start()
            self.running = True
            return True, f"已启动 {host}:{port}"
        except Exception as e:
            msg = repr(e)
            # 2026-11-13 实测：同时开两个实例时，第二个绑不上 8765，
            # 界面上只显示「已停止」，用户不知道是端口被占。给一句能看懂的话。
            if ("10048" in msg or "Address already in use" in msg
                    or "is already in use" in msg or "address in use" in msg.lower()):
                detail = (f"端口 {self.port} 已被占用：很可能已经有一个「一碰传」在运行。\n"
                          "请先关掉另一个窗口再启动；如果确认是别的程序占用，"
                          "可在「服务与设置」里换一个端口。")
                self.log("[错误] " + detail.replace("\n", " "))
                self.stop()
                return False, detail
            self.log("[错误] 启动失败：" + msg)
            self.stop()
            return False, msg

    def stop(self):
        if self.srv is not None:
            try:
                self.srv.shutdown()
                self.srv.server_close()
            except Exception:
                pass
        if self.svc is not None:
            try:
                self.svc.stop()
            except Exception:
                pass
        if self.ble is not None:
            try:
                self.ble.stop()
            except Exception:
                pass
        self.srv = self.svc = self.ble = self.thread = None
        self.running = False

    def ble_snapshot(self) -> dict:
        """BLE 的完整状态：是否在跑、断了的原因、以及给用户的建议。"""
        if not self.running:
            return {"enabled": False, "alive": False, "reason": "",
                    "reason_text": "", "advice": "", "detail": "", "status": ""}
        if self.ble is not None:
            try:
                return self.ble.snapshot()
            except Exception as e:
                return {"enabled": True, "alive": False, "reason": "start_failed",
                        "reason_text": "蓝牙广播状态读取失败",
                        "advice": "重启程序后再试；局域网发现仍可正常使用",
                        "detail": f"{type(e).__name__}: {e}", "status": ""}
        if not self.use_ble:
            return {"enabled": False, "alive": False, "reason": "",
                    "reason_text": "", "advice": "", "detail": "", "status": ""}
        return {"enabled": True, "alive": False, "reason": "start_failed",
                "reason_text": "蓝牙广播组件未加载",
                "advice": "重新运行安装包修复安装；局域网发现仍可正常使用",
                "detail": self.ble_error, "status": ""}

    def status(self) -> dict:
        st = self.srv.state if self.srv is not None else None
        return {
            "running": self.running,
            "port": self.port,
            "host": getattr(st, "host", "") if st else "",
            "device_id": getattr(st, "device_id", "") if st else "",
            "received_ok": getattr(st, "count_ok", 0) if st else 0,
            "duplicate": getattr(st, "count_dup", 0) if st else 0,
            "rejected": getattr(st, "count_reject", 0) if st else 0,
            "ble_state": self.ble_snapshot(),
            "ble": bool(self.ble and getattr(self.ble, "alive", False)),
            "addresses": D.local_addresses(),
        }


# --------------------------------------------------------------------------
# 自检模式（无界面）
# --------------------------------------------------------------------------
def run_selftest(port: int, use_ble: bool) -> int:
    import http.client
    import urllib.request

    out = {"app": APP_NAME, "product_version": APP_VERSION,
           "protocol": R.PROTOCOL, "protocol_version": R.VERSION,
           "data_dir": str(DATA_DIR), "port": port, "checks": {}}
    ctl = ServerController(log=lambda m: print(m))
    ok, msg = ctl.start(port=port + 1, use_ble=use_ble)   # 避开常用端口
    out["checks"]["服务启动"] = {"ok": ok, "detail": msg}
    time.sleep(1.0)
    if ok:
        base = "127.0.0.1", port + 1
        for name, path in (("ping", "/api/ping"), ("info", "/api/info"),
                           ("challenge", "/api/challenge")):
            try:
                c = http.client.HTTPConnection(*base, timeout=4)
                c.request("GET", path)
                r = c.getresponse()
                body = json.loads(r.read().decode("utf-8"))
                c.close()
                out["checks"][path] = {"ok": r.status == 200 and body.get("ok") is True,
                                       "status": r.status, "keys": sorted(body)[:8]}
            except Exception as e:
                out["checks"][path] = {"ok": False, "error": repr(e)}
        st = ctl.status()
        bs = st.get("ble_state") or {}
        out["checks"]["BLE 广播"] = {
            "ok": st["ble"] if use_ble else True,
            "enabled": use_ble,
            "alive": st["ble"],
            "publisher_status": bs.get("status", ""),
            "reason": bs.get("reason", ""),
            "reason_text": bs.get("reason_text", ""),
            "advice": bs.get("advice", ""),
            "detail": bs.get("detail", ""),
            "retrying": bs.get("retrying", False),
        }
        out["device_id"] = st["device_id"]
        _uri = R.build_pair_uri(ctl.cfg)
        # 6.2.2：自检结果不再写完整配对 URI（避免 k 以明文形式扩散到产物/日志）。
        out["pair_uri_fingerprint"] = "sha256:" + hashlib.sha256(
            _uri.encode("utf-8")).hexdigest()[:16]
        out["received_dir"] = str(R.RECEIVED_DIR)
        out["recent_count"] = len(R.read_recent(50))
    ctl.stop()
    out["all_pass"] = all(v.get("ok") for v in out["checks"].values())
    (DATA_DIR / "selftest_result.json").write_text(
        json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0 if out["all_pass"] else 1


# --------------------------------------------------------------------------
# GUI
# --------------------------------------------------------------------------
class MainWindow(QMainWindow):
    def __init__(self, port: int, use_ble: bool, auto_start: bool = True):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME}  v{APP_VERSION}")
        self.setMinimumSize(1000, 660)
        self.resize(1180, 760)
        self.ctl = ServerController(log=self.log_line)
        self.logs: list[str] = []
        self._last_log_size = -1
        self.port = port
        self.use_ble = use_ble
        self._ui_running = None
        self._preview_source: QPixmap | None = None
        # 发送到手机：本地待发队列（协议一次只暂存一个文件，其余排队）
        self._send_queue: list[Path] = []
        self._send_last_path: Path | None = None
        self._sent_check_id = ""
        self._sent_check_at = 0.0
        # 批量发送：一次点击把队列里的文件依次发完，结束后给一次汇总
        self._batch: dict | None = None
        self._batch_summary: dict | None = None
        self._in_send_refresh = False
        # 托盘：关窗只是收进托盘，接收服务与蓝牙广播继续在后台跑
        self._really_quit = False
        self._tray_tip_shown = False
        self._notify_baseline = False
        self._notify_ts = ""
        self.tray: QSystemTrayIcon | None = None
        self.setAcceptDrops(True)

        root = QWidget()
        root.setObjectName("Root")
        self.setCentralWidget(root)
        outer = QVBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        outer.addWidget(self._build_header())
        outer.addWidget(hr())

        body = QWidget()
        bl = QVBoxLayout(body)
        bl.setContentsMargins(24, 24, 24, 16)
        bl.setSpacing(24)
        bl.addWidget(self._build_overview())

        self.stack = QStackedWidget()
        # 页签顺序：接收文件 / 发送文件 / 服务与设置（文件目录已并入接收文件页）
        self.stack.addWidget(self._build_recent_tab())
        self.stack.addWidget(self._build_send_tab())
        self.stack.addWidget(self._build_settings_tab())
        bl.addWidget(self._build_nav())
        bl.addWidget(self.stack, 1)
        outer.addWidget(body, 1)

        self.setStatusBar(QStatusBar())
        self.statusBar().setFixedHeight(36)
        self.statusBar().setSizeGripEnabled(False)
        self.statusBar().showMessage("就绪")
        self.statusBar().addPermanentWidget(
            role_lbl("本地局域网直传 · 不上传云端", "hint"))
        self.statusBar().setContentsMargins(8, 0, 16, 0)

        self.btnToggle.clicked.connect(self.toggle_service)
        self.btnOpenDir.clicked.connect(lambda: self.open_path(DATA_DIR))
        self.btnOpenReceived.clicked.connect(lambda: self.open_path(R.RECEIVED_DIR))
        self.btnRefresh.clicked.connect(self.refresh_all)
        self.spinPort.valueChanged.connect(self._port_changed)
        self.chkBle.toggled.connect(self._ble_changed)
        self.chkAutostart.toggled.connect(self._autostart_toggled)
        self.btnCopyUri.clicked.connect(self.copy_uri)
        self.tableRecent.itemSelectionChanged.connect(self._on_recent_select)
        self.tableRecent.doubleClicked.connect(self.open_from_table)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.tick)
        self.timer.start(2000)

        self._init_tray()

        # 拖拽落区：盖住整窗的半透明提示层，只在拖入时出现
        self._drop_zone = self._build_drop_zone()
        for w in self.findChildren(QWidget):
            w.setAcceptDrops(False)

        if auto_start:
            self.toggle_service()
        self._sync_autostart_ui()
        self.refresh_all()

    def log_line(self, msg: str):
        self.logs.append(f"{time.strftime('%H:%M:%S')} {msg}")
        self.logs = self.logs[-200:]

    # ---------- 顶部 ----------
    def _build_header(self) -> QWidget:
        hdr = QWidget()
        hdr.setFixedHeight(76)
        h = QHBoxLayout(hdr)
        h.setContentsMargins(24, 0, 24, 0)
        h.setSpacing(12)

        h.addWidget(LogoMark(40))

        tb = QVBoxLayout()
        tb.setSpacing(2)
        t = role_lbl("一碰传", "display")
        s = role_lbl(f"桌面端 · v{APP_VERSION} · 碰一下，文件就到电脑", "sub")
        tb.addWidget(t)
        tb.addWidget(s)
        h.addLayout(tb)
        h.addStretch(1)

        self.pill = StatusPill()
        h.addWidget(self.pill)

        self.btnToggle = QPushButton("启动服务")
        self.btnToggle.setProperty("variant", "primary")
        self.btnToggle.setCursor(Qt.PointingHandCursor)
        self.btnToggle.setMinimumHeight(36)
        self.btnToggle.setIconSize(QSize(16, 16))
        h.addWidget(self.btnToggle)
        return hdr

    # ---------- 概览 ----------
    def _build_overview(self) -> QWidget:
        panel = QFrame()
        panel.setObjectName("Panel")
        g = QGridLayout(panel)
        g.setContentsMargins(24, 20, 24, 20)
        g.setHorizontalSpacing(24)
        g.setVerticalSpacing(4)

        # 设备 ID
        b1 = QVBoxLayout()
        b1.setSpacing(6)
        b1.addWidget(role_lbl("设备 ID", "label"))
        self.lbDevice = ElideLabel("—", C.TXT, 13, mono=True)
        b1.addWidget(self.lbDevice)
        b1.addWidget(role_lbl("由本机配对密钥派生", "hint"))
        g.addLayout(b1, 0, 0)

        # 局域网地址
        b2 = QVBoxLayout()
        b2.setSpacing(6)
        b2.addWidget(role_lbl("局域网地址", "label"))
        self.lbAddr = ElideLabel("—", C.TXT, 13, mono=True)
        b2.addWidget(self.lbAddr)
        b2.addWidget(role_lbl("手机与电脑需在同一网络", "hint"))
        g.addLayout(b2, 0, 1)

        # 计数
        b3 = QVBoxLayout()
        b3.setSpacing(6)
        b3.addWidget(role_lbl("接收统计", "label"))
        self.lbCounts = QLabel("0 / 0 / 0")
        self.lbCounts.setProperty("role", "stat")
        b3.addWidget(self.lbCounts)
        b3.addWidget(role_lbl("已接收 / 重复 / 拒绝", "hint"))
        g.addLayout(b3, 0, 2)

        # 广播
        b4 = QVBoxLayout()
        b4.setSpacing(6)
        b4.addWidget(role_lbl("广播状态", "label"))
        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(2)
        self.bleDot = Dot(8, C.TXT3)
        self.lbBle = QLabel("蓝牙广播未开启")
        self.lbBle.setStyleSheet(f"color:{C.TXT2};font-size:14px;")
        row.addWidget(self.bleDot)
        row.addWidget(self.lbBle)
        row.addStretch(1)
        b4.addLayout(row)
        self._portHint = role_lbl("UDP 发现随服务启动 · 端口 8765", "hint")
        b4.addWidget(self._portHint)
        g.addLayout(b4, 0, 3)

        for c in range(4):
            g.setColumnStretch(c, 1)
        return panel

    def _build_nav(self) -> QWidget:
        w = QWidget()
        h = QHBoxLayout(w)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(12)

        seg = QFrame()
        seg.setObjectName("Segmented")
        sl = QHBoxLayout(seg)
        sl.setContentsMargins(4, 4, 4, 4)
        sl.setSpacing(4)

        self.navGroup = QButtonGroup(self)
        self.navGroup.setExclusive(True)
        for i, name in enumerate(("接收文件", "发送文件", "服务与设置")):
            b = QPushButton(name)
            b.setProperty("variant", "seg")
            b.setCheckable(True)
            b.setCursor(Qt.PointingHandCursor)
            b.setMinimumHeight(30)
            self.navGroup.addButton(b, i)
            sl.addWidget(b)
        self.navGroup.idClicked.connect(self._switch_tab)
        self.navGroup.button(0).setChecked(True)
        h.addWidget(seg)
        h.addStretch(1)

        self.btnOpenDir = QPushButton("打开数据目录")
        self.btnOpenDir.setProperty("variant", "ghost")
        self.btnOpenDir.setIcon(line_icon("folder", C.TXT2, 16))
        self.btnOpenDir.setCursor(Qt.PointingHandCursor)
        self.btnOpenDir.setToolTip(str(DATA_DIR))

        self.btnOpenReceived = QPushButton("打开接收目录")
        self.btnOpenReceived.setProperty("variant", "ghost")
        self.btnOpenReceived.setIcon(line_icon("folder", C.TXT2, 16))
        self.btnOpenReceived.setCursor(Qt.PointingHandCursor)
        self.btnOpenReceived.setToolTip(str(R.RECEIVED_DIR))

        self.btnRefresh = QPushButton("刷新")
        self.btnRefresh.setProperty("variant", "ghost")
        self.btnRefresh.setIcon(line_icon("refresh", C.TXT2, 16))
        self.btnRefresh.setCursor(Qt.PointingHandCursor)

        for b in (self.btnOpenDir, self.btnOpenReceived, self.btnRefresh):
            b.setIconSize(QSize(16, 16))
            b.setMinimumHeight(34)
            h.addWidget(b)
        return w

    def _switch_tab(self, index: int):
        self.stack.setCurrentIndex(index)
        self.navGroup.button(index).setChecked(True)
        if index == 2:
            # 每次进入「服务与设置」都重读注册表，界面永远反映系统实际状态
            self._sync_autostart_ui()

    # ---------- 最近传输 ----------
    def _build_recent_tab(self) -> QWidget:
        split = QSplitter(Qt.Horizontal)
        split.setChildrenCollapsible(False)
        split.setHandleWidth(24)

        left = QFrame()
        left.setObjectName("Card")
        v = QVBoxLayout(left)
        v.setContentsMargins(24, 20, 24, 16)
        v.setSpacing(16)

        head = QHBoxLayout()
        head.setSpacing(12)
        tv = QVBoxLayout()
        tv.setSpacing(2)
        tv.addWidget(role_lbl("接收文件", "title"))
        h1 = hint_lbl("最近 50 条传输记录 · 每 2 秒自动刷新")
        h2 = hint_lbl("点选预览 · 双击打开 · 按住可拖到微信、钉钉、资源管理器")
        for lb in (h1, h2):
            lb.setWordWrap(False)     # 标题区文字短，不换行，避免被挤成竖排
            lb.setMinimumWidth(380)   # 给足宽度，避免被截断
        tv.addWidget(h1)
        tv.addWidget(h2)
        head.addLayout(tv, 1)
        head.addStretch(1)
        self.lbRecentCount = role_lbl("", "hint")
        head.addWidget(self.lbRecentCount)
        v.addLayout(head)

        self.tableRecent = FileDragTable(0, 6)
        self.tableRecent.setHorizontalHeaderLabels(
            ["时间", "结果", "文件名", "大小", "类型", "来源"])
        self.tableRecent.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tableRecent.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tableRecent.setSelectionMode(QAbstractItemView.SingleSelection)
        self.tableRecent.setShowGrid(False)
        self.tableRecent.setWordWrap(False)
        self.tableRecent.setTextElideMode(Qt.ElideMiddle)
        self.tableRecent.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.tableRecent.verticalHeader().setVisible(False)
        self.tableRecent.verticalHeader().setDefaultSectionSize(44)
        hh = self.tableRecent.horizontalHeader()
        hh.setFixedHeight(40)
        hh.setHighlightSections(False)
        hh.setSectionsClickable(False)
        hh.setSectionResizeMode(QHeaderView.Fixed)
        hh.setSectionResizeMode(2, QHeaderView.Stretch)
        for col, w in ((0, 92), (1, 96), (3, 88), (4, 76), (5, 112)):
            self.tableRecent.setColumnWidth(col, w)
        for col in range(6):
            self.tableRecent.horizontalHeaderItem(col).setTextAlignment(
                int(Qt.AlignLeft | Qt.AlignVCenter))
        self.tableRecent.horizontalHeaderItem(3).setTextAlignment(
            int(Qt.AlignRight | Qt.AlignVCenter))

        self.recentStack = QStackedWidget()
        self.recentStack.addWidget(self.tableRecent)
        self.recentStack.addWidget(EmptyState(
            "inbox",
            "还没有传输记录",
            "手机碰一下 NFC 标签，选择文件，就能把内容传到这台电脑。",
            "记录保存在本机 transfer.log.jsonl，不上传云端。"))
        v.addWidget(self.recentStack, 1)
        split.addWidget(left)

        right = QFrame()
        right.setObjectName("Card")
        rv = QVBoxLayout(right)
        rv.setContentsMargins(24, 20, 24, 16)
        rv.setSpacing(16)

        rh = QHBoxLayout()
        rh.addWidget(role_lbl("预览", "title"))
        rh.addStretch(1)
        hd = hint_lbl("双击打开文件")
        hd.setWordWrap(False)
        rh.addWidget(hd)
        rv.addLayout(rh)

        self.previewStack = QStackedWidget()

        self.previewStack.addWidget(EmptyState(
            "image",
            "尚未选择文件",
            "从左侧点选一条记录，图片会在这里直接显示。"))

        stage = QFrame()
        stage.setObjectName("Stage")
        sv = QVBoxLayout(stage)
        sv.setContentsMargins(8, 8, 8, 8)
        self.preview = QLabel()
        self.preview.setAlignment(Qt.AlignCenter)
        self.preview.setMinimumSize(320, 240)
        self.preview.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Ignored)
        self.preview.setStyleSheet("background: transparent;")
        sv.addWidget(self.preview, 1)
        self.previewStack.addWidget(stage)

        info = QWidget()
        iv = QVBoxLayout(info)
        iv.setContentsMargins(24, 24, 24, 24)
        iv.setSpacing(0)
        iv.addStretch(1)
        self.infoIcon = QLabel()
        self.infoIcon.setAlignment(Qt.AlignCenter)
        iv.addWidget(self.infoIcon)
        iv.addSpacing(16)
        self.infoName = QLabel("—")
        self.infoName.setWordWrap(True)
        self.infoName.setAlignment(Qt.AlignCenter)
        self.infoName.setStyleSheet(f"color:{C.TXT};font-size:16px;font-weight:600;")
        iv.addWidget(self.infoName)
        iv.addSpacing(8)
        self.infoMeta = QLabel("")
        self.infoMeta.setAlignment(Qt.AlignCenter)
        self.infoMeta.setProperty("role", "hint")
        iv.addWidget(self.infoMeta)
        iv.addSpacing(16)
        self.infoHint = QLabel(html_par("双击可用系统默认程序打开", C.TXT3, 12))
        self.infoHint.setAlignment(Qt.AlignCenter)
        iv.addWidget(self.infoHint)
        iv.addStretch(1)
        self.previewStack.addWidget(info)

        rv.addWidget(self.previewStack, 1)

        self.lbFileInfo = QLabel("—")
        self.lbFileInfo.setWordWrap(True)
        self.lbFileInfo.setStyleSheet(f"color:{C.TXT3};font-size:12px;")
        self.lbFileInfo.setVisible(False)
        rv.addWidget(self.lbFileInfo)

        split.addWidget(right)
        split.setStretchFactor(0, 1)
        split.setStretchFactor(1, 1)
        split.setSizes([520, 560])
        return split

    # ---------- 发送到手机 ----------
    def _build_send_tab(self) -> QWidget:
        card = QFrame()
        card.setObjectName("Card")
        v = QVBoxLayout(card)
        v.setContentsMargins(24, 20, 24, 20)
        v.setSpacing(16)

        tv = QVBoxLayout()
        tv.setSpacing(2)
        tv.addWidget(role_lbl("发送文件", "title"))
        tv.addWidget(role_lbl(
            "把文件拖进窗口，或点「选择文件」；点「发送」后手机碰一下 NFC 标签即可自动接收", "hint"))
        v.addLayout(tv)
        v.addSpacing(8)
        v.addWidget(hr())
        v.addSpacing(8)

        g = QGridLayout()
        g.setHorizontalSpacing(24)
        g.setVerticalSpacing(10)
        g.setColumnMinimumWidth(0, 88)
        g.setColumnStretch(1, 1)

        g.addWidget(role_lbl("待发文件", "label"), 0, 0, Qt.AlignTop)
        self.lbSendFile = ElideLabel("尚未选择文件", C.TXT2, 14)
        self.lbSendFile.setToolTip("")
        g.addWidget(self.lbSendFile, 0, 1)

        g.addWidget(role_lbl("文件信息", "label"), 1, 0, Qt.AlignTop)
        self.lbSendMeta = QLabel("大小 — · 类型 —")
        self.lbSendMeta.setStyleSheet(f"color:{C.TXT2};font-size:13px;")
        g.addWidget(self.lbSendMeta, 1, 1)

        g.addWidget(role_lbl("当前状态", "label"), 2, 0, Qt.AlignTop)
        self.lbSendState = QLabel("等待操作")
        self.lbSendState.setWordWrap(True)
        self.lbSendState.setStyleSheet(f"color:{C.TXT2};font-size:13px;")
        g.addWidget(self.lbSendState, 2, 1)

        g.addWidget(role_lbl("待发队列", "label"), 3, 0, Qt.AlignTop)
        self.lbSendQueue = QLabel("")
        self.lbSendQueue.setWordWrap(True)
        self.lbSendQueue.setStyleSheet(f"color:{C.TXT3};font-size:12px;")
        self.lbSendQueue.setVisible(False)
        g.addWidget(self.lbSendQueue, 3, 1)
        v.addLayout(g)

        self.lbSendSummary = QLabel("")
        self.lbSendSummary.setWordWrap(True)
        self.lbSendSummary.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.lbSendSummary.setStyleSheet(f"color:{C.TXT2};font-size:12px;")
        self.lbSendSummary.setVisible(False)
        v.addWidget(self.lbSendSummary)

        row = QHBoxLayout()
        row.setSpacing(10)
        self.btnPickSend = QPushButton("选择文件")
        self.btnPickSend.setProperty("variant", "ghost")
        self.btnPickSend.setCursor(Qt.PointingHandCursor)
        self.btnPickSend.setMinimumHeight(36)
        self.btnSendTap = QPushButton("发送")
        self.btnSendTap.setProperty("variant", "primary")
        self.btnSendTap.setCursor(Qt.PointingHandCursor)
        self.btnSendTap.setMinimumHeight(36)
        self.btnCancelSend = QPushButton("取消待发")
        self.btnCancelSend.setProperty("variant", "ghost")
        self.btnCancelSend.setCursor(Qt.PointingHandCursor)
        self.btnCancelSend.setMinimumHeight(36)
        self.btnRetryFailed = QPushButton("重试失败的文件")
        self.btnRetryFailed.setCursor(Qt.PointingHandCursor)
        self.btnRetryFailed.setMinimumHeight(36)
        self.btnRetryFailed.setVisible(False)
        row.addWidget(self.btnPickSend)
        row.addWidget(self.btnSendTap)
        row.addWidget(self.btnCancelSend)
        row.addWidget(self.btnRetryFailed)
        row.addStretch(1)
        v.addLayout(row)

        note = wrap_par(
            f"支持 APK、图片、文档、压缩包等任意文件，单文件上限 {R.MAX_UPLOAD_LABEL}。"
            "可一次拖入多个文件，点一次「发送」会把队列里的文件依次发完："
            "手机每碰一次标签取走一个，中途单个失败不会中断后续文件，"
            "全部结束后给出成功 / 失败汇总，失败文件可直接重试。"
            "手机接收成功后待发状态自动清空。", C.TXT3, 12)
        v.addWidget(note)
        v.addStretch(1)

        self.btnPickSend.clicked.connect(self.pick_send_file)
        self.btnSendTap.clicked.connect(self.start_send_batch)
        self.btnCancelSend.clicked.connect(self.cancel_send_file)
        self.btnRetryFailed.clicked.connect(self.retry_failed_files)
        self._refresh_send_ui()
        return card

    # ---- 拖拽落区 ----
    def _build_drop_zone(self) -> QFrame:
        """拖入时覆盖整窗的落区提示；鼠标穿透，不抢 drop 事件。"""
        ov = QFrame(self)
        ov.setObjectName("DropZone")
        ov.setAttribute(Qt.WA_StyledBackground, True)
        ov.setAttribute(Qt.WA_TransparentForMouseEvents, True)
        v = QVBoxLayout(ov)
        v.setContentsMargins(32, 32, 32, 32)
        v.addStretch(1)
        t = QLabel("松开鼠标，加入待发队列")
        t.setAlignment(Qt.AlignCenter)
        f = QFont(t.font())
        f.setPixelSize(24)
        f.setBold(True)
        t.setFont(f)
        t.setStyleSheet(f"color:{C.TXT};")
        v.addWidget(t)
        s = QLabel(f"支持一次拖入多个文件 · 单个不超过 {R.MAX_UPLOAD_LABEL} · 手机碰标签即可接收")
        s.setAlignment(Qt.AlignCenter)
        s.setStyleSheet(f"color:{C.TXT2};font-size:13px;")
        v.addWidget(s)
        v.addStretch(1)
        ov.hide()
        return ov

    def _local_paths(self, mime) -> list[Path]:
        if mime is None or not mime.hasUrls():
            return []
        return [Path(u.toLocalFile()) for u in mime.urls() if u.isLocalFile()]

    def _show_drop_zone(self, on: bool):
        zone = getattr(self, "_drop_zone", None)
        if zone is None:
            return
        if on:
            zone.setGeometry(0, 0, self.width(), self.height())
            zone.raise_()
            zone.show()
        else:
            zone.hide()

    def dragEnterEvent(self, e):
        if any(p.is_file() for p in self._local_paths(e.mimeData())):
            e.acceptProposedAction()
            self._show_drop_zone(True)
        else:
            e.ignore()

    def dragMoveEvent(self, e):
        if any(p.is_file() for p in self._local_paths(e.mimeData())):
            e.acceptProposedAction()
        else:
            e.ignore()

    def dragLeaveEvent(self, e):
        self._show_drop_zone(False)

    def dropEvent(self, e):
        self._show_drop_zone(False)
        files = [p for p in self._local_paths(e.mimeData()) if p.is_file()]
        if not files:
            e.ignore()
            return
        e.acceptProposedAction()
        self._enqueue_send_files(files, dropped=True)

    # ---- 待发队列与发送状态 ----
    def _status_msg(self, text: str, ms: int = 6000):
        sb = self.statusBar()
        if sb is not None:
            sb.showMessage(text, ms)

    def _enqueue_send_files(self, paths: list[Path], dropped: bool = False):
        added, rejected = [], []
        known = {str(p.resolve()).lower() for p in self._send_queue}
        for p in paths:
            try:
                size = p.stat().st_size
            except OSError:
                rejected.append((p.name, "无法读取"))
                continue
            key = str(p.resolve()).lower()
            if key in known:
                rejected.append((p.name, "已在队列里"))
                continue
            if size <= 0:
                rejected.append((p.name, "空文件"))
                continue
            if size > R.MAX_UPLOAD:
                rejected.append(
                    (p.name, f"超过 {R.MAX_UPLOAD_LABEL} 上限"))
                continue
            known.add(key)
            added.append(p)
        self._send_queue.extend(added)
        if added:
            self._batch_summary = None      # 新选择取代上一批的汇总
            self._switch_tab(1)      # 发送文件页签
            msg = (f"已加入待发队列：{added[0].name}" if len(added) == 1
                   else f"已加入 {len(added)} 个文件到待发队列")
            self._status_msg(msg, 8000)
            self.log_line(f"[发送到手机] {msg}")
        if rejected:
            lines = "\n".join(f"· {n}：{why}" for n, why in rejected[:6])
            more = "" if len(rejected) <= 6 else f"\n…另有 {len(rejected) - 6} 个"
            QMessageBox.warning(self, APP_NAME, f"以下文件未加入队列：\n{lines}{more}")
        self._refresh_send_ui()

    def pick_send_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "选择要发送到手机的文件", str(Path.home()), "所有文件 (*)")
        if path:
            self._enqueue_send_files([Path(path)])

    # ---- 批量发送：一次点击把队列里的文件依次发完 ----
    def start_send_batch(self):
        """「发送」：把队列整体转成一批，逐个暂存给手机；单个失败不中断。"""
        if self._batch is not None:
            return
        with R.OUTBOX_LOCK:
            cur = R.read_outbox_locked()
        if cur and not cur.get("claimed"):
            self._status_msg(
                "已有待发文件，手机碰标签即可接收；要换文件请先点「取消待发」", 8000)
            self._refresh_send_ui()
            return
        if self._send_queue:
            src, self._send_queue = list(self._send_queue), []
        elif self._send_last_path is not None:
            src = [self._send_last_path]
        else:
            QMessageBox.information(
                self, APP_NAME, "请先把文件拖进窗口，或点「选择文件」")
            return
        items = []
        for p in src:
            try:
                size = p.stat().st_size
            except OSError:
                size = 0
            items.append({"path": p, "name": p.name, "size": size,
                          "status": "pending", "reason": ""})
        self._batch = {"items": items, "index": 0, "outbox_id": "",
                       "staged_at": 0.0, "claimed_at": 0.0}
        self._batch_summary = None
        self.log_line(f"[发送到手机] 开始批量发送：共 {len(items)} 个文件")
        self._stage_batch_item()
        self._refresh_send_ui()

    def _stage_batch_item(self):
        """暂存当前这一项；失败就记为失败并继续下一项，不打断整批。"""
        b = self._batch
        if b is None:
            return
        items, n = b["items"], len(b["items"])
        while b["index"] < n:
            i, it = b["index"], items[b["index"]]
            try:
                meta = R.stage_outbox(it["path"])
            except (OSError, ValueError) as e:
                it["status"] = "fail"
                it["reason"] = str(e) or "无法暂存"
                self.log_line(f"[发送到手机] {i + 1}/{n} 失败：{it['name']}"
                              f"（{it['reason']}）")
                b["index"] = i + 1
                b["outbox_id"] = ""
                b["staged_at"] = 0.0
                b["claimed_at"] = 0.0
                continue
            it["status"] = "sending"
            b["outbox_id"] = str(meta.get("id") or "")
            b["staged_at"] = time.time()
            b["claimed_at"] = 0.0
            self._send_last_path = it["path"]
            self.log_line(f"[发送到手机] {i + 1}/{n} 已暂存 "
                          f"{meta['name']} / {meta['bytes']} 字节")
            self._status_msg(
                f"正在发送 {i + 1}/{n}：{meta['name']}，等待手机碰标签", 8000)
            return
        self._finish_batch()

    def _advance_batch(self):
        """每 2 秒检查一次当前这一项：送达 / 失败 / 继续等待。"""
        b = self._batch
        if b is None or not b["outbox_id"]:
            return
        with R.OUTBOX_LOCK:
            meta = R.read_outbox_locked()
        if meta is None:
            self._batch_finish_item(False, "待发文件已丢失，请重试")
            return
        if str(meta.get("id")) != b["outbox_id"]:
            return                       # 不是本批次的暂存，等下一轮
        if not meta.get("claimed"):
            return                       # 还没碰标签
        if not b["claimed_at"]:
            b["claimed_at"] = time.time()
        if self._log_has(meta, "sent"):
            self._batch_finish_item(True)
            return
        if self._log_has(meta, "failed"):
            self._batch_finish_item(False, "手机端接收中断，文件未送达")
            return
        if time.time() - b["claimed_at"] > self._deliver_timeout(meta):
            self._batch_finish_item(False, "等待手机确认超时")

    def _batch_finish_item(self, ok: bool, reason: str = ""):
        b = self._batch
        if b is None:
            return
        i, n = b["index"], len(b["items"])
        it = b["items"][i]
        it["status"] = "ok" if ok else "fail"
        it["reason"] = "" if ok else (reason or "发送失败")
        with R.OUTBOX_LOCK:
            cur = R.read_outbox_locked()
            if cur and str(cur.get("id")) == b["outbox_id"]:
                R.cancel_outbox_locked()
        if ok:
            self.log_line(f"[发送到手机] {i + 1}/{n} 已送达手机：{it['name']}")
            self._status_msg(f"{i + 1}/{n} 已送达「{it['name']}」", 8000)
        else:
            self.log_line(f"[发送到手机] {i + 1}/{n} 失败：{it['name']}"
                          f"（{it['reason']}）")
            self._status_msg(f"{i + 1}/{n} 失败：{it['name']}", 8000)
        b["index"] = i + 1
        b["outbox_id"] = ""
        b["staged_at"] = 0.0
        b["claimed_at"] = 0.0
        self._stage_batch_item()

    def _finish_batch(self):
        b = self._batch
        if b is None:
            return
        items = b["items"]
        total = len(items)
        failed = [it for it in items if it["status"] == "fail"]
        ok = sum(1 for it in items if it["status"] == "ok")
        self._batch = None
        self._batch_summary = {"total": total, "ok": ok, "failed": failed}
        self._sent_check_id = ""
        self._sent_check_at = 0.0
        self.log_line(f"[发送到手机] 批量发送结束：共 {total} 个，"
                      f"成功 {ok} 个，失败 {len(failed)} 个")
        if failed:
            names = "、".join(it["name"] for it in failed[:5])
            self._status_msg(
                f"批量发送结束：成功 {ok}/{total}，失败 {len(failed)}"
                f"（{names}）", 12000)
        else:
            self._status_msg(f"批量发送结束：{total} 个文件全部发送成功", 12000)

    def retry_failed_files(self):
        """汇总里的失败项直接退回队列，再走一遍同样的批量流程。"""
        s = self._batch_summary
        if not s or not s["failed"]:
            return
        paths = [it["path"] for it in s["failed"] if isinstance(it.get("path"), Path)]
        if not paths:
            return
        self._batch_summary = None
        self._send_queue = paths + self._send_queue
        self.log_line(f"[发送到手机] 重试 {len(paths)} 个失败文件")
        self.start_send_batch()

    def _deliver_timeout(self, meta: dict) -> float:
        """claimed 之后等 sent/failed 的上限：120 秒 + 按 1 MB/s 的下限估算。"""
        return 120.0 + max(0, int(meta.get("bytes") or 0)) / (1024 * 1024)

    def cancel_send_file(self):
        b = self._batch
        n = len(self._send_queue)
        done = 0
        rest = 0
        if b is not None:
            done = sum(1 for it in b["items"] if it["status"] == "ok")
            rest = len(b["items"]) - done - sum(
                1 for it in b["items"] if it["status"] == "fail")
            self._batch = None
        with R.OUTBOX_LOCK:
            R.cancel_outbox_locked()
        self._send_queue.clear()
        self._sent_check_id = ""
        self._batch_summary = None
        if b is not None:
            self.log_line(f"[发送到手机] 已中止批量发送（完成 {done} 个，"
                          f"未发送 {rest} 个）")
            self._status_msg("已中止批量发送，待发队列已清空", 8000)
        else:
            self.log_line(f"[发送到手机] 已取消 {n} 个待发文件" if n
                          else "[发送到手机] 已取消待发文件")
            self._status_msg("已取消待发文件", 6000)
        self._refresh_send_ui()

    def _log_has(self, meta: dict, result: str) -> bool:
        """日志里是否有这个文件（sha256 相同、时间不早于 claim）的指定结果。"""
        sha = str(meta.get("sha256") or "")
        since = str(meta.get("claimed_at") or "")
        try:
            rows = R.read_recent(80)
        except (OSError, ValueError):
            rows = []
        for it in rows:
            if it.get("result") != result or it.get("sha256") != sha:
                continue
            if not since or str(it.get("ts") or "") >= since:
                return True
        return False

    def _send_delivered(self, meta: dict) -> bool:
        """手机上是否真收下了：outbox 已 claim 且日志里出现对应的 sent 记录。"""
        mid = str(meta.get("id") or "")
        if mid != self._sent_check_id:
            self._sent_check_id = mid
            self._sent_check_at = time.time()
        return self._log_has(meta, "sent")

    def _clear_sent_outbox(self, meta: dict):
        """手机确认收到后清掉暂存，回到可继续添加的空态。"""
        with R.OUTBOX_LOCK:
            cur = R.read_outbox_locked()
            if cur and cur.get("id") == meta.get("id") and cur.get("claimed"):
                R.cancel_outbox_locked()
        self._sent_check_id = ""
        name = meta.get("name") or ""
        self.log_line(f"[发送到手机] 手机已接收「{name}」，待发状态已自动清空")
        self._status_msg(f"「{name}」已发送到手机", 8000)

    def _refresh_send_ui(self):
        if self._in_send_refresh:
            return
        self._in_send_refresh = True
        try:
            meta = None
            confirming = False
            if self._batch is not None:
                self._advance_batch()
            else:
                with R.OUTBOX_LOCK:
                    meta = R.read_outbox_locked()
                if meta and meta.get("claimed"):
                    if self._send_delivered(meta):
                        self._clear_sent_outbox(meta)
                        with R.OUTBOX_LOCK:
                            meta = R.read_outbox_locked()
                    else:
                        # 刚 claim、日志尚未落盘：给 8 秒确认窗口
                        confirming = (time.time() - self._sent_check_at) < 8.0
            self._render_send_ui(meta, confirming)
        finally:
            self._in_send_refresh = False

    def _set_send_file(self, name: str, size: int, color: str):
        self.lbSendFile.setText(name)
        self.lbSendFile.set_color(color)
        self.lbSendFile.setToolTip(name)
        self.lbSendMeta.setText(
            f"大小 {_fmt_size(size)} · 类型 "
            f"{R.EXT_MIME.get(Path(name).suffix.lower(), '未知/二进制')}")

    def _render_batch_ui(self, b: dict):
        items, n = b["items"], len(b["items"])
        i = b["index"]
        if i >= n:
            return
        it = items[i]
        done = sum(1 for x in items if x["status"] in ("ok", "fail"))
        self._set_send_file(it["name"], int(it["size"] or 0), C.TXT)
        with R.OUTBOX_LOCK:
            cur = R.read_outbox_locked()
        receiving = bool(cur and str(cur.get("id")) == b["outbox_id"]
                         and cur.get("claimed"))
        if receiving:
            self.lbSendState.setText(
                f"正在发送 {i + 1}/{n}：{it['name']} · 手机正在接收…")
            self.lbSendState.setStyleSheet(f"color:{C.INDIGO};font-size:13px;")
        else:
            self.lbSendState.setText(
                f"正在发送 {i + 1}/{n}：{it['name']} · 等待手机碰标签")
            self.lbSendState.setStyleSheet(f"color:{C.OK};font-size:13px;")
        self.lbSendQueue.setText(
            f"本批共 {n} 个，已完成 {done} 个；单个失败不会中断后续文件")
        self.lbSendQueue.setVisible(True)
        self.lbSendSummary.setVisible(False)
        self.btnRetryFailed.setVisible(False)
        self.btnSendTap.setEnabled(False)
        self.btnPickSend.setEnabled(False)
        self.btnCancelSend.setEnabled(True)

    def _render_summary_ui(self, s: dict):
        total, ok = s["total"], s["ok"]
        failed = s["failed"]
        self.lbSendFile.setText(f"本批已结束：共 {total} 个文件")
        self.lbSendFile.set_color(C.TXT)
        self.lbSendFile.setToolTip("")
        self.lbSendMeta.setText(f"成功 {ok} 个 · 失败 {len(failed)} 个")
        if failed:
            self.lbSendState.setText(
                f"发送完成：共 {total} 个，成功 {ok} 个，失败 {len(failed)} 个")
            self.lbSendState.setStyleSheet(f"color:{C.WARN};font-size:13px;")
            lines = "\n".join(f"· {it['name']}：{it['reason']}" for it in failed[:8])
            more = "" if len(failed) <= 8 else f"\n…另有 {len(failed) - 8} 个失败文件"
            self.lbSendSummary.setText(f"失败文件（可直接重试）：\n{lines}{more}")
        else:
            self.lbSendState.setText(f"发送完成：共 {total} 个，全部成功")
            self.lbSendState.setStyleSheet(f"color:{C.OK};font-size:13px;")
            self.lbSendSummary.setText("")
        self.lbSendSummary.setVisible(bool(failed))
        self.lbSendQueue.setVisible(False)
        self.btnRetryFailed.setText(f"重试失败的 {len(failed)} 个文件")
        self.btnRetryFailed.setVisible(bool(failed))
        self.btnSendTap.setEnabled(bool(self._send_queue))
        self.btnPickSend.setEnabled(True)
        self.btnCancelSend.setEnabled(bool(self._send_queue))

    def _render_send_ui(self, meta: dict | None, confirming: bool = False):
        if self._batch is not None:
            self._render_batch_ui(self._batch)
            return
        if self._batch_summary is not None:
            self._render_summary_ui(self._batch_summary)
            return

        active = meta if (meta and not meta.get("claimed")) else None
        if active:
            self._set_send_file(str(active.get("name") or ""),
                                int(active.get("bytes") or 0), C.TXT)
            self.lbSendState.setText("待发送：手机碰一下 NFC 标签即可接收")
            self.lbSendState.setStyleSheet(f"color:{C.OK};font-size:13px;")
        elif meta:
            name = str(meta.get("name") or "")
            self._set_send_file(name, int(meta.get("bytes") or 0), C.TXT2)
            if confirming:
                self.lbSendState.setText(f"手机正在接收「{name}」…")
                self.lbSendState.setStyleSheet(f"color:{C.INDIGO};font-size:13px;")
            else:
                self.lbSendState.setText(
                    "已由手机接收；需要再发一次请重新点「发送」")
                self.lbSendState.setStyleSheet(f"color:{C.WARN};font-size:13px;")
        elif self._send_queue:
            p = self._send_queue[0]
            try:
                size = p.stat().st_size
            except OSError:
                size = 0
            self._set_send_file(p.name, size, C.TXT)
            self.lbSendState.setText("已选择，点「发送」后等待手机碰标签")
            self.lbSendState.setStyleSheet(f"color:{C.TXT2};font-size:13px;")
        else:
            self.lbSendFile.setText("尚未选择文件")
            self.lbSendFile.set_color(C.TXT2)
            self.lbSendFile.setToolTip("")
            self.lbSendMeta.setText("大小 — · 类型 —")
            self.lbSendState.setText(
                "没有待发文件。把文件拖进窗口，或点「选择文件」，再点「发送」。")
            self.lbSendState.setStyleSheet(f"color:{C.TXT2};font-size:13px;")

        rest = len(self._send_queue)
        if active or meta:
            queue_note = (f"另有 {rest} 个文件排队，当前文件发完后再逐个发送"
                          if rest else "")
        else:
            queue_note = (f"队列中还有 {rest - 1} 个文件，点一次「发送」会依次发完"
                          if rest > 1 else "")
        self.lbSendQueue.setText(queue_note)
        self.lbSendQueue.setVisible(bool(queue_note))
        self.lbSendSummary.setVisible(False)
        self.btnRetryFailed.setVisible(False)
        self.btnPickSend.setEnabled(True)

        self.btnSendTap.setEnabled(
            (bool(self._send_queue)
             or (meta is not None and self._send_last_path is not None))
            and active is None)
        self.btnCancelSend.setEnabled(bool(meta) or bool(self._send_queue))

    # ---------- 服务与设置 ----------
    def _build_settings_tab(self) -> QWidget:
        page = QWidget()
        outer = QHBoxLayout(page)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(24)

        # 服务卡
        card = QFrame()
        card.setObjectName("Card")
        v = QVBoxLayout(card)
        v.setContentsMargins(24, 20, 24, 20)
        v.setSpacing(0)

        tv = QVBoxLayout()
        tv.setSpacing(2)
        tv.addWidget(role_lbl("服务", "title"))
        hh = hint_lbl("改动端口或蓝牙开关后，需要重启服务生效")
        hh.setWordWrap(False)
        tv.addWidget(hh)
        v.addLayout(tv)
        v.addSpacing(16)

        g = QVBoxLayout()
        g.setContentsMargins(0, 0, 0, 0)
        g.setSpacing(10)

        # 一行 = 左标签（固定 88px）+ 右控件列（自适应宽度、按内容撑高）
        def kv_row(label: str, widget: QWidget,
                   hint: str | None = None, sub: QWidget | None = None):
            fr = QFrame()
            fr.setStyleSheet("background: transparent;")
            outer = QHBoxLayout(fr)
            outer.setContentsMargins(0, 0, 0, 0)
            outer.setSpacing(24)
            kl = role_lbl(label, "label")
            kl.setFixedWidth(88)
            kl.setAlignment(Qt.AlignTop | Qt.AlignLeft)
            outer.addWidget(kl)
            cell = QVBoxLayout()
            cell.setSpacing(6)
            cell.addWidget(widget)
            if sub is not None:
                cell.addWidget(sub)
            if hint:
                cell.addWidget(wrap_par(hint, C.TXT3, 12))
            outer.addLayout(cell, 1)
            # 高度按内容给：控件行 + hint 行 + 状态行，每行约 44px
            rows = 1 + (1 if sub is not None else 0) + (1 if hint else 0)
            fr.setFixedHeight(rows * 44 + 20)
            return fr

        # 端口
        prow = QHBoxLayout()
        prow.setSpacing(8)
        self.spinPort = QSpinBox()
        self.spinPort.setRange(1024, 65535)
        self.spinPort.setValue(self.port)
        self.spinPort.setAlignment(Qt.AlignCenter)
        self.spinPort.setFixedWidth(92)
        self.spinPort.setFixedHeight(34)
        b_minus = QPushButton("−")
        b_plus = QPushButton("＋")
        for b in (b_minus, b_plus):
            b.setObjectName("StepBtn")
            b.setCursor(Qt.PointingHandCursor)
            b.setAutoRepeat(True)
        b_minus.clicked.connect(self.spinPort.stepDown)
        b_plus.clicked.connect(self.spinPort.stepUp)
        prow.addWidget(self.spinPort)
        prow.addWidget(b_minus)
        prow.addWidget(b_plus)
        prow.addStretch(1)
        port_box = QWidget()
        port_box.setLayout(prow)
        port_box.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        g.addWidget(kv_row("监听端口", port_box, hint="1024–65535，默认 8765"))
        g.addWidget(hr())

        # 蓝牙
        brow = QHBoxLayout()
        brow.setSpacing(12)
        self.chkBle = ToggleSwitch()
        self.chkBle.setChecked(self.use_ble)
        brow.addWidget(self.chkBle)
        brow.addWidget(sub_lbl("启用 BLE 广播发现"))
        brow.addStretch(1)
        ble_box = QWidget()
        ble_box.setLayout(brow)
        ble_box.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.lbBleState = wrap_par("蓝牙广播状态将在服务启动后显示", C.TXT3, 12)
        self.lbBleState.setMinimumHeight(28)
        g.addWidget(kv_row("蓝牙广播", ble_box,
                           hint="纯无 IP 的标签依赖这一项；关闭后仅保留 UDP 发现",
                           sub=self.lbBleState))
        g.addWidget(hr())

        # 开机自动启动（HKCU\...\Run，用户级）
        aurow = QHBoxLayout()
        aurow.setSpacing(12)
        self.chkAutostart = ToggleSwitch()
        aurow.addWidget(self.chkAutostart)
        aurow.addWidget(sub_lbl("登录 Windows 后自动在托盘后台接收"))
        aurow.addStretch(1)
        auto_box = QWidget()
        auto_box.setLayout(aurow)
        auto_box.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.lbAutostart = wrap_par("", C.TXT3, 12)
        self.lbAutostart.setMinimumHeight(28)
        g.addWidget(kv_row("开机自启", auto_box,
                           hint="写入 HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run，"
                                "仅当前用户、无需管理员",
                           sub=self.lbAutostart))
        g.addWidget(hr())

        # 数据目录
        drow = QHBoxLayout()
        drow.setSpacing(8)
        self.lbDataDir = QLineEdit(str(DATA_DIR))
        self.lbDataDir.setReadOnly(True)
        self.lbDataDir.setFixedHeight(34)
        self.lbDataDir.setCursor(Qt.IBeamCursor)
        self.lbDataDir.setToolTip(str(DATA_DIR))
        self.btnOpenDir2 = QPushButton("打开")
        self.btnOpenDir2.setCursor(Qt.PointingHandCursor)
        self.btnOpenDir2.setFixedHeight(34)
        self.btnOpenDir2.clicked.connect(lambda: self.open_path(DATA_DIR))
        drow.addWidget(self.lbDataDir, 1)
        drow.addWidget(self.btnOpenDir2)
        dir_box = QWidget()
        dir_box.setLayout(drow)
        dir_box.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        g.addWidget(kv_row("数据目录", dir_box))
        g.addWidget(hr())

        # 标签 URI
        urow = QHBoxLayout()
        urow.setSpacing(8)
        self.editUri = QLineEdit()
        self.editUri.setReadOnly(True)
        self.editUri.setProperty("mono", "true")
        self.editUri.setFixedHeight(34)
        self.editUri.setCursor(Qt.IBeamCursor)
        self._uri_visible = False
        self.btnShowUri = QPushButton("显示")
        self.btnShowUri.setCursor(Qt.PointingHandCursor)
        self.btnShowUri.setFixedHeight(34)
        self.btnShowUri.clicked.connect(self.toggle_uri_visible)
        self.btnCopyUri = QPushButton("复制")
        self.btnCopyUri.setIcon(line_icon("copy", C.TXT2, 15))
        self.btnCopyUri.setIconSize(QSize(15, 15))
        self.btnCopyUri.setCursor(Qt.PointingHandCursor)
        self.btnCopyUri.setFixedHeight(34)
        urow.addWidget(self.editUri, 1)
        urow.addWidget(self.btnShowUri)
        urow.addWidget(self.btnCopyUri)
        uri_box = QWidget()
        uri_box.setLayout(urow)
        uri_box.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        g.addWidget(kv_row("标签 URI", uri_box,
                           hint="默认隐藏密钥；复制后写入 NFC 标签，手机碰一下即可配对"))

        # 用 QScrollArea 包住设置行：卡片高度有限，行数多时可滚动
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        rows_host = QWidget()
        rows_host.setLayout(g)
        scroll.setWidget(rows_host)
        v.addWidget(scroll, 1)
        outer.addWidget(card, 3)

        # 关于卡
        about = QFrame()
        about.setObjectName("Card")
        av = QVBoxLayout(about)
        av.setContentsMargins(24, 20, 24, 20)
        av.setSpacing(0)
        av.addWidget(role_lbl("关于", "title"))
        av.addSpacing(16)

        rows = [
            ("产品", f"一碰传 v{APP_VERSION}"),
            ("协议", "nfctap/3 · 3.0.0"),
            ("运行环境", "Python + PySide6 · 全程局域网直传"),
            ("手机端", f"一碰传 App {MOBILE_VERSION} · UDP / BLE 自动发现"),
            ("标签", "NTAG215 · 含设备 ID 与 256-bit 配对密钥"),
            ("反向发送", "桌面端选文件 → 手机碰标签自动接收"),
            ("密钥", "首次启动本机生成，安装包不含密钥"),
            ("平台边界", "Android 不允许读取任意 App 屏幕，旧流程碰标签后手动选文件"),
            ("安全", "配对双向认证 · 上传加密防篡改 · 危险类型不直接运行"),
        ]
        for i, (k, val) in enumerate(rows):
            if i:
                av.addSpacing(12)
            rr = QHBoxLayout()
            rr.setSpacing(16)
            kl = role_lbl(k, "label")
            kl.setFixedWidth(64)
            kl.setAlignment(Qt.AlignTop | Qt.AlignLeft)
            rr.addWidget(kl)
            vl = wrap_par(val, C.TXT2, 12)
            rr.addWidget(vl, 1)
            av.addLayout(rr)
        av.addStretch(1)
        outer.addWidget(about, 2)

        return page

    # ---------- 行为 ----------
    def _port_changed(self, v):
        self.port = int(v)
        self._portHint.setText(f"UDP 发现随服务启动 · 端口 {self.port}")

    def _ble_changed(self, _):
        self.use_ble = self.chkBle.isChecked()

    def _set_state_text(self, lb: QLabel, text: str, color: str) -> None:
        """状态行统一走富文本（line-height 150%），颜色随状态变化。"""
        lb.setText(html_par(text, color, 12))
        lb.updateGeometry()

    def _sync_autostart_ui(self):
        """把开关对齐注册表真实状态：读不到就不勾，路径不符给出提示。"""
        entry = autostart_entry()
        on = entry is not None
        self.chkAutostart.blockSignals(True)
        self.chkAutostart.setChecked(on)
        self.chkAutostart.blockSignals(False)
        if not on:
            self._set_state_text(self.lbAutostart,
                                 "未启用：登录 Windows 后不会自动后台接收", C.TXT3)
            self.lbAutostart.setToolTip("")
            return
        if entry.strip().lower() == autostart_command().strip().lower():
            self._set_state_text(self.lbAutostart, f"已启用：{entry}", C.OK)
        else:
            self._set_state_text(
                self.lbAutostart,
                f"已启用，但指向另一个位置（安装目录可能已变）：{entry}。"
                "取消后重新勾选即可修正为当前程序路径。", C.WARN)
        self.lbAutostart.setToolTip(entry)

    def _autostart_toggled(self, on: bool):
        try:
            set_autostart(on)
        except OSError as e:
            self.log_line(f"[自启动] 写入注册表失败：{e}")
            QMessageBox.warning(
                self, "开机自动启动",
                f"写入自启动项失败：{e}\n\n可稍后重试。")
        else:
            self.log_line(
                f"[自启动] 已{'写入' if on else '移除'} "
                f"HKCU\\{RUN_KEY}\\{RUN_VALUE}")
        self._sync_autostart_ui()

    def _sync_toggle(self):
        running = self.ctl.running
        if running:
            self.btnToggle.setText("停止服务")
            self.btnToggle.setProperty("variant", "danger")
            self.btnToggle.setIcon(line_icon("stop", C.DANGER, 15))
        else:
            self.btnToggle.setText("启动服务")
            self.btnToggle.setProperty("variant", "primary")
            self.btnToggle.setIcon(line_icon("play", "#062A28", 15))
        self.btnToggle.style().unpolish(self.btnToggle)
        self.btnToggle.style().polish(self.btnToggle)
        self.btnToggle.update()

    def toggle_service(self):
        if self.ctl.running:
            self.ctl.stop()
            self.statusBar().showMessage("服务已停止")
        else:
            ok, msg = self.ctl.start(self.port, self.use_ble)
            self.statusBar().showMessage(msg)
            if not ok:
                QMessageBox.warning(self, "无法启动接收服务", msg)
        self._sync_toggle()
        self.refresh_all()

    def _full_pair_uri(self) -> str:
        return R.build_pair_uri(R.load_or_create_config())

    @staticmethod
    def _mask_pair_uri(uri: str) -> str:
        """默认只显示 device_id，把 k 掩码；点「显示」才展开。"""
        head, sep, tail = uri.partition("k=")
        if not sep:
            return uri
        cut = tail.find("&")
        return head + sep + "********" + (tail[cut:] if cut >= 0 else "")

    def _render_pair_uri(self) -> None:
        uri = self._full_pair_uri()
        self.editUri.setText(uri if self._uri_visible else self._mask_pair_uri(uri))
        self.btnShowUri.setText("隐藏" if self._uri_visible else "显示")

    def toggle_uri_visible(self) -> None:
        self._uri_visible = not self._uri_visible
        self._render_pair_uri()
        if not self._uri_visible:
            self.statusBar().showMessage("配对密钥已隐藏", 2000)

    def copy_uri(self):
        uri = self._full_pair_uri()
        QApplication.clipboard().setText(uri)
        self.statusBar().showMessage("标签 URI 已复制；60 秒后自动清空剪贴板", 4000)
        self.btnCopyUri.setText("已复制")
        QTimer.singleShot(1400, lambda: self.btnCopyUri.setText("复制"))

        def _clear_clipboard():
            if QApplication.clipboard().text() == uri:
                QApplication.clipboard().clear()

        QTimer.singleShot(60_000, _clear_clipboard)

    @staticmethod
    def open_path(p: Path):
        """打开目录或文件。

        v2.3 A3：脚本/可执行类扩展名绝不交给 os.startfile —— Windows 上
        双击 .bat/.ps1/.vbs/.hta/.lnk/.exe 就是执行，不是「打开查看」。
        这类文件改为只打开所在文件夹，让用户自己决定怎么处理，并在状态栏
        说明原因。服务端已把新上传的同类文件降级为 .bin，这里是第二道防线。
        """
        try:
            p = Path(p)
            if p.is_file() and p.suffix.lower() not in SAFE_SUFFIXES:
                folder = p.parent
                folder.mkdir(parents=True, exist_ok=True)
                os.startfile(str(folder))
                print(f"[安全] {p.name} 不在安全扩展名白名单，只打开所在文件夹")
                return
            if p.is_dir() or not p.suffix:
                p.mkdir(parents=True, exist_ok=True)
            os.startfile(str(p))
        except Exception as e:
            print("打开失败", e)

    def open_from_table(self, index):
        row = index.row()
        item = self.tableRecent.item(row, 2)
        if item is not None:
            self.open_path(R.RECEIVED_DIR / item.text())

    def _on_recent_select(self):
        rows = sorted({i.row() for i in self.tableRecent.selectedIndexes()})
        if not rows:
            self._show_preview_name(None)
            return
        item = self.tableRecent.item(rows[0], 2)
        self._show_preview_name(item.text() if item else None)

    def _show_preview_name(self, name: str | None):
        if not name:
            self._preview_source = None
            self.previewStack.setCurrentIndex(0)
            self.lbFileInfo.setText("")
            self.lbFileInfo.setVisible(False)
            return
        f = R.RECEIVED_DIR / name
        if not f.exists():
            self._preview_source = None
            self.previewStack.setCurrentIndex(0)
            self.lbFileInfo.setText("")
            self.lbFileInfo.setVisible(False)
            return
        st = f.stat()
        ext = Path(name).suffix.lower()
        kind = R.kind_of(ext)

        pm = QPixmap(str(f)) if kind == "图片" else QPixmap()
        if not pm.isNull():
            self._preview_source = pm
            self.previewStack.setCurrentIndex(1)
            self._rescale_preview()
            QTimer.singleShot(0, self._rescale_preview)
            self.lbFileInfo.setText(
                f"{kind} · {ext.lstrip('.') or '无扩展名'} · "
                f"{_fmt_size(st.st_size)} · "
                f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(st.st_mtime))}")
            self.lbFileInfo.setVisible(True)
        else:
            # 非图片：把能确认的信息摊开，而不是只说「无法预览」
            self._preview_source = None
            self.infoIcon.setPixmap(kind_icon(kind, C.TXT3, 32).pixmap(32, 32))
            self.infoName.setText(name)
            self.infoMeta.setText(
                f"{kind} · {ext.lstrip('.') or '无扩展名'} · {_fmt_size(st.st_size)} · "
                f"{time.strftime('%Y-%m-%d %H:%M', time.localtime(st.st_mtime))}")
            self.previewStack.setCurrentIndex(2)
            self.lbFileInfo.setText("")
            self.lbFileInfo.setVisible(False)

    def _rescale_preview(self):
        src = self._preview_source
        if src is None or src.isNull():
            return
        w = max(80, self.preview.width() - 8)
        h = max(80, self.preview.height() - 8)
        self.preview.setPixmap(src.scaled(w, h, Qt.KeepAspectRatio,
                                         Qt.SmoothTransformation))

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._rescale_preview()
        zone = getattr(self, "_drop_zone", None)
        if zone is not None and zone.isVisible():
            zone.setGeometry(0, 0, self.width(), self.height())

    # ---------- 刷新 ----------
    def refresh_all(self):
        self._last_log_size = -1
        self.tick(force=True)

    def tick(self, force: bool = False):
        st = self.ctl.status()
        self.pill.set_state(st["running"], st["port"])

        if self._ui_running != st["running"]:
            self._ui_running = st["running"]
            self._sync_toggle()

        self.lbDevice.setText(st["device_id"] or "—")
        addrs = st["addresses"] or []
        primary = st["host"] or (addrs[0] if addrs else "—")
        self.lbAddr.setText(primary)
        self.lbAddr.setToolTip("、".join(addrs) or "—")
        self.lbCounts.setText(
            f"{st['received_ok']} / {st['duplicate']} / {st['rejected']}")
        self.lbCounts.setToolTip(
            f"已接收 {st['received_ok']} · 重复 {st['duplicate']} · "
            f"拒绝 {st['rejected']}")
        bs = st.get("ble_state") or {}
        if not self.use_ble or bs.get("enabled") is False:
            self.lbBle.setText("蓝牙广播未开启")
            self.lbBle.setStyleSheet(f"color:{C.TXT2};font-size:14px;")
            self.bleDot.set_color(C.TXT3)
            self.lbBle.setToolTip("蓝牙广播已关闭：手机只能通过局域网发现这台电脑。")
            self._set_state_text(self.lbBleState,
                                 "已关闭：手机只能通过局域网发现这台电脑。", C.TXT3)
        elif bs.get("alive"):
            self.lbBle.setText("蓝牙广播已开启")
            self.lbBle.setStyleSheet(f"color:{C.TXT};font-size:14px;")
            self.bleDot.set_color(C.OK)
            self.lbBle.setToolTip(
                f"蓝牙广播已开启（{bs.get('status') or 'Started'}）："
                "手机在附近即可发现这台电脑。")
            self._set_state_text(
                self.lbBleState,
                "已开启：手机在附近即可通过蓝牙发现这台电脑。", C.OK)
        else:
            reason = bs.get("reason") or "start_failed"
            short = bs.get("reason_text") or "蓝牙广播不可用"
            advice = bs.get("advice") or ""
            detail = bs.get("detail") or ""
            tag = {
                "winrt_missing": "缺少组件",
                "radio_off": "蓝牙已关闭",
                "no_adapter": "没有蓝牙适配器",
                "no_peripheral": "不支持广播",
                "no_ipv4": "没有局域网地址",
                "start_failed": "启动失败",
                "starting": "启动中",
            }.get(reason, "启动失败")
            self.lbBle.setText(
                "蓝牙广播启动中" if reason == "starting"
                else f"蓝牙广播不可用：{tag}")
            self.lbBle.setStyleSheet(f"color:{C.TXT2};font-size:14px;")
            self.bleDot.set_color(C.INDIGO if reason == "starting" else C.WARN)
            tip = f"{short}。建议：{advice}。" + (f"（{detail}）" if detail else "")
            if bs.get("retrying") and reason != "starting":
                tip += " 正在后台自动重试。"
            self.lbBle.setToolTip(tip)
            if reason == "starting":
                text = "正在启动蓝牙广播，通常一两秒内完成。"
            elif reason == "start_failed" and detail:
                cut = detail if len(detail) <= 70 else detail[:69] + "…"
                text = f"原因：{short}（{cut}）。建议：{advice}。"
            else:
                text = f"原因：{short}。建议：{advice}。"
            self._set_state_text(self.lbBleState, text, C.TXT2)
        self._render_pair_uri()
        self._refresh_send_ui()

        try:
            log_size = R.LOG_PATH.stat().st_size if R.LOG_PATH.exists() else 0
        except OSError:
            log_size = 0
        if force or log_size != self._last_log_size:
            self._last_log_size = log_size
            self._reload_recent()

    def _reload_recent(self):
        rows = R.read_recent(50)
        # 记住当前选中的文件名，重建行后恢复选中并保持右侧预览
        prev_sel = None
        for i in self.tableRecent.selectedIndexes():
            it = self.tableRecent.item(i.row(), 2)
            if it is not None:
                prev_sel = it.text()
            break
        self.tableRecent.setRowCount(len(rows))
        self.recentStack.setCurrentIndex(0 if rows else 1)
        self.lbRecentCount.setText(f"共 {len(rows)} 条" if rows else "暂无记录")

        f_primary = QFont(self.font())
        f_primary.setPixelSize(14)
        f_second = QFont(self.font())
        f_second.setPixelSize(12)
        f_mono = QFont(self.font())
        f_mono.setPixelSize(12)
        f_mono.setFamilies(["Consolas", "Cascadia Mono"])

        for i, it in enumerate(rows):
            result = it.get("result", "")
            r_txt = {"saved": "● 已保存",
                     "duplicate": "● 重复跳过",
                     "sent": "↑ 已发送",
                     "failed": "✕ 发送失败"}.get(result, f"● {result or '—'}")
            r_color = {"saved": C.OK, "duplicate": C.WARN,
                       "rejected": C.DANGER, "sent": C.INDIGO,
                       "failed": C.DANGER}.get(result, C.TXT2)
            vals = [
                (QTableWidgetItem(_fmt_ts(it.get("ts", ""))), f_second, C.TXT3,
                 str(it.get("ts", ""))),
                (QTableWidgetItem(r_txt), f_second, r_color, ""),
                (QTableWidgetItem(it.get("file", "")), f_primary, C.TXT,
                 it.get("file", "")),
                (QTableWidgetItem(_fmt_size(it.get("bytes", 0))), f_second,
                 C.TXT2, f"{it.get('bytes', 0):,} 字节"),
                (QTableWidgetItem(it.get("kind") or R.kind_of(
                    Path(it.get("file", "")).suffix.lower())), f_second, C.TXT2, ""),
                (QTableWidgetItem(it.get("from", "")), f_mono, C.TXT3, ""),
            ]
            for j, (item, font, color, tip) in enumerate(vals):
                item.setFont(font)
                item.setForeground(QColor(color))
                if j == 3:
                    item.setTextAlignment(int(Qt.AlignRight | Qt.AlignVCenter))
                if tip:
                    item.setToolTip(tip)
                self.tableRecent.setItem(i, j, item)
            # 已保存且本地还在的文件，记下真实路径，供拖出到微信/钉钉/资源管理器
            if result == "saved":
                local = R.RECEIVED_DIR / str(it.get("file") or "")
                if local.is_file():
                    self.tableRecent.item(i, 2).setData(Qt.UserRole, str(local))

        # 托盘提示：只在启动后新出现的「已保存」记录上弹一次，不补历史
        saved = [it for it in rows if it.get("result") == "saved"]
        newest = str(saved[0].get("ts", "")) if saved else ""
        if not self._notify_baseline:
            self._notify_baseline = True
            self._notify_ts = newest
        elif newest and newest > self._notify_ts:
            fresh = [str(it.get("file") or "") for it in saved
                     if str(it.get("ts", "")) > self._notify_ts]
            self._notify_ts = newest
            self._notify_received([n for n in fresh if n])

        # 重建行后恢复选中；选中项丢失则清空右侧预览
        if prev_sel:
            for i in range(self.tableRecent.rowCount()):
                it = self.tableRecent.item(i, 2)
                if it is not None and it.text() == prev_sel:
                    self.tableRecent.selectRow(i)
                    return
            self._show_preview_name(None)

    def closeEvent(self, event):
        # 点 X 不是退出：收进托盘，服务与蓝牙广播继续跑，手机照常能传。
        if not self._really_quit and self.tray is not None:
            event.ignore()
            self.hide()
            if not self._tray_tip_shown:
                self._tray_tip_shown = True
                self.tray.showMessage(
                    APP_NAME,
                    "已收进托盘，接收服务与蓝牙广播仍在后台运行。"
                    "双击托盘图标可恢复窗口。",
                    QSystemTrayIcon.Information, 4000)
            return
        try:
            self.ctl.stop()
        except Exception:
            pass
        super().closeEvent(event)
        if self.tray is None:
            # 没有通知区域可用时不留后台幽灵进程
            QApplication.quit()

    # ---------- 系统托盘 ----------
    def _tray_pixmap(self, accent: str = C.TEAL) -> QPixmap:
        """自绘托盘图标：圆角方块 + 双向箭头，与窗口暗色系同一套色值。"""
        pm = QPixmap(64, 64)
        pm.fill(Qt.transparent)
        p = QPainter(pm)
        p.setRenderHint(QPainter.Antialiasing, True)
        p.setPen(Qt.NoPen)
        p.setBrush(QColor(accent))
        p.drawRoundedRect(QRectF(2, 2, 60, 60), 16, 16)

        ink = QColor("#062A28")
        p.setBrush(ink)
        p.setPen(QPen(ink, 6, Qt.SolidLine, Qt.RoundCap))
        # 上行箭头（左）
        p.drawLine(23, 49, 23, 21)
        p.drawPolygon(QPolygonF([QPointF(23, 12), QPointF(33, 26),
                                 QPointF(13, 26)]))
        # 下行箭头（右）
        p.drawLine(41, 15, 41, 43)
        p.drawPolygon(QPolygonF([QPointF(41, 52), QPointF(31, 38),
                                 QPointF(51, 38)]))
        p.end()
        return pm

    def _init_tray(self):
        if not QSystemTrayIcon.isSystemTrayAvailable():
            self.log_line("[托盘] 当前系统没有可用的通知区域，关闭窗口将直接退出")
            return
        self.tray = QSystemTrayIcon(QIcon(self._tray_pixmap()), self)
        self.tray.setToolTip(f"{APP_NAME} v{APP_VERSION} · 后台接收中")

        menu = QMenu(self)
        act_open = QAction("打开主界面", menu)
        act_open.triggered.connect(self.show_from_tray)
        act_send = QAction("发送文件…", menu)
        act_send.triggered.connect(self.tray_send_files)
        act_quit = QAction("退出", menu)
        act_quit.triggered.connect(self.quit_from_tray)
        menu.addAction(act_open)
        menu.addAction(act_send)
        menu.addSeparator()
        menu.addAction(act_quit)
        self.tray.setContextMenu(menu)
        self._tray_menu = menu

        self.tray.activated.connect(self._on_tray_activated)
        self.tray.messageClicked.connect(self.show_from_tray)
        self.tray.show()
        self.log_line("[托盘] 已启用：关闭窗口后仍在后台接收")

    def _on_tray_activated(self, reason):
        if reason == QSystemTrayIcon.DoubleClick:
            self.show_from_tray()

    def show_from_tray(self):
        """从托盘唤起：恢复并真正前置，避免只闪一下任务栏。"""
        if self.isMinimized():
            self.setWindowState(self.windowState() & ~Qt.WindowMinimized)
        self.show()
        self.showNormal()
        self.raise_()
        self.activateWindow()
        self._raise_to_front()

    def _raise_to_front(self):
        """把窗口真正拿到前台。

        Windows 有前台锁：非前台进程直接 SetForegroundWindow 会被系统忽略，
        表现就是「任务栏闪一下」。这里先常规尝试，失败后临时 AttachThreadInput
        到当前前台线程再设前台，最后兜底 BringWindowToTop / SwitchToThisWindow。
        """
        try:
            import ctypes
            u = ctypes.windll.user32
            k = ctypes.windll.kernel32
            hwnd = ctypes.c_void_p(int(self.winId()))
            if not hwnd.value:
                return
            u.ShowWindow(hwnd, 9)                     # SW_RESTORE
            if u.SetForegroundWindow(hwnd):
                return
            fg = u.GetForegroundWindow()
            tid_fg = u.GetWindowThreadProcessId(fg, None) if fg else 0
            tid_me = k.GetCurrentThreadId()
            attached = False
            if tid_fg and tid_fg != tid_me:
                attached = bool(u.AttachThreadInput(tid_fg, tid_me, True))
            u.SetForegroundWindow(hwnd)
            u.BringWindowToTop(hwnd)
            if attached:
                u.AttachThreadInput(tid_fg, tid_me, False)
            if u.GetForegroundWindow() != hwnd.value:
                u.SwitchToThisWindow(hwnd, True)
            if u.GetForegroundWindow() != hwnd.value:
                # 前台锁确实拿不到时，至少保证窗口浮到最上层可见，
                # 而不是留在别的窗口后面只闪任务栏。
                flags = 0x0001 | 0x0002 | 0x0040      # NOSIZE|NOMOVE|SHOWWINDOW
                u.SetWindowPos(hwnd, ctypes.c_void_p(-1), 0, 0, 0, 0, flags)
                u.SetWindowPos(hwnd, ctypes.c_void_p(-2), 0, 0, 0, 0, flags)
        except Exception as e:          # 非 Windows / 无权限时忽略
            self.log_line(f"[托盘] 前置窗口兜底失败：{e}")

    def tray_send_files(self):
        """托盘菜单「发送文件」：直接拉起选文件，选完进待发队列。"""
        self.show_from_tray()
        paths, _ = QFileDialog.getOpenFileNames(
            self, "选择要发送到手机的文件", str(Path.home()), "所有文件 (*)")
        if not paths:
            return
        self._switch_tab(1)
        self._enqueue_send_files([Path(p) for p in paths])

    def quit_from_tray(self):
        """托盘菜单「退出」：真正结束进程。"""
        self._really_quit = True
        if self.tray is not None:
            self.tray.hide()
        self.close()
        QApplication.quit()

    def _notify_received(self, names: list[str]):
        """收到文件时的托盘轻量提示；点气泡直接回主界面看记录。"""
        if self.tray is None or not names:
            return
        if self.isVisible() and self.isActiveWindow():
            return                       # 窗口就在眼前，交给记录表刷新
        if len(names) == 1:
            msg = f"已收到「{names[0]}」，点击查看接收记录"
        else:
            msg = f"已收到 {len(names)} 个文件，点击查看接收记录"
        self.tray.showMessage(APP_NAME, msg,
                              QSystemTrayIcon.Information, 5000)


def main() -> int:
    ap = argparse.ArgumentParser(description=APP_NAME)
    ap.add_argument("--selftest", action="store_true", help="无界面自检")
    ap.add_argument("--data-dir", default=None, help="覆盖数据目录")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-ble", action="store_true")
    ap.add_argument("--no-autostart", action="store_true")
    ap.add_argument("--startup", action="store_true",
                    help="开机自启：静默进托盘，不显示主窗口")
    ap.add_argument("--open-received", action="store_true",
                    help="只打开接收文件目录后退出（供快捷方式使用）")
    a = ap.parse_args()

    if a.selftest:
        return run_selftest(a.port, not a.no_ble)

    if a.open_received:
        # 安装后 received/ 可能还不存在，这里显式创建再交给资源管理器。
        try:
            R.RECEIVED_DIR.mkdir(parents=True, exist_ok=True)
            os.startfile(str(R.RECEIVED_DIR))
        except Exception as e:
            print("打开接收目录失败：", e)
            return 1
        return 0
    if not HAS_QT:
        print("PySide6 不可用：", QT_IMPORT_ERROR)
        return 2

    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)
    apply_theme(app)
    # 托盘形态：关掉最后一个窗口不等于退出，进程要留在后台继续接收
    app.setQuitOnLastWindowClosed(False)
    ico = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent)) / "nfctap.ico"
    if ico.exists():
        app.setWindowIcon(QIcon(str(ico)))
    win = MainWindow(a.port, not a.no_ble, not a.no_autostart)
    if ico.exists():
        win.setWindowIcon(QIcon(str(ico)))
    if a.startup:
        # 开机自启：不 show、不抢焦点，只留托盘图标；服务与 BLE 已在构造时启动
        win.log_line("[自启动] 开机静默启动，仅驻留托盘")
    else:
        win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
