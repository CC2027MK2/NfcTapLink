/*
 * NfcTapLink · 真机自检入口（仅 debug 构建存在，release 不含此类）
 *
 * 目的：在没有物理 NFC 标签的情况下，用平台 NdefRecord.createUri() 构造
 * 与真实标签完全一致的 NdefMessage，通过 EXTRA_NDEF_MESSAGES 发给
 * TapActivity，从而验证「系统 NFC 分发 → NDEF URI 解析 → 配对 → 上传」整条
 * 代码路径。adb shell am 无法注入 Parcelable 数组，故用本 Activity 代劳。
 *
 * 触发方式：
 *   adb shell am start -n com.example.nfctaplink/.SelfTestActivity \
 *     --es uri "nfctap://pair?d=xxx&k=yyy" --ez clearCache true
 *
 * v5 起可指定要发送的文件类型，用于验证「任意文件传输」：
 *   --es attach apk    发本 App 自己的真实 APK（读 sourceDir，校验真二进制）
 *   --es attach docx   发打包在 debug assets 里的真实 .docx
 *   --es attach txt    发带时间戳的唯一 .txt（内容每轮不同，避免服务端去重）
 *   --es attach png    默认，发随机生成的合法 PNG
 *
 * v2 自检场景（用 --es uri 传不同标签内容，--ez clearCache 控制是否清缓存）：
 *   - 纯无 IP（默认，与物理标签一致）-> 期望命中 ble
 *   - 带引导候选 c=  -> 期望命中 tag-hint
 *   - 候选写错但不清缓存 -> 期望命中 cached
 *   - v1 的 h/p/k      -> 兼容回退，期望命中 tag-v1
 *
 * 这不是产品功能，不参与任何 UI 入口，也不写入发布版 Manifest。
 */
package com.example.nfctaplink;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
import android.nfc.NfcAdapter;
import android.os.Bundle;
import android.util.Log;

import java.io.FileOutputStream;
import java.util.Random;

public class SelfTestActivity extends Activity {

    private static final String TAG = "NfcTapLinkSelfTest";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // 标签 URI 必须通过 --es uri 传入当前物理标签的完整内容。
        // v5.4 改动：不再在 debug 源码里内置任何真实配对码/设备 ID。
        // 原因：① 轮换 k 后无需重编译 APK；② 旧 k 曾进入发布包与日志，
        // 视为已泄露，不该继续打进 debug 产物。所有真机回归脚本都已显式传 uri。
        String uri = getIntent().getStringExtra("uri");
        if (uri == null || uri.trim().isEmpty()) {
            Log.e(TAG, "缺少 --es uri；请传入当前物理标签的完整 nfctap:// URI"
                    + "（本机 python receiver.py --paircode 可打印）");
            new android.app.AlertDialog.Builder(this)
                    .setTitle("自检缺少参数")
                    .setMessage("请用 --es uri 传入当前标签 URI，本次不再内置配对码。")
                    .setPositiveButton("关闭", (d, w) -> finish())
                    .setOnCancelListener(d -> finish())
                    .show();
            return;
        }
        // 从实际使用的 URI 解析配对码写入 prefs，保证与标签里的 k 完全一致。
        android.net.Uri parsed = android.net.Uri.parse(uri);
        String code = parsed.getQueryParameter("k");
        if (code == null || code.trim().isEmpty()) {
            Log.e(TAG, "传入的 uri 缺少配对码 k（指纹 " + fingerprint(uri) + "）");
            finish();
            return;
        }
        final String fCode = code.trim();
        boolean clearCache = getIntent().getBooleanExtra("clearCache", false);
        // v4：--ez noPending true 清掉寄存图，用于测试「碰标签 → 自动取媒体库最新图」。
        boolean noPending = getIntent().getBooleanExtra("noPending", false);
        // --ei windowMin 0 可强制让「最新一张」超出时间窗口，用于验证防误发降级。
        int windowMin = getIntent().getIntExtra("windowMin", -1);

        // v5：按 --es attach 决定这次要发什么；默认仍是 PNG。
        String attach = getIntent().getStringExtra("attach");
        if (attach == null) attach = "png";

        // 自备一张随机的合法 PNG 到 App 私有缓存，并把 pending 指向它。
        // 2026-11-13 说明：adb shell am 无法构造带有效 URI grant 的真实分享
        // Intent（EXTRA_STREAM 是 Parcelable Uri，--eu 只传 string），
        // 用它测「图库分享」会假失败。这里绕开分享环节，直接备好私有缓存，
        // 专测 NFC 分发 → NDEF 解析 → 自动发现 → 配对 → 上传 这条主链路。
        // 分享寄存链路另由系统解析表 query-activities 与 handleShare 逻辑验证。
        String time = new java.text.SimpleDateFormat("yyyyMMdd-HHmmss-SSS",
                java.util.Locale.US).format(new java.util.Date());
        String fname;
        String sendName;
        if ("apk".equalsIgnoreCase(attach)) {
            fname = cacheOwnApk();
            sendName = "NfcTapLink-app-debug.apk";
        } else if ("docx".equalsIgnoreCase(attach)) {
            fname = cacheAsset("一碰传测试文档.docx", "一碰传测试文档.docx");
            sendName = "一碰传测试文档.docx";
        } else if ("txt".equalsIgnoreCase(attach)) {
            // 内容带毫秒时间戳，保证每轮 sha256 都不同，能验证「新文件落盘」路径
            String body = "一碰传 v5 文件传输自检\r\n时间：" + time
                    + "\r\n这是一份普通文本文件，用来验证任意文件传输。\r\n";
            sendName = "一碰传自检-" + time + ".txt";
            fname = cacheBytesText(sendName, body);
        } else {
            fname = makeTestPng();
            sendName = "apk_e2e_selftest.png";
        }
        if (fname == null) {
            Log.e(TAG, "备文件失败，attach=" + attach);
            finish();
            return;
        }

        SharedPreferences p = getSharedPreferences(Prefs.PREF, Context.MODE_PRIVATE);
        SharedPreferences.Editor ed = p.edit();
        if (clearCache) {
            ed.remove(Prefs.KEY_LAST_ENDPOINT)
              .remove(Prefs.KEY_DEVICE_ID)
              .remove(Prefs.KEY_HOST);
            Log.i(TAG, "已清缓存地址与设备 ID（强制走 UDP / 子网发现）");
        }
        ed.putString(Prefs.KEY_CODE, fCode);
        if (windowMin >= 0) ed.putInt(Prefs.KEY_AUTO_WINDOW_MIN, windowMin);
        else ed.remove(Prefs.KEY_AUTO_WINDOW_MIN);
        if (noPending) {
            ed.remove(Prefs.KEY_PENDING_URI).remove(Prefs.KEY_PENDING_NAME);
        } else {
            ed.putString(Prefs.KEY_PENDING_URI, "cache://" + fname)
              .putString(Prefs.KEY_PENDING_NAME, sendName);
        }
        ed.apply();
        Log.i(TAG, "自备私有缓存: " + fname + "（发送名 " + sendName + "，attach="
                + attach + "），clearCache=" + clearCache + "，noPending=" + noPending);

        // 平台 API 生成 TNF_WELL_KNOWN / RTD_URI 记录：
        // payload = 0x00(无前缀) + URI 本体，与 PN532 回读的标签字节一致
        NdefRecord rec = NdefRecord.createUri(uri);
        NdefMessage msg = new NdefMessage(new NdefRecord[]{rec});

        byte[] pb = rec.getPayload();
        Log.i(TAG, "NDEF payload 长度=" + pb.length
                + " 首字节=0x" + String.format("%02X", pb[0] & 0xFF));

        Intent it = new Intent(this, TapActivity.class);
        it.setAction(NfcAdapter.ACTION_NDEF_DISCOVERED);
        it.putExtra(NfcAdapter.EXTRA_NDEF_MESSAGES, new NdefMessage[]{msg});
        // 6.2.2 起 TapActivity 拒绝无 EXTRA_TAG 的注入；本 Activity 是 debug 专属
        // 自检入口，用这个标记让 TapActivity 只对「debug 构建 + 自检」放行。
        it.putExtra("selftest", true);
        it.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        Log.i(TAG, "发出 ACTION_NDEF_DISCOVERED，URI 指纹=" + fingerprint(uri));

        startActivity(it);
        finish();
    }

    /** 把本 App 自己的 APK 读进私有缓存：真二进制，用来验证 APK 传输。 */
    private String cacheOwnApk() {
        try {
            String src = getPackageManager()
                    .getApplicationInfo(getPackageName(), 0).sourceDir;
            byte[] bytes = readFile(new java.io.File(src));
            String fname = "pending_apk_" + System.currentTimeMillis() + ".apk";
            try (FileOutputStream fos = openFileOutput(fname, Context.MODE_PRIVATE)) {
                fos.write(bytes);
            }
            Log.i(TAG, "已缓存自身 APK " + bytes.length + " 字节（源 " + src + "）");
            return fname;
        } catch (Exception e) {
            Log.e(TAG, "缓存自身 APK 失败", e);
            return null;
        }
    }

    /** 写一段文本到私有缓存，返回文件名。 */
    private String cacheBytesText(String displayName, String content) {
        try {
            byte[] bytes = content.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            String fname = "pending_txt_" + System.currentTimeMillis() + "_" + displayName;
            try (FileOutputStream fos = openFileOutput(fname, Context.MODE_PRIVATE)) {
                fos.write(bytes);
            }
            Log.i(TAG, "已生成文本 " + bytes.length + " 字节 -> " + displayName);
            return fname;
        } catch (Exception e) {
            Log.e(TAG, "生成文本失败", e);
            return null;
        }
    }

    /** 把 debug assets 里的真实文件读进私有缓存。 */
    private String cacheAsset(String assetName, String displayName) {
        try {
            byte[] bytes;
            try (java.io.InputStream is = getAssets().open(assetName)) {
                bytes = readAll(is);
            }
            String fname = "pending_asset_" + System.currentTimeMillis() + "_" + displayName;
            try (FileOutputStream fos = openFileOutput(fname, Context.MODE_PRIVATE)) {
                fos.write(bytes);
            }
            Log.i(TAG, "已缓存 assets/" + assetName + " " + bytes.length + " 字节");
            return fname;
        } catch (Exception e) {
            Log.e(TAG, "缓存 assets 文件失败", e);
            return null;
        }
    }

    private static byte[] readFile(java.io.File f) throws Exception {
        try (java.io.InputStream is = new java.io.FileInputStream(f)) {
            return readAll(is, f.length());
        }
    }

    private static byte[] readAll(java.io.InputStream is, long expected) throws Exception {
        if (is == null) return null;
        try (java.io.InputStream in = is) {
            if (expected > 0) {
                byte[] out = new byte[(int) expected];
                int off = 0;
                while (off < out.length) {
                    int n = in.read(out, off, out.length - off);
                    if (n < 0) break;
                    off += n;
                }
                int pending = in.read();
                if (pending == -1) {
                    return off == out.length ? out : java.util.Arrays.copyOf(out, off);
                }
                java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
                bos.write(out, 0, off);
                bos.write(pending);
                byte[] buf = new byte[8192];
                int n;
                while ((n = in.read(buf)) != -1) bos.write(buf, 0, n);
                return bos.toByteArray();
            }
            java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) != -1) bos.write(buf, 0, n);
            return bos.toByteArray();
        }
    }

    private static byte[] readAll(java.io.InputStream is) throws Exception {
        return readAll(is, -1L);
    }

    /** 生成一张内容随机的合法 PNG 到 App 私有 files 目录，返回文件名。 */
    private String makeTestPng() {
        String fname = "pending_selftest_" + System.currentTimeMillis() + ".png";
        try {
            int w = 320, h = 240;
            android.graphics.Bitmap bm =
                    android.graphics.Bitmap.createBitmap(w, h,
                            android.graphics.Bitmap.Config.ARGB_8888);
            Random r = new Random();
            for (int y = 0; y < h; y += 8) {
                for (int x = 0; x < w; x += 8) {
                    int c = ((x / 8 + y / 8) % 2 == 0)
                            ? 0xFFB43C28 : 0xFF14203C;
                    for (int dy = 0; dy < 8 && y + dy < h; dy++) {
                        for (int dx = 0; dx < 8 && x + dx < w; dx++) {
                            bm.setPixel(x + dx, y + dy, c);
                        }
                    }
                }
            }
            // 随机像素点，保证每次生成的内容哈希不同（避开服务端 sha256 去重）
            for (int i = 0; i < 200; i++) {
                bm.setPixel(r.nextInt(w), r.nextInt(h), r.nextInt() | 0xFF000000);
            }
            try (FileOutputStream fos = openFileOutput(fname, Context.MODE_PRIVATE)) {
                bm.compress(android.graphics.Bitmap.CompressFormat.PNG, 100, fos);
            }
            bm.recycle();
            Log.i(TAG, "测试 PNG 已写入 " + fname);
        } catch (Exception e) {
            Log.e(TAG, "生成测试 PNG 失败", e);
        }
        return fname;
    }

    /** 日志里不打印含配对密钥的 URI，只打印其 SHA-256 前 16 位作为可对照的指纹。 */
    private static String fingerprint(String s) {
        try {
            java.security.MessageDigest md =
                    java.security.MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(s.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 8; i++) sb.append(String.format("%02x", d[i] & 0xff));
            return "URI-SHA256:" + sb;
        } catch (Exception e) {
            return "<unavailable>";
        }
    }
}
