/*
 * NfcTapLink · 碰标签 / 分享入口（Java 实现，等价翻译自 kotlin-src/TapActivity.kt）
 *
 * A) 收到 ACTION_SEND（任意 mime，含 * 斜杠 *）：把分享来的文件（图片/Word/APK…）
 *    「寄存」到本地（URI + 显示名），
 *    不立即上传。这是绕开「App 无法读取任意 App 当前屏幕」限制的正路。
 * B) 收到 ACTION_NDEF_DISCOVERED(nfctap://pair...)：读标签里的 64 hex k，
 *    校验 d = sha256(hexToBytes(k))[:16]，走 /api/challenge + /api/pair 双向认证，
 *    再用会话密钥构造 NT3 加密载荷上传，给结果反馈。
 *
 * v3：k 只用于本地 HMAC，绝不上网；server_proof 校验不过就中止，不传任何文件。
 * 仅用 HttpURLConnection + javax.crypto.Mac，零第三方依赖。
 */
package com.example.nfctaplink;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.Dialog;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.res.ColorStateList;
import android.database.Cursor;
import android.graphics.Color;
import android.graphics.drawable.ColorDrawable;
import android.net.Uri;
import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.Ndef;
import android.os.Build;
import android.os.Bundle;
import android.os.CountDownTimer;
import android.os.Parcelable;
import android.provider.OpenableColumns;
import android.util.Log;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import android.content.ContentValues;
import android.provider.MediaStore;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class TapActivity extends Activity {

    private static final String TAG = "NfcTapLink";
    private final ExecutorService io = Executors.newSingleThreadExecutor();
    // 反向发送（电脑 → 手机）探测单独一条线程：它可能与用户已选文件的上传
    // 同时进行，不能和 io 抢同一个执行队列，否则上传会被拖后最多数秒。
    private final ExecutorService outboxIo = Executors.newSingleThreadExecutor();
    // v6：取文件后的确认窗；同一时刻只允许一个，避免连碰两次弹两个框。
    // v3：倒计时结束是「自动取消」，只有用户点「立即发送」才发。
    private static final int CONFIRM_SECONDS = 5;
    private static final int RESULT_SECONDS = 15;
    // v6.2：与电脑端 MAX_UPLOAD 一致的 1 GB 单文件上限。
    // 收发都走流式（1 MB 块 + 局部密钥流），不再把整包读进 byte[]。
    private static final long MAX_FILE_BYTES = 1024L * 1024 * 1024;
    private static final int MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
    private boolean confirming = false;
    private Dialog confirmBox = null;
    private Dialog progressBox = null;
    private Dialog resultBox = null;
    /** 6.2.2（H1）：首次配对 / 换标签的用户确认框。 */
    private Dialog pairDialog = null;
    private TextView tvProgressMsg = null;
    private TextView tvConfirmCountdown = null;
    private CountDownTimer resultTimer = null;
    private CountDownTimer confirmTimer = null;
    // 碰标签后先画出来的状态页；以及「选择器已弹出 / 已返回」的调度状态。
    private TextView tvTapStatus = null;
    private TextView tvTapHint = null;
    private boolean pickerLaunched = false;
    private boolean pickerReturned = false;
    /** outbox 探测命中待发文件时主动收掉选择器，接收流程接管。 */
    private boolean outboxTakeover = false;
    /** 用户已经选好文件（或寄存文件），发送流程接管，反向探测不再抢方向。 */
    private boolean flowCommittedToSend = false;
    /** 探测在用户已经进入发送后才拿到「电脑有待发」结论时，暂存文件名等发送结束再问。 */
    private volatile String latePendingName = null;
    /** 「补接收」模式：只接收，不再回落到发送流程。 */
    private boolean receiveOnly = false;
    /**
     * 6.2.5：方向探测进行中。重复碰标签必须忽略——否则第二次探测会在待发文件
     * 已被第一次接收后得到「没有待发」，反而把用户推进文件选择器。
     */
    private volatile boolean outboxProbeActive = false;
    /** 本次碰标签流程的起点（elapsedRealtime），仅用于 logcat 阶段耗时定位。 */
    private long t0 = 0;

    private long since() {
        return t0 == 0 ? 0 : android.os.SystemClock.elapsedRealtime() - t0;
    }

    private void mark(String stage) {
        Log.i(TAG, "T+" + since() + "ms " + stage);
    }

    /**
     * 碰标签/分享后的第一帧就画出可见界面。
     * 之前本 Activity 没有内容视图，窗口只剩深色 windowBackground，
     * 真机表现为「碰完先黑屏一段时间，再跳到文件选择器」。
     */
    private void showTapStatus(String msg, String hint) {
        setContentView(R.layout.activity_tap_status);
        tvTapStatus = findViewById(R.id.tvTapStatus);
        tvTapHint = findViewById(R.id.tvTapHint);
        setStatus(msg, hint);
    }

    private void setStatus(String msg, String hint) {
        if (tvTapStatus != null && msg != null) tvTapStatus.setText(msg);
        if (tvTapHint != null && hint != null) tvTapHint.setText(hint);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Intent it = getIntent();
        String action = it == null ? null : it.getAction();
        t0 = android.os.SystemClock.elapsedRealtime();
        Log.i(TAG, "T+0 onCreate action=" + action);
        // 6.2.3：选择器已弹出时 Activity 被重建（旋转 / 系统回收），不能再按原始
        // 标签 Intent 重跑一遍流程，否则会重复拉起选择器、也会丢失接收方向的判定。
        if (savedInstanceState != null && savedInstanceState.getBoolean(STATE_PICKER, false)) {
            pickerLaunched = true;
            showTapStatus("正在连接电脑…", "选好文件后立即传送");
            mark("Activity 重建：选择器已弹出，等待选择结果");
            return;
        }
        if (Intent.ACTION_SEND.equals(action) || Intent.ACTION_SEND_MULTIPLE.equals(action)) {
            showTapStatus("正在寄存文件…", "寄存后碰一下标签即可传到电脑");
            handleShare(it);
        } else if (isTagAction(action)) {
            showTapStatus("正在读取标签…", "请保持手机贴近电脑");
            mark("状态页已绘制（首帧内容就绪）");
            handleNfc(it);
        } else {
            startActivity(new Intent(this, MainActivity.class));
            finish();
        }
    }

    @Override
    protected void onSaveInstanceState(Bundle outState) {
        super.onSaveInstanceState(outState);
        outState.putBoolean(STATE_PICKER, pickerLaunched && !pickerReturned);
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        if (isTagAction(intent.getAction())) handleNfc(intent);
    }

    /** 6.2.2（H1）：只认系统 NFC 派发的 NDEF 标签；TECH/TAG 不含配对 URI。 */
    private static boolean isTagAction(String action) {
        return NfcAdapter.ACTION_NDEF_DISCOVERED.equals(action);
    }

    // ---- A) 图库分享：寄存待发图片 ----
    private void handleShare(Intent intent) {
        Uri uri = getStreamUri(intent);
        if (uri == null) {
            // 纯文本分享（没有 EXTRA_STREAM）不是本 App 的职责
            toast("没有收到文件，请用「分享 → 一碰传」发送文件");
            finish();
            return;
        }

        String name = queryDisplayName(uri);
        if (name == null || name.trim().isEmpty()) {
            // 没有显示名时按分享方给的 mime 猜扩展名，避免退化成 .bin
            name = "shared_file" + extFromMime(intent.getType());
        }

        // 2026-11-13 真机实测修复：
        // 原先只在 takePersistableUriPermission() 抛 SecurityException 时才退化到私有缓存，
        // 但小米 HyperOS 3 / Android 16 的 MediaProvider 不抛异常、也不授予持久读权限。
        // 结果分享时寄存成功，之后 TapActivity 再打开同一个 content:// URI 时报
        //   SecurityException: ... has no access to content://media/external/images/media/7754
        // 表现为「读不到寄存的图片，请重新分享一次」。
        // 修正：分享当场就把原始字节读进 App 私有缓存，后续只认私有文件，
        // 完全不依赖 ROM 的 URI 持久授权行为。
        String cached = cacheBytes(uri, name);
        if (cached != null) {
            savePending(Uri.parse("cache://" + cached), name);
            toast("已寄存「" + name + "」，碰一下 NFC 标签即可传到电脑");
            finish();
            return;
        }

        // 兜底：极少数情况下读不到字节（例如 URI 已失效），仍尝试持久权限 + 原 URI
        Log.w(TAG, "私有缓存失败，退回 content URI + 持久权限");
        try {
            getContentResolver().takePersistableUriPermission(
                    uri, Intent.FLAG_GRANT_READ_URI_PERMISSION);
        } catch (SecurityException e) {
            Log.w(TAG, "持久 URI 权限不可用: " + e.getMessage());
        }
        savePending(uri, name);
        toast("已寄存「" + name + "」，碰一下 NFC 标签即可传到电脑");
        finish();
    }

    @SuppressWarnings("deprecation")
    private Uri getStreamUri(Intent intent) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            return intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri.class);
        }
        return intent.getParcelableExtra(Intent.EXTRA_STREAM);
    }

    private void savePending(Uri uri, String name) {
        prefs().edit()
                .putString(Prefs.KEY_PENDING_URI, uri.toString())
                .putString(Prefs.KEY_PENDING_NAME, name)
                .apply();
    }

    private String cacheBytes(Uri uri, String displayName) {
        String fname = null;
        try {
            // v6.2：流式落盘，1 GB 文件也不整段进内存
            long declaredSize = querySize(uri);
            if (declaredSize > MAX_FILE_BYTES) {
                Log.w(TAG, "分享文件超过上限，拒绝缓存：" + declaredSize);
                return null;
            }
            // 文件名加时间戳前缀避免覆盖；保留原扩展名，方便落盘与类型识别
            String safe = displayName == null ? "photo.jpg" : displayName;
            safe = safe.replace('/', '_').replace('\\', '_');
            fname = "pending_" + System.currentTimeMillis() + "_" + safe;
            try (InputStream in = getContentResolver().openInputStream(uri);
                 FileOutputStream fos = openFileOutput(fname, Context.MODE_PRIVATE)) {
                if (in == null) return null;
                long total = copyLimited(in, fos, MAX_FILE_BYTES);
                if (total == 0) {
                    deleteFile(fname);
                    return null;
                }
                Log.i(TAG, "已缓存 " + total + " 字节 -> " + fname);
            }
            return fname;
        } catch (Exception e) {
            Log.e(TAG, "cacheBytes 失败", e);
            if (fname != null) deleteFile(fname);
            return null;
        }
    }

    private String queryDisplayName(Uri uri) {
        if (ContentResolver.SCHEME_CONTENT.equals(uri.getScheme())) {
            try (Cursor c = getContentResolver().query(uri, null, null, null, null)) {
                if (c != null) {
                    int idx = c.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                    if (idx >= 0 && c.moveToFirst()) return c.getString(idx);
                }
            } catch (Exception e) {
                Log.w(TAG, "queryDisplayName 失败: " + e.getMessage());
            }
        }
        return uri.getLastPathSegment();
    }

    // ---- B) 碰标签：解析 -> 取图 -> 自动发现电脑 -> 换 token -> 上传 ----
    //
    // v4 免寄存：把取图时机从「分享时」挪到「碰标签时」。
    //    MODE_PICKER（默认）   每次碰标签拉起系统文件选择器，用户点选后才发
    //    MODE_LEGACY          旧行为，只发「分享寄存」的文件
    //    MODE_AUTO_RECENT     自动取媒体库最近一张（限时间窗口，需确认）
    //    MODE_AUTO_ANY        自动取媒体库最近一张（不限时间，需确认）
    // 若有「分享寄存」的文件，一律优先用它（用户明确指定过，最不容易发错）。
    // v3：默认不再自动取相册最新图；确认窗超时自动取消，不自动发送。
    private static final int REQ_PICK_FILE = 4201;
    /** 6.2.3：选择器已弹出但还没返回（用于 Activity 重建后不重复拉起）。 */
    private static final String STATE_PICKER = "picker_open";

    private void handleNfc(Intent intent) {
        mark("handleNfc 开始");
        if (confirming) {
            Log.i(TAG, "确认窗还在，忽略这次碰标签");
            return;
        }
        // 6.2.3：选择器已经弹出、用户还没选完，重复碰标签不能把流程再跑一遍，
        // 否则会叠加新选择器、也会把已经定好的方向重置。
        if (pickerLaunched && !pickerReturned) {
            Log.i(TAG, "文件选择器已弹出，忽略这次重复碰标签");
            return;
        }
        if (outboxProbeActive) {
            Log.i(TAG, "上一次碰标签的方向探测尚未结束，忽略这次重复碰标签");
            toast("正在处理上一次碰标签…");
            return;
        }
        // v7：上一次的结果框若还停着（用户没点「完成」），这次碰标签先收掉它，
        // 否则新流程会被盖在下面，看起来像「碰了没反应」。
        dismissResult();
        String payload = extractPairUri(intent);
        if (payload == null) {
            toast("标签里没有 nfctap:// 配对信息");
            finish();
            return;
        }

        Uri u = Uri.parse(payload);
        String code = u.getQueryParameter("k");
        String deviceId = u.getQueryParameter("d");
        String hint = u.getQueryParameter("c");
        String host = u.getQueryParameter("h");
        int port = 8765;
        String ps = u.getQueryParameter("p");
        if (ps != null) {
            try { port = Integer.parseInt(ps); } catch (NumberFormatException ignored) {}
        }
        if (code == null || code.trim().isEmpty()) {
            toast("标签缺少 64 位十六进制配对密钥 k");
            finish();
            return;
        }
        final String fCode = code.trim();
        final String fTagHost = host == null ? "" : host.trim();
        final int fTagPort = port;
        final String fHint = hint == null ? "" : hint.trim();

        // v3：k 必须是 64 hex；d 必须等于标签里的 d 或由 k 算出的 d。
        // 标签没写 d 时由 k 派生，不再从 prefs / BuildConfig 取旧设备 ID。
        String computedDid;
        try {
            computedDid = V3Crypto.deviceId(fCode);
        } catch (Exception e) {
            toast("标签里的配对密钥 k 必须是 64 位十六进制");
            finish();
            return;
        }
        final String fComputedDid = computedDid;
        if (deviceId != null && !deviceId.trim().isEmpty()
                && !deviceId.trim().equalsIgnoreCase(fComputedDid)) {
            toast("标签设备 ID 与配对密钥不匹配，已取消");
            finish();
            return;
        }
        final String fDeviceId = fComputedDid;

        // 6.2.4：防注入收紧。已配对过电脑后，只接受同一台电脑的标签。
        // 之前允许「connect 失败 → 用系统解析的 URI 兜底」，恶意 App 可以显式
        // Intent 注入一条 nfctap:// 把手机改绑到别的电脑；现在设备 ID 必须与
        // 已配对的一致，首次配对仍走 H1 的用户确认弹窗。
        SharedPreferences pin = prefs();
        String pinnedDid = pin.getString(Prefs.KEY_DEVICE_ID, "");
        if (pinnedDid != null && !pinnedDid.isEmpty()
                && !pinnedDid.equalsIgnoreCase(fComputedDid)) {
            Log.w(TAG, "拒绝设备 ID 不匹配的标签：已配对 "
                    + pinnedDid.substring(0, Math.min(6, pinnedDid.length()))
                    + "…，标签 " + fComputedDid.substring(0, Math.min(6, fComputedDid.length())) + "…");
            toast("这张标签不属于已配对的电脑，已拒绝。更换电脑请在「一碰传」主界面重新填写配对密钥");
            finish();
            return;
        }
        Log.i(TAG, "标签参数 d=" + fDeviceId.substring(0, Math.min(6, fDeviceId.length()))
                + "… h=" + (fTagHost.isEmpty() ? "(无)" : fTagHost)
                + " c=" + (fHint.isEmpty() ? "(无)" : fHint)
                + " p=" + fTagPort);

        // 6.2.2（H1）：首次配对 / 换标签必须由用户明示确认；
        // 未确认前绝不覆盖已有 k/h/p，避免恶意标签或显式 Intent 静默改写配对。
        SharedPreferences p = prefs();
        String oldCode = p.getString(Prefs.KEY_CODE, "");
        boolean firstPair = oldCode == null || oldCode.isEmpty();
        boolean changed = !firstPair && !oldCode.equalsIgnoreCase(fCode);
        if (firstPair || changed) {
            confirmPairing(fCode, fDeviceId, fTagHost, fTagPort, fHint, firstPair);
            return;
        }
        applyTagAndContinue(fCode, fDeviceId, fTagHost, fTagPort, fHint);
    }

    /** 写入本次碰标签的配对参数，并继续 outbox 探测 / 选择文件流程。 */
    private void applyTagAndContinue(String fCode, String fDeviceId, String fTagHost,
                                     int fTagPort, String fHint) {
        // 把碰标签的原始参数落到 prefs：系统照片选择器返回后 Activity 可能已被重建，
        // 发现流程从 prefs 恢复，不依赖实例字段。
        // apply() 同步更新内存、异步落盘：主线程不必等磁盘，后台线程读到的也是新值。
        SharedPreferences p = prefs();
        p.edit()
         .putString(Prefs.KEY_CODE, fCode)
         .putString(Prefs.KEY_DEVICE_ID, fDeviceId)
         .putInt(Prefs.KEY_PORT, fTagPort)
         .putString(Prefs.KEY_TAG_HOST, fTagHost)
         .putString(Prefs.KEY_TAG_HINT, fHint)
         .putInt(Prefs.KEY_TAG_PORT, fTagPort)
         .apply();
        mark("标签解析 + prefs 写入完成");

        // 6.2.5：方向只由 outbox 探测的结论决定，不再用短计时器「抢跑」。
        // 6.2.3 的「1.5 秒内没结论就先弹选择器」在真机上必然失效：一次完整发现是
        // 「缓存 ping → BLE 扫描 3.5 s → UDP 2.2 s → 子网扫描」，除「缓存地址仍有效」
        // 这条快路径外都超过 1.5 秒。选择器一旦先出现，用户点选就置 flowCommittedToSend，
        // 接收方向被抢走；而 finishActivity 收不掉系统 SAF 选择器（跨任务/后台启动限制）。
        // 现在：状态页停在「正在连接电脑…」，等探测给出确定结论——
        //   有待发文件 → 直接接收；
        //   没待发 / 电脑不在线 / 协议不符 → 再打开文件选择器。
        boolean hasPendingShare = p.getString(Prefs.KEY_PENDING_URI, null) != null;
        int sendMode = p.getInt(Prefs.KEY_SEND_MODE, Prefs.MODE_PICKER);
        boolean pickerMode = !hasPendingShare && sendMode == Prefs.MODE_PICKER;
        setStatus("正在连接电脑…",
                pickerMode ? "电脑有待发会直接接收，没有则稍后打开文件选择" : null);

        // v6.1：电脑端「发送到手机」优先。桌面端暂存文件时，碰标签直接收文件，
        // 不再弹选择器 / 不读相册 / 不上传。服务端没有待发文件时静默回落到旧流程。
        // 把刚解析出的标签参数直接传进去，避免反向发送探测拿到旧 hint / 旧 k。
        mark("提交后台 outbox 探测");
        tryReceiveOutbox(fCode, fDeviceId, fTagHost, fTagPort, fHint);
    }

    /** 首次配对或 k 变化时弹窗确认；取消则直接结束，不写任何 prefs。 */
    private void confirmPairing(String code, String did, String host, int port,
                                String hint, boolean firstPair) {
        if (isFinishing()) return;
        if (pairDialog != null && pairDialog.isShowing()) pairDialog.dismiss();
        String target = (host == null || host.isEmpty())
                ? "目标：自动发现（UDP / BLE）" : "目标：" + host + ":" + port;
        String msg = "设备 " + did.substring(0, Math.min(8, did.length())) + "…\n" + target
                + "\n\n只有在你确实把手机贴近了这台电脑的 NFC 标签时才继续。"
                + (firstPair ? "" : "替换后，之前寄存的文件会发往新设备。");
        pairDialog = new AlertDialog.Builder(this)
                .setTitle(firstPair ? "首次与该标签配对" : "检测到新的配对标签")
                .setMessage(msg)
                .setCancelable(false)
                .setPositiveButton("继续配对",
                        (d, w) -> applyTagAndContinue(code, did, host, port, hint))
                .setNegativeButton("取消", (d, w) -> finish())
                .show();
    }

    /** 探测电脑端 outbox；有待发文件则下载到手机，否则继续原来的发送流程。 */
    private void tryReceiveOutbox(String code, String deviceId, String tagHost,
                                  int tagPort, String hint) {
        outboxProbeActive = true;
        outboxIo.execute(() -> {
            try {
                SharedPreferences p = prefs();
                DiscoveryClient dc = new DiscoveryClient(TapActivity.this);
                mark("后台 discover 开始");
                DiscoveryClient.Endpoint ep =
                        dc.discover(deviceId, code, tagHost, tagPort, hint);
                mark("后台 discover 结束 ep=" + (ep == null ? "null" : ep.via));
                // 用户已经选好文件、发送流程接管：别再改写会话/地址，直接退出。
                if (flowCommittedToSend) {
                    Log.i(TAG, "用户已选择文件，放弃反向发送探测");
                    return;
                }
                if (ep == null) {
                    Log.i(TAG, "反向发送探测：未发现电脑，回落到原发送流程");
                    runOnUiThread(this::continueAfterOutbox);
                    return;
                }
                final String fHost = ep.host;
                final int fPort = ep.port;
                p.edit().putString(Prefs.KEY_HOST, fHost)
                        .putInt(Prefs.KEY_PORT, fPort).apply();
                runOnUiThread(() -> {
                    if (!isFinishing()) setStatus("已连上电脑", "正在检查是否有待发文件…");
                });
                String proto = serverProtocol(fHost, fPort);
                mark("protocol 校验完成 proto=" + proto);
                if (flowCommittedToSend) return;
                if (!V3Crypto.PROTOCOL.equals(proto)) {
                    runOnUiThread(this::continueAfterOutbox);
                    return;
                }
                String token = getToken(p, fHost, fPort, code, deviceId);
                mark("pair/token 完成");
                if (flowCommittedToSend) return;
                OutboxInfo info = fetchOutbox(fHost, fPort, token);
                // 「没问到结论」不能当成「没有待发」：先重试一次，避免网络抖动/
                // 服务端瞬时 5xx 把用户直接推进发送方向。
                if (!info.known && !info.authFail) {
                    Log.w(TAG, "outbox 查询未得到确定结果（" + info.error + "），200ms 后重试一次");
                    Thread.sleep(200);
                    info = fetchOutbox(fHost, fPort, token);
                }
                mark("outbox 查询完成 hasPending=" + info.hasPending + " known=" + info.known);
                if (flowCommittedToSend) {
                    // 用户已经选好文件在发送：不打断，但把待发文件记下来，
                    // 发送结束后再问一次，避免「电脑发送了、手机却只发送」。
                    if (info.hasPending) latePendingName = info.name;
                    Log.i(TAG, "用户已选择文件，接收探测结果留到发送结束后处理");
                    return;
                }
                if (!info.hasPending) {
                    if (info.authFail) {
                        clearSession(p);
                        String token2 = getToken(p, fHost, fPort, code, deviceId);
                        info = fetchOutbox(fHost, fPort, token2);
                        if (info.hasPending) {
                            token = p.getString(Prefs.KEY_TOKEN, "");
                        } else {
                            if (!info.known) {
                                Log.w(TAG, "outbox 复询仍未拿到结论：" + info.error);
                            }
                            runOnUiThread(this::continueAfterOutbox);
                            return;
                        }
                    } else {
                        if (!info.known) {
                            Log.w(TAG, "outbox 未确认（" + info.error + "），按无待发继续");
                        }
                        runOnUiThread(this::continueAfterOutbox);
                        return;
                    }
                }
                final OutboxInfo fInfo = info;
                runOnUiThread(() -> {
                    if (flowCommittedToSend || isFinishing()) return;
                    Log.i(TAG, "电脑端有待发文件：" + fInfo.name);
                    // 选择器已经弹出且用户还没选：主动收掉，改由接收流程接管。
                    // 6.2.5 起正常路径不会再提前弹选择器，这里只保留兜底。
                    if (pickerLaunched && !pickerReturned) {
                        outboxTakeover = true;
                        finishActivity(REQ_PICK_FILE);
                        mark("电脑有待发文件，收掉文件选择器改为接收");
                    }
                    showProgress(fInfo.name);
                    setProgress("已连上电脑\n正在接收文件…");
                });
                DownloadResult r = downloadOutbox(p, code, fHost, fPort, token, fInfo);
                final DownloadResult fr = r;
                runOnUiThread(() -> {
                    if (fr.ok) {
                        Log.i(TAG, "✓ 已从电脑接收：" + fr.savedAs);
                        showResult(true, "已保存到手机",
                                fInfo.name + "\n" + fmtSize(fr.bytes)
                                + "\n\n已保存到手机的 Download/一碰传 目录\n"
                                + "文件：" + fr.savedAs + "\n"
                                + "sha256：" + fInfo.sha256);
                    } else {
                        Log.w(TAG, "接收电脑文件失败：" + fr.error);
                        showResult(false, "接收失败", fr.error);
                    }
                });
            } catch (Exception e) {
                Log.w(TAG, "反向发送探测异常，回落到原发送流程：" + e.getMessage());
                runOnUiThread(this::continueAfterOutbox);
            } finally {
                outboxProbeActive = false;
            }
        });
    }

    /** outbox 为空 / 电脑端不支持时，恢复 6.0.1 的既有碰标签行为。 */
    private void continueAfterOutbox() {
        mark("回到主线程 continueAfterOutbox");
        if (isFinishing() || flowCommittedToSend) return;
        // 探测已有结论（无待发 / 电脑不在线）：方向定为发送。
        if (receiveOnly) {
            // 用户在「电脑还有待发文件」弹窗里选了接收，但此刻已经取不到待发文件，
            // 不能回落到发送流程（否则又变成一次误发送）。
            receiveOnly = false;
            Log.i(TAG, "补接收：电脑端已无待发文件，结束");
            finish();
            return;
        }
        SharedPreferences p = prefs();
        String pending = p.getString(Prefs.KEY_PENDING_URI, null);
        String pendingName = p.getString(Prefs.KEY_PENDING_NAME, "file");
        if (pending != null) {
            flowCommittedToSend = true;
            sendPending(pending, pendingName == null ? "photo.jpg" : pendingName);
            return;
        }
        int mode = p.getInt(Prefs.KEY_SEND_MODE, Prefs.MODE_PICKER);
        if (mode == Prefs.MODE_LEGACY) {
            toast("还没有寄存文件。请先在其他应用里「分享 → 一碰传」");
            finish();
            return;
        }
        if (mode == Prefs.MODE_PICKER) {
            // 碰标签时已经提前拉起过选择器，这里不再重复弹一次。
            if (!pickerLaunched) launchPicker("点选要传送的文件");
            return;
        }
        long windowSec = mode == Prefs.MODE_AUTO_ANY ? -1
                : p.getInt(Prefs.KEY_AUTO_WINDOW_MIN, Prefs.DEFAULT_WINDOW_MIN) * 60L;
        toast("已碰标签，正在取最近图片…");
        setStatus("正在取最近图片…", null);
        io.execute(() -> {
            RecentImage.Result r = RecentImage.pick(TapActivity.this, windowSec);
            runOnUiThread(() -> {
                if (r.code == RecentImage.OK && r.item != null) {
                    Log.i(TAG, "自动取图命中：" + r.item.name + "，弹 " + CONFIRM_SECONDS + " 秒确认");
                    confirmThenSend(r.item.uri, r.item.name, r.item.size);
                } else {
                    toast(r.msg + "，点选一张即可传送");
                    launchPicker(null);
                }
            });
        });
    }

    private static class OutboxInfo {
        /** known=false 表示「没问到结论」（超时/5xx/解析失败），不能当成「没有待发」。 */
        final boolean hasPending, authFail, known;
        final String id, name, sha256, mime, error;
        final long bytes;
        OutboxInfo(boolean hasPending, boolean authFail, boolean known, String id, String name,
                   String sha256, String mime, long bytes, String error) {
            this.hasPending = hasPending; this.authFail = authFail; this.known = known;
            this.id = id; this.name = name; this.sha256 = sha256;
            this.mime = mime; this.bytes = bytes; this.error = error;
        }
        /** 服务端明确回答：没有待发文件。 */
        static OutboxInfo none() {
            return new OutboxInfo(false, false, true, "", "", "", "", 0, "");
        }
        /** 没拿到确定答案：网络错误 / 5xx / 载荷解析失败。 */
        static OutboxInfo unknown(boolean authFail, String error) {
            return new OutboxInfo(false, authFail, false, "", "", "", "", 0, error);
        }
    }

    private OutboxInfo fetchOutbox(String host, int port, String token) throws Exception {
        HttpURLConnection c = null;
        try {
            c = (HttpURLConnection) new URL(
                    "http://" + host + ":" + port + "/api/outbox").openConnection();
            c.setRequestMethod("GET");
            c.setConnectTimeout(4000);
            c.setReadTimeout(8000);
            c.setRequestProperty("Authorization", "Bearer " + token);
            int status = c.getResponseCode();
            String text = readResponse(c, status);
            if (status == 401 || status == 403) {
                return OutboxInfo.unknown(true, "会话失效");
            }
            if (status != 200) return OutboxInfo.unknown(false, "HTTP " + status);
            JSONObject j = new JSONObject(text);
            if (!j.optBoolean("ok")) return OutboxInfo.unknown(false, "ok=false");
            // 与电脑端 /api/outbox 的约定：ok=true 时 pending 要么是对象，要么是 null。
            // 只有读到这个字段才算「确定没有待发」，缺字段一律按未知处理。
            if (!j.has("pending")) return OutboxInfo.unknown(false, "缺少 pending 字段");
            if (j.isNull("pending")) return OutboxInfo.none();
            JSONObject q = j.getJSONObject("pending");
            String id = q.optString("id", "");
            if (id.isEmpty()) return OutboxInfo.unknown(false, "pending 缺少 id");
            return new OutboxInfo(true, false, true, id,
                    q.optString("name", "file"), q.optString("sha256", ""),
                    q.optString("mime", "application/octet-stream"),
                    q.optLong("bytes", 0), "");
        } finally {
            if (c != null) c.disconnect();
        }
    }

    private static class DownloadResult {
        final boolean ok;
        final String savedAs, error;
        final long bytes;
        DownloadResult(boolean ok, String savedAs, long bytes, String error) {
            this.ok = ok; this.savedAs = savedAs; this.bytes = bytes; this.error = error;
        }
        static DownloadResult fail(String error) {
            return new DownloadResult(false, "", 0, error);
        }
    }

    /**
     * v6.2：流式接收。响应体 = "NT3" + nameLen + name + tag(32) + cipher。
     * 先读头部派生密钥，再按 1 MB 块「校验 HMAC + 就地解密 + 写盘 + 算 SHA-256」，
     * 峰值内存只有一块，1 GB 文件也不会 OOM；长度取自 Content-Length（long）。
     */
    private DownloadResult downloadOutbox(SharedPreferences p, String code,
                                          String host, int port,
                                          String token, OutboxInfo info) {
        HttpURLConnection c = null;
        ContentResolver cr = getContentResolver();
        Uri pendingUri = null;
        File tmpFile = null;
        boolean committed = false;
        try {
            String sn = p.getString(Prefs.KEY_SERVER_NONCE, "");
            String cn = p.getString(Prefs.KEY_CLIENT_NONCE, "");
            long ts = System.currentTimeMillis() / 1000;
            String nonce = V3Crypto.randomHex12();
            c = (HttpURLConnection) new URL("http://" + host + ":" + port
                    + "/api/download?id=" + info.id).openConnection();
            c.setRequestMethod("GET");
            c.setConnectTimeout(8000);
            // 1 GB：服务端要先扫一遍明文算 tag 才发首字节，首包可能等数分钟；
            // 传输阶段按块持续有数据，读超时只约束「单次无数据」的间隔。
            c.setReadTimeout(300000);
            c.setRequestProperty("Authorization", "Bearer " + token);
            c.setRequestProperty("X-Nonce", nonce);
            c.setRequestProperty("X-Ts", String.valueOf(ts));
            int status = c.getResponseCode();
            if (status != 200) {
                String text = readResponse(c, status);
                JSONObject j = new JSONObject(text);
                if (status == 401 || status == 403) clearSession(p);
                return DownloadResult.fail(j.optString("error", "HTTP " + status));
            }
            if (!info.id.equalsIgnoreCase(c.getHeaderField("X-Outbox-Id"))) {
                return DownloadResult.fail("服务端返回的文件 ID 不匹配");
            }
            long total = c.getContentLengthLong();
            if (total <= 0) return DownloadResult.fail("服务端未给出下载长度");
            if (total > MAX_FILE_BYTES + 4096L) {
                return DownloadResult.fail("待接收文件超过 " + fmtSize(MAX_FILE_BYTES) + " 上限");
            }

            InputStream in = c.getInputStream();
            byte[] magic = readFully(in, 4);
            if (magic[0] != 'N' || magic[1] != 'T' || magic[2] != '3') {
                return DownloadResult.fail("下载载荷格式错误");
            }
            int nameLen = magic[3] & 0xff;
            if (nameLen == 0) return DownloadResult.fail("下载载荷长度错误");
            byte[] rest = readFully(in, nameLen + 32);
            byte[] prefix = new byte[4 + nameLen + 32];
            System.arraycopy(magic, 0, prefix, 0, 4);
            System.arraycopy(rest, 0, prefix, 4, rest.length);
            long cipherLen = total - prefix.length;
            if (info.bytes > 0 && info.bytes != cipherLen) {
                return DownloadResult.fail("服务端长度字段不一致，已拒绝保存");
            }
            V3Crypto.Inbound bound = V3Crypto.beginDownload(code, sn, cn, token, ts,
                    nonce, info.id, prefix, cipherLen);

            String safe = info.name.replace('/', '_').replace('\\', '_');
            String stamp = new java.text.SimpleDateFormat(
                    "yyyyMMdd-HHmmss", Locale.CHINA).format(new java.util.Date());
            String out = stamp + "-" + safe;

            OutputStream os;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                ContentValues v = new ContentValues();
                v.put(MediaStore.Downloads.DISPLAY_NAME, out);
                v.put(MediaStore.Downloads.MIME_TYPE, info.mime);
                v.put(MediaStore.Downloads.RELATIVE_PATH,
                        android.os.Environment.DIRECTORY_DOWNLOADS + "/一碰传");
                v.put(MediaStore.Downloads.IS_PENDING, 1);
                pendingUri = cr.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, v);
                if (pendingUri == null) throw new java.io.IOException("无法创建下载记录");
                os = cr.openOutputStream(pendingUri);
                if (os == null) throw new java.io.IOException("无法写入下载文件");
            } else {
                tmpFile = new File(getFilesDir(), out + ".part");
                os = new FileOutputStream(tmpFile);
            }

            MessageDigest md = MessageDigest.getInstance("SHA-256");
            long got = 0, lastPct = -1;
            try (OutputStream fo = os) {
                byte[] buf = new byte[V3Crypto.CHUNK];
                while (got < cipherLen) {
                    int n = in.read(buf, 0, (int) Math.min(buf.length, cipherLen - got));
                    if (n < 0) {
                        throw new java.io.IOException(
                                "接收中断：只收到 " + got + " / " + cipherLen + " 字节");
                    }
                    bound.feed(buf, 0, n);
                    md.update(buf, 0, n);
                    fo.write(buf, 0, n);
                    got += n;
                    long pct = got * 100 / cipherLen;
                    if (pct != lastPct) {
                        lastPct = pct;
                        final long fGot = got, fTotal = cipherLen;
                        runOnUiThread(() -> setProgress(
                                "正在接收… " + fmtSize(fGot) + " / " + fmtSize(fTotal)));
                    }
                }
                fo.flush();
            }
            bound.verify();
            String digest = hex(md.digest());
            if (!info.sha256.equalsIgnoreCase(digest)) {
                throw new java.io.IOException("文件校验和不匹配，已拒绝保存");
            }
            if (pendingUri != null) {
                ContentValues done = new ContentValues();
                done.put(MediaStore.Downloads.IS_PENDING, 0);
                cr.update(pendingUri, done, null, null);
                pendingUri = null;
            } else if (tmpFile != null) {
                File dest = new File(getFilesDir(), out);
                if (!tmpFile.renameTo(dest)) throw new java.io.IOException("无法保存到应用私有目录");
                tmpFile = null;
            }
            committed = true;
            return new DownloadResult(true, out, cipherLen, "");
        } catch (Exception e) {
            return DownloadResult.fail(e.getMessage() == null ? "接收异常" : e.getMessage());
        } finally {
            if (!committed) {
                if (pendingUri != null) {
                    try {
                        cr.delete(pendingUri, null, null);
                    } catch (Exception ignored) {
                    }
                }
                if (tmpFile != null) {
                    try {
                        tmpFile.delete();
                    } catch (Exception ignored) {
                    }
                }
            }
            if (c != null) c.disconnect();
        }
    }

    /** 从流里读满 n 字节，不足即抛；用于固定长度的协议头。 */
    private static byte[] readFully(InputStream in, int n) throws Exception {
        byte[] out = new byte[n];
        int off = 0;
        while (off < n) {
            int r = in.read(out, off, n - off);
            if (r < 0) throw new java.io.IOException("下载响应不完整");
            off += r;
        }
        return out;
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format(Locale.ROOT, "%02x", x & 0xff));
        return sb.toString();
    }

    /** v7：传送进度框，带文件名，避免用户以为「点完就退出了」。 */
    private void showProgress(String name) {
        if (isFinishing()) return;
        dismissProgress();
        progressBox = newDialog(R.layout.dialog_progress);
        tvProgressMsg = progressBox.findViewById(R.id.tvProgressMsg);
        tvProgressMsg.setText("正在寻找电脑…");
        ((TextView) progressBox.findViewById(R.id.tvProgressFile)).setText(name);
        progressBox.setCancelable(false);
        progressBox.show();
    }

    private void setProgress(String msg) {
        if (progressBox != null && progressBox.isShowing() && tvProgressMsg != null) {
            tvProgressMsg.setText(msg);
        }
    }

    private void dismissProgress() {
        try {
            if (progressBox != null && progressBox.isShowing()) progressBox.dismiss();
        } catch (Exception ignored) {
        }
        progressBox = null;
        tvProgressMsg = null;
    }

    /**
     * v7：结果框。成功也停下来让用户看清（标题 / 内容含文件名、大小、落点），
     * 失败给可操作的原因。点「完成」才关闭，不再靠一闪而过的 Toast。
     */
    private void showResult(boolean ok, String title, String detail) {
        dismissProgress();
        dismissResult();
        if (isFinishing() || isDestroyed()) return;
        resultBox = newDialog(R.layout.dialog_result);
        View dot = resultBox.findViewById(R.id.dotResult);
        dot.setBackgroundTintList(ColorStateList.valueOf(
                getColor(ok ? R.color.success : R.color.danger)));
        ((TextView) resultBox.findViewById(R.id.tvResultTitle)).setText(title);
        ((TextView) resultBox.findViewById(R.id.tvResultBody))
                .setText(detail + "\n\n（" + RESULT_SECONDS + " 秒后自动关闭）");
        ((Button) resultBox.findViewById(R.id.btnResultDone))
                .setOnClickListener(v -> finish());
        // 2026-11-13 实测：这个框若一直停着，MIUI 会拒绝下一次 am start/
        // 碰标签的启动（ActivityTaskManager 直接 abort），表现为「再碰没反应」。
        // 所以允许返回键关闭，并在 15 秒后自动收掉，绝不长期占用前台。
        resultBox.setCancelable(true);
        resultBox.setOnCancelListener(d -> finish());
        resultBox.show();
        if (resultTimer != null) resultTimer.cancel();
        resultTimer = new CountDownTimer(RESULT_SECONDS * 1000L, 1000) {
            @Override public void onTick(long left) { }
            @Override public void onFinish() {
                Log.i(TAG, "结果提示超时自动关闭");
                dismissResult();
                finish();
            }
        };
        resultTimer.start();
    }

    /**
     * 6.2.4：反向探测如果在用户已经进入发送后才拿到「电脑有待发」结论，
     * 发送结束后再给一次接收机会，避免「电脑发送了、手机却只发送」。
     */
    private void maybeOfferLatePending() {
        final String name = latePendingName;
        if (name == null || isFinishing() || isDestroyed()) return;
        latePendingName = null;
        // 结果框 15 秒自动关闭会在用户读弹窗时把 Activity 一起结束，先停掉计时。
        try {
            if (resultTimer != null) {
                resultTimer.cancel();
                resultTimer = null;
            }
        } catch (Exception ignored) {
        }
        new AlertDialog.Builder(this)
                .setTitle("电脑还有待发文件")
                .setMessage("「" + name + "」还没有接收。\n\n现在接收吗？刚发送的文件不受影响。")
                .setPositiveButton("现在接收", (d, w) -> {
                    dismissResult();
                    flowCommittedToSend = false;
                    pickerLaunched = false;
                    pickerReturned = false;
                    receiveOnly = true;
                    showTapStatus("正在连接电脑…", "正在接收待发文件");
                    SharedPreferences p = prefs();
                    tryReceiveOutbox(p.getString(Prefs.KEY_CODE, ""),
                            p.getString(Prefs.KEY_DEVICE_ID, ""),
                            p.getString(Prefs.KEY_TAG_HOST, ""),
                            p.getInt(Prefs.KEY_TAG_PORT, 8765),
                            p.getString(Prefs.KEY_TAG_HINT, ""));
                })
                .setNegativeButton("稍后", (d, w) -> finish())
                .setCancelable(false)
                .show();
    }

    private void dismissResult() {
        try {
            if (resultTimer != null) resultTimer.cancel();
        } catch (Exception ignored) {
        }
        resultTimer = null;
        try {
            if (resultBox != null && resultBox.isShowing()) resultBox.dismiss();
        } catch (Exception ignored) {
        }
        resultBox = null;
    }

    /**
     * v3：取到的文件先弹确认窗，只有点「立即发送」才发。
     * 倒计时结束 = 自动取消并 finish，绝不自动上传。
     */
    private void confirmThenSend(final Uri uri, final String name, final long size) {
        if (isFinishing() || confirming) return;
        confirming = true;
        final boolean[] settled = {false};

        confirmTimer = new CountDownTimer(CONFIRM_SECONDS * 1000L, 500) {
            @Override public void onTick(long left) {
                if (confirmBox != null && confirmBox.isShowing() && tvConfirmCountdown != null) {
                    tvConfirmCountdown.setText(((left + 999) / 1000) + " 秒后自动取消");
                }
            }
            @Override public void onFinish() {
                if (confirmBox != null && confirmBox.isShowing()) confirmBox.dismiss();
                confirmBox = null;
                tvConfirmCountdown = null;
                if (!settled[0]) {
                    Log.i(TAG, "确认窗超时，自动取消，不发送 " + name);
                    cancelConfirm(settled);
                }
            }
        };

        confirmBox = newDialog(R.layout.dialog_confirm);
        ((TextView) confirmBox.findViewById(R.id.tvConfirmName)).setText(name);
        ((TextView) confirmBox.findViewById(R.id.tvConfirmSize))
                .setText(size > 0 ? fmtSize(size) : "大小未知");
        tvConfirmCountdown = confirmBox.findViewById(R.id.tvConfirmCountdown);
        tvConfirmCountdown.setText(CONFIRM_SECONDS + " 秒后自动取消");
        ((Button) confirmBox.findViewById(R.id.btnSendNow)).setOnClickListener(v -> {
            confirmTimer.cancel(); settled[0] = true; confirming = false;
            dismissConfirmDialog();
            sendUriPayload(uri, name, size);
        });
        ((Button) confirmBox.findViewById(R.id.btnPickOther)).setOnClickListener(v -> {
            confirmTimer.cancel(); settled[0] = true; confirming = false;
            dismissConfirmDialog();
            launchPicker("请选择要传送的文件");
        });
        ((Button) confirmBox.findViewById(R.id.btnConfirmCancel))
                .setOnClickListener(v -> cancelConfirm(settled));
        // 返回键 = 取消并退出；v3 不再有「倒计时走完仍自动发送」的误发风险。
        confirmBox.setCancelable(true);
        confirmBox.setOnCancelListener(d -> {
            Log.i(TAG, "确认窗被返回键取消");
            cancelConfirm(settled);
        });
        confirmBox.show();
        confirmTimer.start();
    }

    /** 确认窗统一取消：停倒计时、复位标志、收框、结束本次碰标签。 */
    private void cancelConfirm(boolean[] settled) {
        if (settled[0]) return;
        settled[0] = true;
        confirming = false;
        try {
            if (confirmTimer != null) confirmTimer.cancel();
        } catch (Exception ignored) {
        }
        dismissConfirmDialog();
        toast("已取消");
        finish();
    }

    private void dismissConfirmDialog() {
        try {
            if (confirmBox != null && confirmBox.isShowing()) confirmBox.dismiss();
        } catch (Exception ignored) {
        }
        confirmBox = null;
        tvConfirmCountdown = null;
    }

    /** 统一的自绘弹窗：透明系统底板 + 布局里的圆角面板，宽度铺满、左右各留 24。 */
    private Dialog newDialog(int layoutRes) {
        Dialog d = new Dialog(this, R.style.Theme_NfcTapLink_Dialog);
        d.requestWindowFeature(Window.FEATURE_NO_TITLE);
        d.setContentView(layoutRes);
        Window w = d.getWindow();
        if (w != null) {
            w.setBackgroundDrawable(new ColorDrawable(Color.TRANSPARENT));
            w.addFlags(WindowManager.LayoutParams.FLAG_DIM_BEHIND);
            int width = getResources().getDisplayMetrics().widthPixels;
            int maxWidth = (int) (480 * getResources().getDisplayMetrics().density);
            if (width > maxWidth) width = maxWidth;
            WindowManager.LayoutParams lp = w.getAttributes();
            lp.width = width;
            lp.height = WindowManager.LayoutParams.WRAP_CONTENT;
            lp.dimAmount = 0.6f;
            w.setAttributes(lp);
            w.setLayout(width, WindowManager.LayoutParams.WRAP_CONTENT);
        }
        return d;
    }

    private static String fmtSize(long n) {
        if (n >= 1024L * 1024 * 1024)
            return String.format(java.util.Locale.CHINA, "%.2f GB", n / 1073741824.0);
        if (n >= 1024 * 1024)
            return String.format(java.util.Locale.CHINA, "%.1f MB", n / 1048576.0);
        if (n >= 1024)
            return String.format(java.util.Locale.CHINA, "%.1f KB", n / 1024.0);
        return n + " B";
    }

    /** 读电脑端 /api/ping 的 protocol；不是 nfctap/3 一律拒绝，防止降级到旧伪造服务。 */
    private static String serverProtocol(String host, int port) {
        HttpURLConnection c = null;
        try {
            c = (HttpURLConnection) new URL(
                    "http://" + host + ":" + port + "/api/ping").openConnection();
            c.setConnectTimeout(4000);
            c.setReadTimeout(4000);
            if (c.getResponseCode() != 200) return null;
            byte[] b = readAll(c.getInputStream());
            if (b == null) return null;
            return new JSONObject(new String(b, StandardCharsets.UTF_8))
                    .optString("protocol", null);
        } catch (Exception e) {
            Log.w(TAG, "读取电脑端协议失败: " + e.getMessage());
            return null;
        } finally {
            if (c != null) c.disconnect();
        }
    }

    /** 兼容路径：读「分享寄存」的私有缓存文件。 */
    private void sendPending(String pending, String name) {
        toast("已碰标签，正在传送寄存的文件…");
        io.execute(() -> {
            Payload pl = pendingPayload(pending, name);
            runOnUiThread(() -> {
                if (pl == null) {
                    toast("读不到寄存的文件，请重新选择");
                    launchPicker(null);
                } else {
                    sendPayload(pl);
                }
            });
        });
    }

    /** 系统照片选择器：API 33+ ACTION_PICK_IMAGES 无需任何存储权限。 */
    private void launchPicker(String msg) {
        mark("launchPicker 开始");
        if (msg != null) toast(msg);
        pickerLaunched = true;
        setStatus("正在连接电脑…", "选好文件后立即传送");
        // v5：从「只能选图片」改为「可选任意文件」。
        // ACTION_OPEN_DOCUMENT 是存储访问框架（SAF）的标准入口，本身不需要任何
        // 存储权限，选中的 URI 天然可读；覆盖面比 PICK_IMAGES 更广。
        try {
            Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
            i.addCategory(Intent.CATEGORY_OPENABLE);
            i.setType("*/*");
            startActivityForResult(i, REQ_PICK_FILE);
            mark("已调用 startActivityForResult(OPEN_DOCUMENT)");
        } catch (Exception e) {
            try {
                Intent i = new Intent(Intent.ACTION_GET_CONTENT);
                i.addCategory(Intent.CATEGORY_OPENABLE);
                i.setType("*/*");
                startActivityForResult(Intent.createChooser(i, "选择要传送的文件"),
                        REQ_PICK_FILE);
            } catch (Exception e2) {
                toast("无法打开文件选择界面：" + e2.getMessage());
                finish();
            }
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != REQ_PICK_FILE) return;
        pickerReturned = true;
        mark("onActivityResult 返回 resultCode=" + resultCode);
        if (outboxTakeover && resultCode != RESULT_OK) {
            // 是「电脑端有待发文件」主动收掉了选择器，接收流程已经在跑，
            // 这里既不能提示取消，也不能结束 Activity。
            Log.i(TAG, "选择器因接收流程接管而关闭，继续接收");
            return;
        }
        if (resultCode != RESULT_OK || data == null || data.getData() == null) {
            toast("已取消传送");
            finish();
            return;
        }
        flowCommittedToSend = true;
        Uri uri = data.getData();
        String name = queryDisplayName(uri);
        if (name == null || name.trim().isEmpty()) {
            name = "shared_file" + extFromMime(data.getType());
        }
        final String fName = name;
        // v6.2：预检大小（1 GB 上限），超过直接给可读提示，不再白读一遍再等服务端 413
        long size = querySize(uri);
        if (size > MAX_FILE_BYTES) {
            toast("文件超过 " + fmtSize(MAX_FILE_BYTES)
                    + " 上限（当前约 " + fmtSize(size) + "），已取消传送");
            finish();
            return;
        }
        toast("已选择「" + fName + "」，正在传送…");
        sendUriPayload(uri, fName, size);
    }

    /** 待发送文件来源：本地文件或 SAF URI，二者其一。 */
    private static final class Payload {
        final String name;
        final long size;
        final File file;
        final Uri uri;
        final boolean temp;
        Payload(String name, long size, File file, Uri uri, boolean temp) {
            this.name = name; this.size = size;
            this.file = file; this.uri = uri; this.temp = temp;
        }
    }

    /** 尺寸已知时直接发；未知（Provider 不报 SIZE）就先流式暂存拿到长度。 */
    private void sendUriPayload(final Uri uri, final String name, final long knownSize) {
        if (knownSize > 0 && knownSize <= MAX_FILE_BYTES) {
            sendPayload(new Payload(name, knownSize, null, uri, false));
            return;
        }
        showProgress(name);
        io.execute(() -> {
            File staged = stageUri(uri, name);
            if (staged == null) {
                runOnUiThread(() -> {
                    dismissProgress();
                    showResult(false, "读不到文件",
                            "文件可能已失效，或超过 " + fmtSize(MAX_FILE_BYTES) + " 上限。");
                });
                return;
            }
            runOnUiThread(() -> sendPayload(
                    new Payload(name, staged.length(), staged, null, true)));
        });
    }

    /** 统一的发送流程：发现电脑 → ping 粗筛 → challenge/pair 双向认证 → 加密上传。 */
    private void sendPayload(final Payload pl) {
        final String name = pl.name;
        Log.i(TAG, "准备发送 " + name + " / " + pl.size + " 字节");
        // v7：不再只用一闪而过的 Toast，改为「进度框 → 结果框」，
        // 让用户明确看到正在传、传成功/失败，而不是点完就回桌面不知结果。
        showProgress(name);
        io.execute(() -> {
            try {
                SharedPreferences p = prefs();
                String deviceId = p.getString(Prefs.KEY_DEVICE_ID, "");
                String code = p.getString(Prefs.KEY_CODE, "");
                String tagHost = p.getString(Prefs.KEY_TAG_HOST, "");
                String hint = p.getString(Prefs.KEY_TAG_HINT, "");
                int tagPort = p.getInt(Prefs.KEY_TAG_PORT, 8765);

                DiscoveryClient dc = new DiscoveryClient(TapActivity.this);
                DiscoveryClient.Endpoint ep =
                        dc.discover(deviceId, code, tagHost, tagPort, hint);
                if (ep == null) {
                    Log.w(TAG, "发现失败：缓存 / 引导候选 / BLE / UDP / 子网均未命中");
                    runOnUiThread(() -> showResult(false, "找不到电脑",
                            "请检查：\n"
                            + "· 电脑上的「一碰传」已启动，状态显示运行中\n"
                            + "· 手机与电脑连接同一局域网\n"
                            + "· 电脑防火墙已允许本程序访问\n\n"
                            + "文件名：" + name));
                    return;
                }
                Log.i(TAG, "✓ 发现电脑 " + ep);
                final String via = ep.via;
                runOnUiThread(() -> setProgress("已连上电脑（" + via + "）\n正在传送…"));
                final String fHost = ep.host;
                final int fPort = ep.port;
                p.edit().putString(Prefs.KEY_HOST, fHost)
                        .putInt(Prefs.KEY_PORT, fPort).apply();

                // v3：/api/ping 只做粗筛，protocol 必须 nfctap/3；
                // 真正身份由 /api/pair 的 server_proof 保证。
                String proto = serverProtocol(fHost, fPort);
                if (proto == null || !V3Crypto.PROTOCOL.equals(proto)) {
                    Log.w(TAG, "电脑端协议不是 nfctap/3，已中止上传");
                    runOnUiThread(() -> showResult(false, "电脑端协议不兼容",
                            "需要 v3 接收端（nfctap/3）。\n\n请升级电脑端后再试。"));
                    return;
                }

                // k 只用于本地 HMAC；challenge/pair 双向认证，server_proof 不过就抛异常。
                String token = getToken(p, fHost, fPort, code, deviceId);
                UploadResult r = upload(p, fHost, fPort, token, pl);
                if (!r.ok && r.authFail) {
                    // 服务端重启 / 密钥轮换 / 跨主机残留会话：清掉后重新挑战应答一次。
                    Log.w(TAG, "会话被服务端拒绝，重新配对一次后重试上传");
                    String token2 = getToken(p, fHost, fPort, code, deviceId);
                    r = upload(p, fHost, fPort, token2, pl);
                }
                final UploadResult fr = r;
                runOnUiThread(() -> {
                    if (fr.ok) {
                        p.edit().remove(Prefs.KEY_PENDING_URI)
                                .remove(Prefs.KEY_PENDING_NAME).apply();
                        if (fr.duplicate) {
                            Log.i(TAG, "电脑里已有这个文件，已跳过重复保存：" + name);
                            showResult(true, "电脑里已有这个文件",
                                    name + "\n" + fmtSize(pl.size)
                                    + "\n\n内容相同，已跳过重复保存。\n"
                                    + "文件：" + fr.file);
                        } else {
                            Log.i(TAG, "✓ 已传送：" + name);
                            showResult(true, "已发送到电脑",
                                    name + "\n" + fmtSize(fr.bytes)
                                    + "\n\n已保存到电脑的 received 目录\n"
                                    + "文件：" + fr.file + "\n"
                                    + "sha256：" + fr.sha256 + "\n"
                                    + "类型：" + fr.mime);
                        }
                    } else {
                        Log.w(TAG, "传送失败：" + fr.error);
                        showResult(false, "传送失败", fr.error);
                    }
                    maybeOfferLatePending();
                });
            } catch (Exception e) {
                Log.e(TAG, "上传流程异常", e);
                runOnUiThread(() -> {
                    showResult(false, "传送异常",
                            e.getMessage() == null ? "未知错误" : e.getMessage());
                    maybeOfferLatePending();
                });
            } finally {
                // 为发送临时暂存的文件用完即删
                if (pl.temp && pl.file != null) {
                    try {
                        pl.file.delete();
                    } catch (Exception ignored) {
                    }
                }
            }
        });
    }

    private InputStream openPayload(Payload pl) throws Exception {
        return pl.file != null ? new java.io.FileInputStream(pl.file)
                : getContentResolver().openInputStream(pl.uri);
    }

    /** 寄存文件 -> Payload；content:// 若拿不到尺寸，先流式暂存。 */
    private Payload pendingPayload(String raw, String name) {
        try {
            if (raw.startsWith("cache://")) {
                File f = getFileStreamPath(raw.substring("cache://".length()));
                if (!f.isFile() || f.length() == 0) return null;
                return new Payload(name, f.length(), f, null, false);
            }
            Uri uri = Uri.parse(raw);
            long size = querySize(uri);
            if (size > MAX_FILE_BYTES) return null;
            if (size > 0) return new Payload(name, size, null, uri, false);
            File staged = stageUri(uri, name);
            return staged == null ? null
                    : new Payload(name, staged.length(), staged, null, true);
        } catch (Exception e) {
            Log.e(TAG, "读寄存文件失败", e);
            return null;
        }
    }

    /** 把 content:// 流式复制到私有缓存，用于尺寸未知或需要多次读取的来源。 */
    private File stageUri(Uri uri, String displayName) {
        File out = null;
        try (InputStream in = getContentResolver().openInputStream(uri)) {
            if (in == null) return null;
            String safe = displayName == null ? "file.bin"
                    : displayName.replace('/', '_').replace('\\', '_');
            out = new File(getCacheDir(), "out_" + System.currentTimeMillis() + "_" + safe);
            try (OutputStream os = new FileOutputStream(out)) {
                copyLimited(in, os, MAX_FILE_BYTES);
            }
            if (out.length() == 0) {
                out.delete();
                return null;
            }
            return out;
        } catch (Exception e) {
            Log.w(TAG, "暂存文件失败：" + e.getMessage());
            if (out != null) out.delete();
            return null;
        }
    }

    /** 流式复制并守住上限；超限直接抛，不整体进内存。 */
    private static long copyLimited(InputStream in, OutputStream out, long limit)
            throws Exception {
        byte[] buf = new byte[64 * 1024];
        long total = 0;
        int n;
        while ((n = in.read(buf)) != -1) {
            total += n;
            if (total > limit) {
                throw new java.io.IOException(
                        "文件超过 " + fmtSize(limit) + " 上限，已取消");
            }
            out.write(buf, 0, n);
        }
        return total;
    }

    /**
     * 6.2.2（H1）：配对 URI 只允许来自真实 NFC 标签。
     * 显式 Intent / 自定义 scheme 伪造不出可连接的 Tag 句柄，
     * Ndef.connect() 会失败，因此在这里被拒绝。
     */
    private String extractPairUri(Intent intent) {
        if (intent == null || !NfcAdapter.ACTION_NDEF_DISCOVERED.equals(intent.getAction())) {
            Log.w(TAG, "拒绝非 NDEF_DISCOVERED 的配对请求");
            return null;
        }
        Tag tag = getTagExtra(intent);
        if (tag == null) {
            // 6.2.2 起拒绝无 EXTRA_TAG 的显式 Intent 注入；但 debug 包里的
            // SelfTestActivity 需要用 EXTRA_NDEF_MESSAGES 复现「系统 NFC 分发」这条链路
            // （adb shell am 无法注入 Parcelable 形式的 Tag）。这里只放行
            // 「debug 构建 + 显式 selftest 标记」的自检入口，发布版不是 debuggable，
            // 该分支永远不生效。
            if (intent.getBooleanExtra("selftest", false)
                    && (getApplicationInfo().flags
                        & android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
                NdefMessage[] msgs = getNdefMessages(intent);
                if (msgs != null) {
                    for (NdefMessage m : msgs) {
                        String uri = uriFromMessage(m);
                        if (uri != null) return uri;
                    }
                }
            }
            Log.w(TAG, "拒绝无 EXTRA_TAG 的配对请求（显式 Intent 注入）");
            return null;
        }
        Ndef ndef = Ndef.get(tag);
        if (ndef == null) {
            Log.w(TAG, "标签未枚举 NDEF 技术，忽略");
            return null;
        }
        NdefMessage cached = null;
        boolean tagConnectOk = true;
        try {
            ndef.connect();
            cached = ndef.getCachedNdefMessage();
        } catch (Exception e) {
            // 真标签也会在部分 ROM / NFC 状态下抛 SecurityException（例如系统 NFC
            // 服务刚持有过该 Tag 句柄、或 NFC 会话竞争），此时不能直接判定「伪造
            // 标签」而把整条链路掐死——6.2.x 真机回归就是这里退化成了「标签里
            // 没有 nfctap:// 配对信息」。改记日志后继续走「系统解析结果」兜底，
            // 只有兜底也拿不到 URI 时才算真的没配对信息。
            Log.w(TAG, "Tag.connect 失败，退回系统解析结果：" + e.getClass().getSimpleName());
            tagConnectOk = false;
        } finally {
            try { ndef.close(); } catch (Exception ignored) { }
        }
        if (tagConnectOk && cached != null) {
            String uri = uriFromMessage(cached);
            if (uri != null) return uri;
        }
        // 已确认 Tag 可连接后，才允许用系统解析结果兜底（部分 ROM 不填 EXTRA_NDEF_MESSAGES）。
        String data = intent.getDataString();
        if (data != null && data.startsWith("nfctap://")) return data;
        NdefMessage[] msgs = getNdefMessages(intent);
        if (msgs != null) {
            for (NdefMessage m : msgs) {
                String uri = uriFromMessage(m);
                if (uri != null) return uri;
            }
        }
        return null;
    }

    private static Tag getTagExtra(Intent intent) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            return intent.getParcelableExtra(NfcAdapter.EXTRA_TAG, Tag.class);
        }
        return intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
    }

    /** 从 NDEF 消息里找到第一条 nfctap:// URI 记录并还原完整 URI。 */
    private static String uriFromMessage(NdefMessage m) {
        if (m == null) return null;
        for (NdefRecord rec : m.getRecords()) {
            byte[] pb = rec.getPayload();
            if (pb.length == 0) continue;
            int code = pb[0] & 0xFF;
            String prefix;
            switch (code) {
                case 0x01: prefix = "http://www."; break;
                case 0x02: prefix = "https://www."; break;
                case 0x03: prefix = "http://"; break;
                case 0x04: prefix = "https://"; break;
                default:   prefix = ""; break;
            }
            // NDEF URI 记录（RTD_URI）的 payload[0] 恒为 URI 前缀码，
            // 0x00 表示「无缩写」，此时也必须跳过这一字节。
            int start = 1;
            String text = new String(pb, start, pb.length - start, StandardCharsets.UTF_8);
            String full = prefix + text;
            if (full.startsWith("nfctap://")) return full;
        }
        return null;
    }

    @SuppressWarnings("deprecation")
    private NdefMessage[] getNdefMessages(Intent intent) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            return intent.getParcelableArrayExtra(
                    NfcAdapter.EXTRA_NDEF_MESSAGES, NdefMessage.class);
        }
        Parcelable[] raw = intent.getParcelableArrayExtra(NfcAdapter.EXTRA_NDEF_MESSAGES);
        if (raw == null) return null;
        NdefMessage[] out = new NdefMessage[raw.length];
        for (int i = 0; i < raw.length; i++) out[i] = (NdefMessage) raw[i];
        return out;
    }

    private SharedPreferences prefs() {
        return getSharedPreferences(Prefs.PREF, Context.MODE_PRIVATE);
    }

    /** 读小响应（JSON / ping）。文件传输一律流式，不走这里。 */
    private static byte[] readAll(InputStream is) throws Exception {
        if (is == null) return null;
        try (InputStream in = is) {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            long total = 0;
            while ((n = in.read(buf)) != -1) {
                total += n;
                if (total > MAX_RESPONSE_BYTES) {
                    throw new java.io.IOException("响应体过大");
                }
                bos.write(buf, 0, n);
            }
            return bos.toByteArray();
        }
    }

    /**
     * v5.4 A8：读取前先问 ContentProvider 文件多大，超过服务端上限就直接
     * 提示，不必白读一遍。OpenableColumns.SIZE 可能为 null / -1（部分 Provider
     * 不提供），此时返回 -1，交给 readAll 的硬闸兜底。
     */
    private long querySize(Uri uri) {
        if (uri == null || !ContentResolver.SCHEME_CONTENT.equals(uri.getScheme())) return -1;
        try (Cursor c = getContentResolver().query(
                uri, new String[]{OpenableColumns.SIZE}, null, null, null)) {
            if (c != null && c.moveToFirst()) {
                int idx = c.getColumnIndex(OpenableColumns.SIZE);
                if (idx >= 0 && !c.isNull(idx)) return c.getLong(idx);
            }
        } catch (Exception e) {
            Log.w(TAG, "querySize 失败: " + e.getMessage());
        }
        return -1;
    }

    /** mime -> 扩展名，只覆盖最常见几种，用于「没有显示名」时兜底命名。 */
    private static String extFromMime(String mime) {
        if (mime == null) return "";
        String m = mime.toLowerCase(java.util.Locale.ROOT);
        if (m.equals("image/jpeg")) return ".jpg";
        if (m.equals("image/png")) return ".png";
        if (m.equals("image/webp")) return ".webp";
        if (m.equals("image/gif")) return ".gif";
        if (m.equals("application/pdf")) return ".pdf";
        if (m.equals("video/mp4")) return ".mp4";
        if (m.equals("audio/mpeg")) return ".mp3";
        if (m.equals("text/plain")) return ".txt";
        return "";
    }

    // ---- HTTP：与电脑端 receiver.py 的 nfctap/3 协议对应 ----
    /**
     * v3 双向配对：GET /api/challenge -> POST /api/pair -> 校验 server_proof。
     * 会话保存 token / exp / sn / cn；token 过期或服务端拒绝时重新 challenge/pair。
     * k 只在本地 HMAC 里用，绝不出现在 URL 或请求体。
     */
    private String getToken(SharedPreferences p, String host, int port,
                            String code, String deviceId) throws Exception {
        String cached = p.getString(Prefs.KEY_TOKEN, null);
        long exp = p.getLong(Prefs.KEY_TOKEN_EXP, 0L);
        String sn = p.getString(Prefs.KEY_SERVER_NONCE, "");
        String cn = p.getString(Prefs.KEY_CLIENT_NONCE, "");
        if (cached != null && !cached.trim().isEmpty()
                && exp > System.currentTimeMillis() / 1000 + 60
                && sn != null && !sn.isEmpty() && cn != null && !cn.isEmpty()
                && (host + ":" + port + ":" + deviceId).equals(
                        p.getString(Prefs.KEY_TOKEN_BINDING, ""))) {
            return cached;
        }

        byte[] k = V3Crypto.keyBytes(code);
        String did = V3Crypto.deviceId(code);
        if (deviceId != null && !deviceId.trim().isEmpty()
                && !deviceId.trim().equalsIgnoreCase(did)) {
            throw new IllegalStateException("设备 ID 与配对密钥不匹配");
        }

        HttpResult challenge = httpGet("http://" + host + ":" + port + "/api/challenge");
        JSONObject c = new JSONObject(challenge.body);
        if (challenge.status != 200 || !c.optBoolean("ok")) {
            throw new IllegalStateException(c.optString("error", "取 challenge 失败 HTTP " + challenge.status));
        }
        if (!V3Crypto.PROTOCOL.equals(c.optString("protocol"))
                || !V3Crypto.VERSION.equals(c.optString("version"))
                || !did.equals(c.optString("device_id"))) {
            throw new IllegalStateException("电脑端协议 / 版本 / 设备 ID 不匹配，已中止配对");
        }
        String serverNonce = c.optString("server_nonce", "");
        if (serverNonce.isEmpty()) throw new IllegalStateException("challenge 缺少 server_nonce");

        String clientNonce = V3Crypto.randomHex16();
        String proof = V3Crypto.hmacUtf8Hex(k,
                "client|" + serverNonce + "|" + clientNonce + "|" + did);

        JSONObject req = new JSONObject();
        req.put("server_nonce", serverNonce);
        req.put("client_nonce", clientNonce);
        req.put("device_id", did);
        req.put("proof", proof);
        HttpResult paired = httpPostJson("http://" + host + ":" + port + "/api/pair",
                req.toString());
        JSONObject j = new JSONObject(paired.body);
        if (paired.status != 200 || !j.optBoolean("ok")) {
            throw new IllegalStateException(j.optString("error", "配对失败 HTTP " + paired.status));
        }
        String token = j.getString("token");
        String want = V3Crypto.hmacUtf8Hex(k,
                "server|" + serverNonce + "|" + clientNonce + "|" + token);
        String got = j.optString("server_proof", "");
        if (!V3Crypto.constantTimeEquals(
                want.getBytes(StandardCharsets.UTF_8), got.getBytes(StandardCharsets.UTF_8))) {
            throw new IllegalStateException("服务端身份证明不匹配，拒绝连接");
        }

        long ttl = j.optLong("expires_in", 600L);
        p.edit().putString(Prefs.KEY_TOKEN, token)
                .putLong(Prefs.KEY_TOKEN_EXP, System.currentTimeMillis() / 1000 + ttl)
                .putString(Prefs.KEY_SERVER_NONCE, serverNonce)
                .putString(Prefs.KEY_CLIENT_NONCE, clientNonce)
                .putString(Prefs.KEY_TOKEN_BINDING, host + ":" + port + ":" + deviceId)
                .commit();
        return token;
    }

    /** token 过期 / 服务端拒绝（401）时清会话，下次碰标签重新 challenge/pair。 */
    private void clearSession(SharedPreferences p) {
        p.edit().remove(Prefs.KEY_TOKEN)
                .remove(Prefs.KEY_TOKEN_EXP)
                .remove(Prefs.KEY_SERVER_NONCE)
                .remove(Prefs.KEY_CLIENT_NONCE)
                .remove(Prefs.KEY_TOKEN_BINDING)
                .apply();
    }

    private static class UploadResult {
        final boolean ok, duplicate, authFail;
        final String file, sha256, mime, error;
        final long bytes;
        UploadResult(boolean ok, boolean duplicate, boolean authFail, String file,
                     String sha256, String mime, long bytes, String error) {
            this.ok = ok; this.duplicate = duplicate; this.authFail = authFail;
            this.file = file; this.sha256 = sha256; this.mime = mime;
            this.bytes = bytes; this.error = error;
        }
        static UploadResult fail(String error) {
            return new UploadResult(false, false, false, "", "", "", 0, error);
        }
        static UploadResult authError(String error) {
            return new UploadResult(false, false, true, "", "", "", 0, error);
        }
    }

    /** 文件名截到 255 个 UTF-8 字节以内，且不截断半个字符。 */
    private static String trimName(String name) {
        byte[] b = name.getBytes(StandardCharsets.UTF_8);
        if (b.length <= 255) return name;
        int cut = 255;
        while (cut > 0 && (b[cut] & 0xC0) == 0x80) cut--;
        return new String(b, 0, cut, StandardCharsets.UTF_8);
    }

    /**
     * v3：NT3 加密载荷 + Bearer / X-Nonce / X-Ts，Content-Type 固定 octet-stream。
     * v6.2：两遍流式——第一遍算 tag，第二遍把密文按 1 MB 块写进 socket。
     */
    private UploadResult upload(SharedPreferences p, String host, int port, String token,
                                Payload pl) {
        HttpURLConnection conn = null;
        try {
            String code = p.getString(Prefs.KEY_CODE, "");
            String sn = p.getString(Prefs.KEY_SERVER_NONCE, "");
            String cn = p.getString(Prefs.KEY_CLIENT_NONCE, "");
            String name = trimName(pl.name);
            if (name.isEmpty()) return UploadResult.fail("文件名为空");
            if (pl.size <= 0) return UploadResult.fail("空文件无法发送");
            if (pl.size > MAX_FILE_BYTES) {
                return UploadResult.fail("文件超过 " + fmtSize(MAX_FILE_BYTES) + " 上限");
            }

            long ts = System.currentTimeMillis() / 1000;
            String nonce = V3Crypto.randomHex12();
            V3Crypto.Outbound out;
            try (InputStream in = openPayload(pl)) {
                if (in == null) return UploadResult.fail("读不到要发送的文件");
                out = V3Crypto.prepareUpload(code, sn, cn, token, ts, nonce,
                        name, pl.size, in);
            }
            long bodyLen = out.header.length + out.plainLen;

            URL url = new URL("http://" + host + ":" + port + "/api/upload");
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setUseCaches(false);
            conn.setConnectTimeout(8000);
            // 1 GB 上行期间 socket 持续有数据；响应前服务端要校验 1 GB 密文并落盘
            conn.setReadTimeout(300000);
            conn.setRequestProperty("Authorization", "Bearer " + token);
            conn.setRequestProperty("X-Nonce", nonce);
            conn.setRequestProperty("X-Ts", String.valueOf(ts));
            conn.setRequestProperty("Content-Type", "application/octet-stream");
            conn.setFixedLengthStreamingMode(bodyLen);
            try (OutputStream os = conn.getOutputStream()) {
                os.write(out.header);
                try (InputStream in = openPayload(pl)) {
                    if (in == null) return UploadResult.fail("读不到要发送的文件");
                    out.writeCipher(in, os);
                }
                os.flush();
            }
            int status = conn.getResponseCode();
            String text = readResponse(conn, status);
            JSONObject j = new JSONObject(text);
            if (status == 200 && j.optBoolean("ok")) {
                return new UploadResult(true, j.optBoolean("duplicate"), false,
                        j.optString("file"), j.optString("sha256"),
                        j.optString("mime"), j.optLong("bytes"), "");
            }
            if (status == 401 || status == 403) {
                clearSession(p);
                return UploadResult.authError(j.optString("error", "会话失效 HTTP " + status));
            }
            if (status == 413) {
                return UploadResult.fail("文件超过电脑端上限：" + j.optString("error", ""));
            }
            return UploadResult.fail(j.optString("error", "HTTP " + status));
        } catch (Exception e) {
            return UploadResult.fail(e.getMessage() == null ? "网络异常" : e.getMessage());
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    private static class HttpResult {
        final int status;
        final String body;
        HttpResult(int status, String body) { this.status = status; this.body = body; }
    }

    private HttpResult httpGet(String urlStr) throws Exception {
        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) new URL(urlStr).openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(8000);
            conn.setReadTimeout(10000);
            int status = conn.getResponseCode();
            return new HttpResult(status, readResponse(conn, status));
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    private HttpResult httpPostJson(String urlStr, String json) throws Exception {
        HttpURLConnection conn = null;
        try {
            byte[] body = json.getBytes(StandardCharsets.UTF_8);
            conn = (HttpURLConnection) new URL(urlStr).openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setUseCaches(false);
            conn.setConnectTimeout(8000);
            conn.setReadTimeout(10000);
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Content-Length", String.valueOf(body.length));
            conn.setFixedLengthStreamingMode(body.length);
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body);
                os.flush();
            }
            int status = conn.getResponseCode();
            return new HttpResult(status, readResponse(conn, status));
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    private static String readResponse(HttpURLConnection conn, int status) {
        try {
            InputStream is = (status >= 200 && status <= 299) ? conn.getInputStream() : conn.getErrorStream();
            if (is == null) return "{}";
            byte[] b = readAll(is);
            return b == null ? "{}" : new String(b, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "{}";
        }
    }

    private void toast(String msg) {
        Toast.makeText(this, msg, Toast.LENGTH_LONG).show();
        Log.i(TAG, msg);
    }

    @Override
    protected void onDestroy() {
        try {
            if (confirmTimer != null) confirmTimer.cancel();
            if (confirmBox != null && confirmBox.isShowing()) confirmBox.dismiss();
            dismissProgress();
            dismissResult();
        } catch (Exception ignored) {
        }
        super.onDestroy();
        io.shutdownNow();
    }
}
