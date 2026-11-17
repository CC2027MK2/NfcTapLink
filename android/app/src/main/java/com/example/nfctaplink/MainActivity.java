/*
 * NfcTapLink · 主界面（Java 实现，等价翻译自 kotlin-src/MainActivity.kt）
 *
 * 三个作用：
 *  1. 手动配置电脑地址 / 端口 / 配对密钥（IP 变了不必重写 NFC 标签）；
 *  2. 显示状态：是否已配对、是否有寄存待发的文件（图片/文档/APK…）；
 *  3. 用手机给 NTAG 标签写入 v3 的 nfctap:// 配对 URI
 *     （d=sha256(hexToBytes(k))[:16] & k=64 hex 配对密钥）。
 *
 * 用平台 Activity 而非 AppCompatActivity，避免引入缓存里没有的 androidx 依赖。
 */
package com.example.nfctaplink;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.content.res.ColorStateList;
import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.Ndef;
import android.nfc.tech.NdefFormatable;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends Activity {

    private EditText etHost, etPort, etCode;
    private TextView tvStatus, tvHostValue, tvPairValue, tvDeviceValue, tvPendingValue, tvNfcWarn;
    private View dotState, dotPair, dotPending;
    private NfcAdapter adapter;
    private PendingIntent pendingIntent;
    private IntentFilter[] nfcFilters;
    private String[][] nfcTechLists;
    private boolean writing = false;
    private View panelSettings;
    private Button btnSettings;
    private final ExecutorService io = Executors.newSingleThreadExecutor();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        etHost = findViewById(R.id.etHost);
        etPort = findViewById(R.id.etPort);
        etCode = findViewById(R.id.etCode);
        tvStatus = findViewById(R.id.tvStatus);
        tvHostValue = findViewById(R.id.tvHostValue);
        tvPairValue = findViewById(R.id.tvPairValue);
        tvDeviceValue = findViewById(R.id.tvDeviceValue);
        tvPendingValue = findViewById(R.id.tvPendingValue);
        tvNfcWarn = findViewById(R.id.tvNfcWarn);
        dotState = findViewById(R.id.dotState);
        dotPair = findViewById(R.id.dotPair);
        dotPending = findViewById(R.id.dotPending);

        // 连接设置默认收起：主界面只留「当前状态」，点开才铺开详情与配置
        panelSettings = findViewById(R.id.panelSettings);
        btnSettings = findViewById(R.id.btnSettings);
        btnSettings.setOnClickListener(v -> {
            boolean show = panelSettings.getVisibility() != View.VISIBLE;
            panelSettings.setVisibility(show ? View.VISIBLE : View.GONE);
            btnSettings.setText(show ? "收起连接设置  ▴" : "连接设置  ▾");
        });

        // 首次打开 App 时一次性申请运行时权限（BLE 扫描 + 读相册）。
        // 放在主界面而非碰标签那一刻，避免权限弹窗打断「一碰即传」的短会话。
        java.util.List<String> need = new java.util.ArrayList<>();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            need.add(android.Manifest.permission.BLUETOOTH_SCAN);
            need.add(android.Manifest.permission.BLUETOOTH_CONNECT);
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            need.add(android.Manifest.permission.READ_MEDIA_IMAGES);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                need.add("android.permission.READ_MEDIA_VISUAL_USER_SELECTED");
            }
        } else {
            need.add(android.Manifest.permission.READ_EXTERNAL_STORAGE);
        }
        java.util.List<String> missing = new java.util.ArrayList<>();
        for (String perm : need) {
            if (checkSelfPermission(perm) != android.content.pm.PackageManager.PERMISSION_GRANTED)
                missing.add(perm);
        }
        if (!missing.isEmpty()) {
            requestPermissions(missing.toArray(new String[0]), 1001);
        }

        SharedPreferences p = prefs();
        etHost.setText(p.getString(Prefs.KEY_HOST, ""));
        etPort.setText(String.valueOf(p.getInt(Prefs.KEY_PORT, 8765)));
        etCode.setText(p.getString(Prefs.KEY_CODE, ""));

        ((Button) findViewById(R.id.btnSave)).setOnClickListener(v -> {
            String h = etHost.getText().toString().trim();
            String ps = etPort.getText().toString().trim();
            String k = etCode.getText().toString().trim();
            Integer port = parseIntOrNull(ps);
            if (port == null || port < 1 || port > 65535 || k.isEmpty()) {
                toast("端口 / 64 位配对密钥都要填");
                return;
            }
            String newDid;
            try {
                V3Crypto.keyBytes(k);
                newDid = V3Crypto.deviceId(k);
            } catch (Exception e) {
                toast("配对密钥必须是 64 位十六进制");
                return;
            }
            prefs().edit()
                    .putString(Prefs.KEY_HOST, h)
                    .putInt(Prefs.KEY_PORT, port)
                    .putString(Prefs.KEY_CODE, k)
                    // 手填新密钥等同于「明确换绑」：同步更新设备 ID 钉子，
                    // 否则下一次碰新标签会被防注入校验当成不匹配而拒绝。
                    .putString(Prefs.KEY_DEVICE_ID, newDid)
                    .remove(Prefs.KEY_TOKEN)
                    .remove(Prefs.KEY_TOKEN_EXP)
                    .remove(Prefs.KEY_SERVER_NONCE)
                    .remove(Prefs.KEY_CLIENT_NONCE)
                    .apply();
            toast("已保存，下次碰标签会用新地址");
            refresh();
        });

        ((Button) findViewById(R.id.btnWriteTag)).setOnClickListener(v -> {
            String k = p.getString(Prefs.KEY_CODE, etCode.getText().toString().trim());
            if (k == null || k.trim().isEmpty()) {
                toast("请先填入 64 位十六进制配对密钥，或先碰一次已写好的标签");
                return;
            }
            try {
                V3Crypto.keyBytes(k);
            } catch (Exception e) {
                toast("配对密钥必须是 64 位十六进制");
                return;
            }
            writing = true;
            toast("把 NFC 标签贴到手机背面（将写入 v3 无 IP 内容）…");
            refresh();
        });

        ((Button) findViewById(R.id.btnMode)).setOnClickListener(v -> {
            int m = prefs().getInt(Prefs.KEY_SEND_MODE, Prefs.MODE_PICKER);
            m = (m + 1) % 4;
            prefs().edit().putInt(Prefs.KEY_SEND_MODE, m).apply();
            toast("取文件模式已切换：" + modeLabel(m));
            refresh();
        });

        ((Button) findViewById(R.id.btnClearPending)).setOnClickListener(v -> {
            prefs().edit()
                    .remove(Prefs.KEY_PENDING_URI)
                    .remove(Prefs.KEY_PENDING_NAME)
                    .apply();
            toast("已清除寄存文件");
            refresh();
        });

        adapter = NfcAdapter.getDefaultAdapter(this);

        int flags = PendingIntent.FLAG_UPDATE_CURRENT;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            flags |= PendingIntent.FLAG_MUTABLE;
        }
        pendingIntent = PendingIntent.getActivity(
                this, 0,
                new Intent(this, getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
                flags);

        // 前台派发：App 在前台时由本进程直接收标签，系统不再弹「发现NFC卡片」确认。
        // 必须同时注册 NDEF_DISCOVERED，否则带 nfctap:// 的标签会被归到
        // 低优先级的 TAG_DISCOVERED，onNewIntent 里就分不出类型（旧版只注册了这个，
        // 结果是前台碰标签完全没有反应）。
        nfcFilters = new IntentFilter[]{
                new IntentFilter(NfcAdapter.ACTION_NDEF_DISCOVERED),
                new IntentFilter(NfcAdapter.ACTION_TECH_DISCOVERED),
                new IntentFilter(NfcAdapter.ACTION_TAG_DISCOVERED),
        };
        nfcTechLists = new String[][]{
                {android.nfc.tech.Ndef.class.getName()},
                {android.nfc.tech.NdefFormatable.class.getName()},
        };
        refresh();
    }

    private SharedPreferences prefs() {
        return getSharedPreferences(Prefs.PREF, Context.MODE_PRIVATE);
    }

    private void refresh() {
        SharedPreferences p = prefs();
        boolean hasToken = !p.getString(Prefs.KEY_TOKEN, "").isEmpty()
                && p.getLong(Prefs.KEY_TOKEN_EXP, 0) > System.currentTimeMillis() / 1000;
        String pending = p.getString(Prefs.KEY_PENDING_NAME, null);
        String host = p.getString(Prefs.KEY_HOST, "");
        int port = p.getInt(Prefs.KEY_PORT, 8765);
        String did = "";
        try {
            did = V3Crypto.deviceId(p.getString(Prefs.KEY_CODE, ""));
        } catch (Exception ignored) {
        }
        int mode = p.getInt(Prefs.KEY_SEND_MODE, Prefs.MODE_PICKER);

        // 顶部状态：色点 + 文字，NFC 不可用时另外给一行原因提示
        if (adapter == null) {
            setState("NFC 不可用", R.color.warning);
            tvNfcWarn.setText("这台手机没有 NFC 硬件，无法碰标签传送。");
            tvNfcWarn.setVisibility(View.VISIBLE);
        } else if (!adapter.isEnabled()) {
            setState("NFC 未开启", R.color.warning);
            tvNfcWarn.setText("NFC 未开启，请到系统设置中打开后再碰标签。");
            tvNfcWarn.setVisibility(View.VISIBLE);
        } else if (writing) {
            setState("等待贴标签写入…", R.color.warning);
            tvNfcWarn.setVisibility(View.GONE);
        } else {
            setState("待命", R.color.accent);
            tvNfcWarn.setVisibility(View.GONE);
        }

        tvHostValue.setText(host.isEmpty()
                ? "自动发现 · 端口 " + port
                : host + ":" + port);

        tvPairValue.setText(hasToken ? "已配对 · 会话有效" : "未配对或会话已过期");
        tvPairValue.setTextColor(getColor(hasToken ? R.color.text_primary : R.color.text_secondary));
        tintDot(dotPair, hasToken ? R.color.success : R.color.text_tertiary);

        if (did.isEmpty()) {
            tvDeviceValue.setText("未配置配对密钥");
            tvDeviceValue.setTextColor(getColor(R.color.text_tertiary));
        } else {
            tvDeviceValue.setText(did);
            tvDeviceValue.setTextColor(getColor(R.color.text_primary));
        }

        if (pending == null) {
            tvPendingValue.setText("暂无寄存文件");
            tvPendingValue.setTextColor(getColor(R.color.text_secondary));
            tintDot(dotPending, R.color.text_tertiary);
        } else {
            tvPendingValue.setText(pending);
            tvPendingValue.setTextColor(getColor(R.color.text_primary));
            tintDot(dotPending, R.color.accent);
        }

        ((Button) findViewById(R.id.btnMode)).setText("取文件模式：" + modeLabel(mode));
    }

    private void setState(String text, int colorRes) {
        tvStatus.setText(text);
        tintDot(dotState, colorRes);
    }

    private void tintDot(View dot, int colorRes) {
        dot.setBackgroundTintList(ColorStateList.valueOf(getColor(colorRes)));
    }

    private static String modeLabel(int mode) {
        switch (mode) {
            case Prefs.MODE_AUTO_ANY:   return "自动取最近图（不限时间）";
            case Prefs.MODE_PICKER:     return "每次碰标签选文件";
            case Prefs.MODE_LEGACY:     return "仅用分享寄存的文件（旧模式）";
            case Prefs.MODE_AUTO_RECENT:
            default:                    return "自动取最近图（30分钟内）";
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (adapter != null) {
            adapter.enableForegroundDispatch(this, pendingIntent, nfcFilters, nfcTechLists);
            Log.i("NfcTapLink", "前台派发已启用（NDEF/TECH/TAG 三种 action）");
        }
        refresh();
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (adapter != null) adapter.disableForegroundDispatch(this);
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        if (!writing) {
            // 非写卡状态下碰标签，交给 TapActivity 处理。
            // 三种 action 都要转：NDEF_DISCOVERED 有 URI 记录，
            // TECH/TAG_DISCOVERED 只有 Tag，需由 TapActivity 自己再读 NDEF。
            String action = intent.getAction();
            if (NfcAdapter.ACTION_NDEF_DISCOVERED.equals(action)
                    || NfcAdapter.ACTION_TECH_DISCOVERED.equals(action)
                    || NfcAdapter.ACTION_TAG_DISCOVERED.equals(action)) {
                Log.i("NfcTapLink", "前台派发收到标签 action=" + action + "，转交 TapActivity");
                Intent fwd = new Intent(this, TapActivity.class);
                fwd.setAction(action);
                if (intent.getExtras() != null) fwd.putExtras(intent.getExtras());
                if (intent.getData() != null) fwd.setData(intent.getData());
                startActivity(fwd);
            }
            return;
        }
        Tag tag = getTagExtra(intent);
        if (tag == null) return;

        final String uri = buildUri();
        final Tag t = tag;
        io.execute(() -> {
            WriteResult r = writeTag(t, uri);
            runOnUiThread(() -> {
                writing = false;
                toast(r.ok ? "✓ 标签写入成功" : "写入失败：" + r.msg);
                refresh();
            });
        });
    }

    private Tag getTagExtra(Intent intent) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            return intent.getParcelableExtra(NfcAdapter.EXTRA_TAG, Tag.class);
        }
        return intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
    }

    private String buildUri() {
        // v3：d = sha256(hexToBytes(k))[:16]，k = prefs 里的 64 hex 配对密钥。
        // 不读 config.json、不读 BuildConfig，也不从网络取 k / d。
        String k = prefs().getString(Prefs.KEY_CODE, etCode.getText().toString().trim());
        if (k == null) k = "";
        k = k.trim();
        try {
            V3Crypto.keyBytes(k);
            String d = V3Crypto.deviceId(k);
            return "nfctap://pair?d="
                    + java.net.URLEncoder.encode(d, "UTF-8")
                    + "&k=" + java.net.URLEncoder.encode(k, "UTF-8");
        } catch (Exception e) {
            return "nfctap://pair?d=&k=";
        }
    }

    private static class WriteResult {
        final boolean ok;
        final String msg;
        WriteResult(boolean ok, String msg) { this.ok = ok; this.msg = msg; }
    }

    private WriteResult writeTag(Tag tag, String uri) {
        NdefRecord rec = NdefRecord.createUri(uri);
        NdefMessage msg = new NdefMessage(new NdefRecord[]{rec});
        try {
            Ndef ndef = Ndef.get(tag);
            if (ndef != null) {
                ndef.connect();
                try {
                    if (!ndef.isWritable()) return new WriteResult(false, "标签只读");
                    byte[] raw = msg.toByteArray();
                    if (ndef.getMaxSize() < raw.length)
                        return new WriteResult(false, "标签容量不足（需要 " + raw.length + " 字节）");
                    ndef.writeNdefMessage(msg);
                    return new WriteResult(true, "ok");
                } finally {
                    ndef.close();
                }
            } else {
                NdefFormatable fmt = NdefFormatable.get(tag);
                if (fmt == null) return new WriteResult(false, "标签不支持 NDEF 格式化");
                fmt.connect();
                try {
                    fmt.format(msg);
                    return new WriteResult(true, "ok");
                } finally {
                    fmt.close();
                }
            }
        } catch (Exception e) {
            return new WriteResult(false, e.getMessage() == null ? "IO 异常" : e.getMessage());
        }
    }

    private static Integer parseIntOrNull(String s) {
        try { return Integer.parseInt(s); } catch (NumberFormatException e) { return null; }
    }

    private void toast(String s) {
        Toast.makeText(this, s, Toast.LENGTH_LONG).show();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        io.shutdownNow();
    }
}
