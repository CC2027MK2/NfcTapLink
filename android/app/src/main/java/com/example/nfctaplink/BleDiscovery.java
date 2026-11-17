/*
 * NfcTapLink · BLE 广播发现（手机端，第 3 级发现）
 *
 * 为什么需要：UDP 组播/广播不跨 /24（真机实测电脑侧收到查询 0 条），
 * 但 BLE 广播不依赖 IP 网络。电脑端 ble_announcer.py 用 WinRT
 * BluetoothLEAdvertisementPublisher 发 ManufacturerData，手机扫描后
 * 直接拿到「设备 ID + 当前 IP:端口」，随后仍走局域网 HTTP 传图。
 *
 * 载荷（ManufacturerData，CompanyId 0xFFFE，24 B）：
 *   0-1   b"NT"
 *   2-9   device_id（8 B = 标签里 16 hex 的完整值）
 *   10-13 IPv4 4 B
 *   14-15 port 2 B 大端
 *   16-19 ts 4 B 小端 unix 秒
 *   20-23 reserved 4 B（v3 起全 0，不再放签名）
 *
 * v3 广播无签名，只作候选地址提示；真正身份由 /api/pair 的 server_proof 保证。
 *
 * 权限（Manifest）：Android 12+ BLUETOOTH_SCAN(neverForLocation) /
 * BLUETOOTH_CONNECT；Android 11 及以下 BLUETOOTH / BLUETOOTH_ADMIN +
 * ACCESS_FINE_LOCATION，并要求定位开关打开。
 */
package com.example.nfctaplink;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothManager;
import android.bluetooth.le.BluetoothLeScanner;
import android.bluetooth.le.ScanCallback;
import android.bluetooth.le.ScanRecord;
import android.bluetooth.le.ScanResult;
import android.bluetooth.le.ScanSettings;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.util.Log;
import android.util.SparseArray;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public class BleDiscovery {

    private static final String TAG = "NfcTapLinkBle";
    public static final int COMPANY_ID = 0xFFFE;
    private static final int PAYLOAD_LEN = 24;
    private static final long MAX_AGE_S = 90;
    private static final int SCAN_MS = 3500;

    /** 与 DiscoveryClient.Endpoint 同构，避免两个发现模块互相依赖。 */
    public static class Hit {
        public final String ip;
        public final int port;
        Hit(String ip, int port) { this.ip = ip; this.port = port; }
        @Override public String toString() { return ip + ":" + port; }
    }

    private final Context ctx;

    public BleDiscovery(Context ctx) {
        this.ctx = ctx.getApplicationContext();
    }

    /** 阻塞扫描，最多 SCAN_MS 毫秒；命中第一个设备 ID 匹配的广播即返回。 */
    public Hit scan(String deviceId, String pairCode) {
        // 2026-11-13 真机教训：APK 升级安装后，系统会重置运行时权限，
        // BLUETOOTH_SCAN 变回 granted=false。此时 startScan 会静默无结果，
        // 日志里只有 BtGatt 的 "Skipping client"，极难定位。
        // 这里显式检查并给出可操作提示（打开一次主界面即可自动请求授权）。
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S
                && ctx.checkSelfPermission(android.Manifest.permission.BLUETOOTH_SCAN)
                        != PackageManager.PERMISSION_GRANTED) {
            Log.w(TAG, "缺少 BLUETOOTH_SCAN 运行时权限，跳过 BLE 发现；"
                    + "请打开一次「一碰传」主界面完成授权（升级安装后可能需重新授权）");
            return null;
        }
        BluetoothManager bm = (BluetoothManager) ctx.getSystemService(Context.BLUETOOTH_SERVICE);
        if (bm == null) { Log.w(TAG, "无 BluetoothManager"); return null; }
        BluetoothAdapter adapter = bm.getAdapter();
        if (adapter == null || !adapter.isEnabled()) {
            Log.w(TAG, "蓝牙未开启，跳过 BLE 发现");
            return null;
        }
        BluetoothLeScanner scanner = adapter.getBluetoothLeScanner();
        if (scanner == null) { Log.w(TAG, "无 BluetoothLeScanner"); return null; }

        final List<Hit> hits = new ArrayList<>();
        final int[] seen = {0};
        final CountDownLatch latch = new CountDownLatch(1);
        final ScanCallback cb = new ScanCallback() {
            @Override
            public void onScanResult(int callbackType, ScanResult result) {
                seen[0]++;
                try {
                    ScanRecord rec = result.getScanRecord();
                    if (rec == null) return;
                    SparseArray<byte[]> mds = rec.getManufacturerSpecificData();
                    byte[] data = mds == null ? null : mds.get(COMPANY_ID);
                    if (data == null) return;
                    Hit h = parse(data, deviceId);
                    if (h != null) {
                        synchronized (hits) {
                            if (hits.isEmpty()) hits.add(h);
                        }
                        Log.i(TAG, "✓ 命中 BLE 广播 " + h + " 来自 "
                                + result.getDevice().getAddress());
                        latch.countDown();
                    }
                } catch (Exception e) {
                    Log.w(TAG, "解析广播异常: " + e.getMessage());
                }
            }

            @Override
            public void onScanFailed(int errorCode) {
                Log.w(TAG, "BLE 扫描失败 errorCode=" + errorCode);
                latch.countDown();
            }
        };

        try {
            ScanSettings settings = new ScanSettings.Builder()
                    .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
                    .setReportDelay(0)
                    .build();
            // 不加 ScanFilter：部分 ROM 对 manufacturerData 过滤支持不一致，
            // 改为在回调里按 CompanyId + deviceId 自行过滤，兼容性更好。
            scanner.startScan(null, settings, cb);
            Log.i(TAG, "开始 BLE 扫描，等待 " + SCAN_MS + " ms，目标设备 ID=" + deviceId);
            latch.await(SCAN_MS, TimeUnit.MILLISECONDS);
        } catch (Exception e) {
            Log.w(TAG, "BLE 扫描异常: " + e.getMessage());
        } finally {
            try { scanner.stopScan(cb); } catch (Exception ignored) {}
        }
        synchronized (hits) {
            Log.i(TAG, "BLE 扫描结束：收到 " + seen[0] + " 条广播，设备 ID 匹配 " + hits.size() + " 条");
            return hits.isEmpty() ? null : hits.get(0);
        }
    }

    /** v3：载荷无签名；只校验 magic / 长度 / deviceId / 新鲜度。 */
    static Hit parse(byte[] d, String deviceId) {
        try {
            if (d == null || d.length != PAYLOAD_LEN) return null;
            if (d[0] != 'N' || d[1] != 'T') return null;

            StringBuilder id = new StringBuilder();
            for (int i = 2; i < 10; i++) id.append(String.format("%02x", d[i] & 0xff));
            if (deviceId != null && !deviceId.isEmpty()
                    && !deviceId.equalsIgnoreCase(id.toString())) return null;

            long ts = ((long) (d[16] & 0xff)) | (((long) (d[17] & 0xff)) << 8)
                    | (((long) (d[18] & 0xff)) << 16) | (((long) (d[19] & 0xff)) << 24);
            long now = System.currentTimeMillis() / 1000 & 0xFFFFFFFFL;
            if (now - ts > MAX_AGE_S) return null;

            String ip = (d[10] & 0xff) + "." + (d[11] & 0xff) + "."
                    + (d[12] & 0xff) + "." + (d[13] & 0xff);
            int port = ((d[14] & 0xff) << 8) | (d[15] & 0xff);
            if (port < 1 || port > 65535) return null;
            return new Hit(ip, port);
        } catch (Exception e) {
            return null;
        }
    }
}
