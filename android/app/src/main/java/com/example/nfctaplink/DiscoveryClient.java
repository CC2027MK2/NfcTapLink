/*
 * NfcTapLink · v2 自动发现客户端（Java 实现，零第三方依赖）
 *
 * 为什么需要它：v1 把电脑 IP 写死在 NFC 标签里，换 Wi-Fi / 换网段就失效。
 * 实测：标签里写死 IP（如 192.168.1.10）后，换 Wi-Fi / 换网段即失效，
 * 固定 IP 方案已完全不可用。
 *
 * 借鉴（一手规范，见设计说明 S19–S22）：
 *   - LocalSend protocol v2.2：UDP 组播 224.0.0.167:53317 发 JSON 查询，
 *     对方单播应答；组播被禁时用子网扫描（legacy）兜底。
 *   - Syncthing Local Discovery v4：链路定向广播 + 周期公告，地址随报文携带。
 *   - KDE Connect / croc：缓存「上次已知地址」加速重连，本地直连优先。
 *
 * 三级发现（都在「碰标签」这一次前台会话里完成，不常驻后台）：
 *   1. 缓存地址：上次成功的 host:port，先发 /api/ping 快探（约 100 ms）
 *   2. UDP 发现：MulticastLock + 组播/定向广播查询，收无签名公告 → 拿候选 IPs
 *   3. 子网扫描：本机 wlan0 的 /24 并发探 /api/ping（legacy 兜底）
 * 三者都失败才返回 null；任一命中都会缓存为下次的首选地址。
 *
 * 安全：v3 公告**没有签名**，不证明电脑身份，只是候选地址提示。
 * 真正身份由 /api/pair 的 server_proof 保证；/api/ping 额外拒绝非 nfctap/3 服务。
 */
package com.example.nfctaplink;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.wifi.WifiManager;
import android.os.SystemClock;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.HttpURLConnection;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.MulticastSocket;
import java.net.NetworkInterface;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

public class DiscoveryClient {

    private static final String TAG = "NfcTapLinkDisc";
    private static final String MCAST_GRP = "224.0.0.167";
    private static final int MCAST_PORT = 53317;
    private static final int PROTO_V = 3;
    private static final long MAX_AGE_S = 30;
    private static final int UDP_WAIT_MS = 2200;
    private static final int PING_TIMEOUT_MS = 350;

    /** 发现结果：地址 + 端口 + 命中途径（用于日志 / UI，便于排障）。 */
    public static class Endpoint {
        public final String host;
        public final int port;
        public final String via;
        Endpoint(String host, int port, String via) {
            this.host = host; this.port = port; this.via = via;
        }
        @Override public String toString() { return host + ":" + port + " via " + via; }
    }

    private final Context ctx;
    private final SharedPreferences prefs;

    public DiscoveryClient(Context ctx) {
        this.ctx = ctx.getApplicationContext();
        this.prefs = this.ctx.getSharedPreferences(Prefs.PREF, Context.MODE_PRIVATE);
    }

    /**
     * 找到标签指定的那台电脑。若标签自带 h/p（v1 兼容），直接返回该地址。
     * 否则走三级自动发现。全程阻塞调用，必须在后台线程执行。
     */
    public Endpoint discover(String deviceId, String pairCode,
                             String tagHost, int tagPort, String bootstrapCsv) {
        // pairCode 仅为兼容旧调用签名保留；v3 发现层不再用 k 验签。
        long t0 = SystemClock.elapsedRealtime();
        String tagHostS = tagHost == null ? "" : tagHost.trim();
        String hintS = bootstrapCsv == null ? "" : bootstrapCsv.trim();
        stage("cfg", "开始发现：deviceId=%s tagHost=%s tagPort=%d hint=%s",
                mask(deviceId), tagHostS.isEmpty() ? "(无)" : tagHostS,
                tagPort, hintS.isEmpty() ? "(无)" : hintS);
        if (deviceId == null || deviceId.isEmpty()) {
            Log.w(TAG, "[warn] deviceId 为空：/api/ping 的 device_id 校验必然失败，"
                    + "任何候选都不会命中（检查标签里的 k 是否被正确解析）");
        }

        // ---- v1 兼容：标签里写了 IP 就直接用，但要 ping 一下确认协议与设备 ID ----
        if (!tagHostS.isEmpty()) {
            Endpoint e = new Endpoint(tagHostS, tagPort, "tag-v1");
            long s = SystemClock.elapsedRealtime();
            String why = pingWhy(e, deviceId);
            if (why == null) {
                stage("tag-v1", "✓ 命中 %s:%d（%d ms）", e.host, e.port, ms(s));
                save(e);
                return e;
            }
            stage("tag-v1", "✗ %s:%d 失败：%s（%d ms），转入自动发现",
                    e.host, e.port, why, ms(s));
        } else {
            stage("tag-v1", "跳过：标签里没有 h= 写死地址（v2/v3 标签的正常形态）");
        }

        // ---- 1 缓存地址（KDE Connect / croc 的「上次已知地址」思路）----
        String cached = prefs.getString(Prefs.KEY_LAST_ENDPOINT, null);
        if (cached != null && cached.contains(":")) {
            try {
                String[] parts = cached.split(":", 2);
                Endpoint e = new Endpoint(parts[0], Integer.parseInt(parts[1]), "cached");
                long s = SystemClock.elapsedRealtime();
                String why = pingWhy(e, deviceId);
                if (why == null) {
                    stage("cached", "✓ 命中 %s:%d（%d ms）", e.host, e.port, ms(s));
                    save(e);
                    return e;
                }
                stage("cached", "✗ %s:%d 失败：%s（%d ms）", e.host, e.port, why, ms(s));
            } catch (NumberFormatException ex) {
                stage("cached", "✗ 缓存地址格式非法，已忽略：%s", cached);
            }
        } else {
            stage("cached", "跳过：没有上次成功地址");
        }

        // ---- 2 标签里的引导候选（可选 c=，仅加速，不是唯一依据）----
        List<Endpoint> boot = new ArrayList<>();
        if (!hintS.isEmpty()) {
            for (String s : hintS.split(",")) {
                String ip = s.trim();
                if (ip.matches("^\\d{1,3}(\\.\\d{1,3}){3}$")) {
                    boot.add(new Endpoint(ip, tagPort > 0 ? tagPort : 8765, "tag-hint"));
                }
            }
            Endpoint hit = tryFirst(boot, deviceId, "tag-hint");
            if (hit != null) { save(hit); return hit; }
            stage("tag-hint", "全部失效，转入 BLE/UDP 发现（标签无需重写）");
        } else {
            stage("tag-hint", "跳过：标签里没有 c= 引导候选");
        }

        // ---- 3 BLE 广播发现（不依赖 IP 网络，可跨 /24 与 AP 隔离）----
        // 放在 UDP 之前：真机实测组播不跨网段，BLE 反而是最可能命中的零配置通道。
        long sBle = SystemClock.elapsedRealtime();
        try {
            BleDiscovery.Hit bh = new BleDiscovery(ctx).scan(deviceId, pairCode);
            if (bh == null) {
                stage("ble", "✗ 未收到匹配广播（耗时 %d ms）", ms(sBle));
            } else {
                Endpoint e = new Endpoint(bh.ip, bh.port, "ble");
                String why = pingWhy(e, deviceId);
                if (why == null) {
                    stage("ble", "✓ 广播地址复核通过 %s:%d（%d ms）", e.host, e.port, ms(sBle));
                    save(e);
                    return e;
                }
                stage("ble", "✗ 广播地址 %s:%d 不可用：%s（%d ms）", e.host, e.port, why, ms(sBle));
            }
        } catch (Exception e) {
            stage("ble", "✗ 异常：%s", e);
        }

        // ---- 4 UDP 组播 / 定向广播发现 ----
        long sUdp = SystemClock.elapsedRealtime();
        List<Endpoint> candidates = udpDiscover(deviceId, pairCode);
        if (candidates.isEmpty()) {
            stage("udp", "✗ 没有收到任何合法公告（耗时 %d ms）", ms(sUdp));
        } else {
            Endpoint hit = tryFirst(candidates, deviceId, "udp");
            if (hit != null) { save(hit); return hit; }
            stage("udp", "✗ %d 个候选全部未通过 /api/ping（耗时 %d ms）",
                    candidates.size(), ms(sUdp));
        }

        // ---- 5 子网扫描（LocalSend legacy / Syncthing 广播兜底）----
        long sSub = SystemClock.elapsedRealtime();
        List<Endpoint> scanned = subnetCandidates(tagPort > 0 ? tagPort : 8765);
        Endpoint hit = tryFirst(scanned, deviceId, "subnet");
        if (hit != null) { save(hit); return hit; }
        stage("subnet", "✗ %d 个地址全部未命中（耗时 %d ms）", scanned.size(), ms(sSub));

        stage("cfg", "五级发现均未命中，总耗时 %d ms，deviceId=%s", ms(t0), mask(deviceId));
        return null;
    }

    private void save(Endpoint e) {
        prefs.edit().putString(Prefs.KEY_LAST_ENDPOINT, e.host + ":" + e.port).apply();
        Log.i(TAG, "[cfg] 缓存本次命中地址: " + e);
    }

    // ------------------------------------------------------------------
    // 日志辅助：统一 [级别] 前缀，便于 adb logcat 过滤后逐级核对
    // ------------------------------------------------------------------

    private static void stage(String stage, String fmt, Object... args) {
        Log.i(TAG, "[" + stage + "] " + String.format(Locale.ROOT, fmt, args));
    }

    private static long ms(long since) {
        return SystemClock.elapsedRealtime() - since;
    }

    /** device_id 是配对密钥派生的指纹，日志里只留前 6 位，避免整段密钥落盘。 */
    private static String mask(String id) {
        if (id == null || id.isEmpty()) return "(空)";
        return id.length() <= 6 ? id : id.substring(0, 6) + "…";
    }

    // ------------------------------------------------------------------
    // UDP 发现
    // ------------------------------------------------------------------

    private List<Endpoint> udpDiscover(String deviceId, String pairCode) {
        // pairCode 仅为兼容旧调用签名保留；v3 公告无签名。
        List<Endpoint> out = new ArrayList<>();
        MulticastSocket sock = null;
        WifiManager.MulticastLock lock = null;
        try {
            WifiManager wm = (WifiManager) ctx.getSystemService(Context.WIFI_SERVICE);
            if (wm != null) {
                // Android 默认过滤非本机地址的组播包，不拿锁就收不到应答。
                lock = wm.createMulticastLock("nfctap-discovery");
                lock.setReferenceCounted(true);
                lock.acquire();
            }
            sock = new MulticastSocket(0);
            sock.setSoTimeout(400);
            sock.setBroadcast(true);
            sock.setTimeToLive(2);
            InetAddress group = InetAddress.getByName(MCAST_GRP);
            // 加入组播组：优先走 wlan0，避免选中蜂窝 / 虚拟接口
            NetworkInterface ni = wifiInterface();
            if (ni != null) sock.setNetworkInterface(ni);
            sock.joinGroup(group);

            JSONObject q = new JSONObject();
            q.put("t", "q").put("v", PROTO_V).put("id", deviceId);
            byte[] qb = q.toString().getBytes(StandardCharsets.UTF_8);

            // 发组播 + 定向广播 + 全局广播；任一通道通即可。
            List<String> bcasts = broadcastAddresses();
            sock.send(new DatagramPacket(qb, qb.length, group, MCAST_PORT));
            int sent = 1;
            for (String b : bcasts) {
                try {
                    sock.send(new DatagramPacket(qb, qb.length,
                            InetAddress.getByName(b), MCAST_PORT));
                    sent++;
                } catch (Exception ex) {
                    stage("udp", "广播 %s 发送失败：%s", b, ex.getMessage());
                }
            }
            stage("udp", "已发 %d 个查询：组播 %s:%d + 广播 %s（网卡 %s）",
                    sent, MCAST_GRP, MCAST_PORT, bcasts,
                    ni == null ? "默认" : ni.getName());

            long deadline = System.currentTimeMillis() + UDP_WAIT_MS;
            byte[] buf = new byte[4096];
            int recv = 0;
            while (System.currentTimeMillis() < deadline) {
                try {
                    DatagramPacket pkt = new DatagramPacket(buf, buf.length);
                    sock.receive(pkt);
                    recv++;
                    String s = new String(pkt.getData(), pkt.getOffset(), pkt.getLength(),
                            StandardCharsets.UTF_8);
                    stage("udp", "收到来自 %s:%d 的 %d 字节：%s",
                            pkt.getAddress().getHostAddress(), pkt.getPort(), pkt.getLength(),
                            s.length() > 160 ? s.substring(0, 160) + "…" : s);
                    List<Endpoint> got = parseAnnouncement(s, deviceId, "udp");
                    for (Endpoint e : got) if (!contains(out, e)) out.add(e);
                    if (!out.isEmpty()) break;   // 拿到一份合法公告就够，尽快进入 HTTP 验证
                } catch (java.net.SocketTimeoutException ignored) {
                } catch (Exception e) {
                    stage("udp", "收包异常：%s", e);
                }
            }
            stage("udp", "等待结束：收到 %d 个包，解析出 %d 个候选", recv, out.size());
        } catch (Exception e) {
            stage("udp", "✗ 发现不可用：%s", e);
        } finally {
            if (sock != null) {
                try { sock.leaveGroup(InetAddress.getByName(MCAST_GRP)); } catch (Exception ignored) {}
                sock.close();
            }
            if (lock != null && lock.isHeld()) {
                try { lock.release(); } catch (Exception ignored) {}
            }
        }
        stage("udp", "候选 %d 个：%s", out.size(), out);
        return out;
    }

    private static boolean contains(List<Endpoint> list, Endpoint e) {
        for (Endpoint x : list) if (x.host.equals(e.host) && x.port == e.port) return true;
        return false;
    }

    /** v3：公告无 sig/sb。只校验 t/v/id/ts/port/ips 的结构与新鲜度，不校验 HMAC。 */
    static List<Endpoint> parseAnnouncement(String raw, String deviceId, String via) {
        List<Endpoint> out = new ArrayList<>();
        try {
            JSONObject obj = new JSONObject(raw);
            if (!"a".equals(obj.optString("t")) || obj.optInt("v") != PROTO_V) return out;
            if (!deviceId.equals(obj.optString("id"))) {
                Log.w(TAG, "公告设备 ID 不匹配，丢弃");
                return out;
            }
            if (!obj.has("ts")) return out;
            long age = System.currentTimeMillis() / 1000 - obj.optLong("ts", 0);
            if (age < -5 || age > MAX_AGE_S) {
                Log.w(TAG, "公告已过期，age=" + age + "s");
                return out;
            }
            if (!obj.has("port")) return out;
            int port = obj.optInt("port", 0);
            if (port < 1 || port > 65535) return out;
            JSONArray ips = obj.optJSONArray("ips");
            if (ips == null || ips.length() == 0) return out;
            for (int i = 0; i < ips.length() && i < 16; i++) {
                String ip = ips.optString(i, "");
                if (ip.matches("^\\d{1,3}(\\.\\d{1,3}){3}$")) {
                    out.add(new Endpoint(ip, port, via));
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "公告解析失败: " + e.getMessage());
        }
        return out;
    }

    // ------------------------------------------------------------------
    // 候选验证 / 子网扫描
    // ------------------------------------------------------------------

    private Endpoint tryFirst(List<Endpoint> candidates, String deviceId, String via) {
        if (candidates.isEmpty()) { stage(via, "无候选，跳过"); return null; }
        long t0 = SystemClock.elapsedRealtime();

        // 候选很少时串行探测，逐条打印可读结果，便于定位「连不上现在停在哪一步」
        if (candidates.size() <= 6) {
            for (Endpoint e : candidates) {
                long s = SystemClock.elapsedRealtime();
                String why = pingWhy(e, deviceId);
                if (why == null) {
                    stage(via, "✓ 命中 %s:%d（%d ms）", e.host, e.port, ms(s));
                    return e;
                }
                stage(via, "✗ %s:%d 失败：%s（%d ms）", e.host, e.port, why, ms(s));
            }
            stage(via, "✗ %d 个候选全部失败（%d ms）", candidates.size(), ms(t0));
            return null;
        }

        // 候选多（子网扫描）时并发，按原因聚合成一行摘要，避免刷 254 行
        ExecutorService pool = Executors.newFixedThreadPool(
                Math.min(12, Math.max(2, candidates.size())));
        Map<String, Integer> reasons = new HashMap<>();
        String sample = null;
        try {
            List<Callable<Endpoint>> tasks = new ArrayList<>();
            for (Endpoint e : candidates) {
                tasks.add(() -> {
                    String why = pingWhy(new Endpoint(e.host, e.port, via), deviceId);
                    synchronized (reasons) {
                        reasons.put(why == null ? "ok" : why,
                                reasons.getOrDefault(why == null ? "ok" : why, 0) + 1);
                    }
                    return why == null ? e : null;
                });
            }
            long deadline = System.currentTimeMillis() + 4000;
            List<Future<Endpoint>> fs = pool.invokeAll(tasks, 4, TimeUnit.SECONDS);
            for (Future<Endpoint> f : fs) {
                if (System.currentTimeMillis() > deadline) break;
                try {
                    Endpoint e = f.get(100, TimeUnit.MILLISECONDS);
                    if (e != null) {
                        stage(via, "✓ 命中 %s:%d（%d ms）", e.host, e.port, ms(t0));
                        return e;
                    }
                } catch (Exception ignored) {}
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            pool.shutdownNow();
        }
        for (Map.Entry<String, Integer> en : reasons.entrySet()) {
            if ("ok".equals(en.getKey())) continue;
            if (sample == null) sample = en.getKey();
        }
        stage(via, "✗ %d 个地址未命中（%d ms），失败原因统计：%s；示例：%s",
                candidates.size(), ms(t0), reasons, sample == null ? "无" : sample);
        return null;
    }

    /**
     * HTTP /api/ping 粗筛：协议必须 nfctap/3、ok=true、device_id 与标签一致。
     * @return null 表示通过；否则返回可读的失败原因（用于逐级日志定位）。
     */
    private String pingWhy(Endpoint e, String deviceId) {
        HttpURLConnection c = null;
        try {
            c = (HttpURLConnection) new URL(
                    "http://" + e.host + ":" + e.port + "/api/ping").openConnection();
            c.setConnectTimeout(PING_TIMEOUT_MS);
            c.setReadTimeout(PING_TIMEOUT_MS);
            c.setRequestMethod("GET");
            int code = c.getResponseCode();
            if (code != 200) return "HTTP " + code;
            byte[] b = readAll(c.getInputStream());
            JSONObject j = new JSONObject(new String(b, StandardCharsets.UTF_8));
            if (!j.optBoolean("ok")) return "ok=false";
            String proto = j.optString("protocol", "");
            if (!V3Crypto.PROTOCOL.equals(proto)) {
                return "协议不符(期望 " + V3Crypto.PROTOCOL + "，实际 " + (proto.isEmpty() ? "空" : proto) + ")";
            }
            String got = j.optString("device_id", "");
            if (deviceId == null || deviceId.isEmpty()) return "本地 deviceId 为空";
            if (!deviceId.equals(got)) {
                return "device_id 不符(期望 " + mask(deviceId) + "，实际 " + mask(got) + ")";
            }
            return null;
        } catch (java.net.SocketTimeoutException ex) {
            return "超时(" + PING_TIMEOUT_MS + "ms，主机无响应或被防火墙丢弃)";
        } catch (java.net.ConnectException ex) {
            return "连接被拒绝(端口未监听：" + e.port + ")";
        } catch (java.net.NoRouteToHostException ex) {
            return "路由不可达(不在同一网段或被隔离)";
        } catch (Exception ex) {
            return ex.getClass().getSimpleName()
                    + (ex.getMessage() == null ? "" : ":" + ex.getMessage());
        } finally {
            if (c != null) c.disconnect();
        }
    }

    /** 本机 Wi-Fi 所在 /24 的全部地址（LocalSend legacy 思路），上限 254 个。 */
    private List<Endpoint> subnetCandidates(int port) {
        List<Endpoint> out = new ArrayList<>();
        String[] detail = localIPv4Detail();   // {ip, 网卡名, 前缀长度}
        if (detail == null || detail[0] == null || port < 1) {
            stage("subnet", "✗ 拿不到本机局域网 IPv4，跳过子网扫描");
            return out;
        }
        String ip = detail[0];
        String prefix = ip.substring(0, ip.lastIndexOf('.') + 1);
        for (int i = 1; i <= 254; i++) out.add(new Endpoint(prefix + i, port, "subnet"));
        stage("subnet", "本机 %s/%s（网卡 %s），扫描 %s1-%s254:%d，共 %d 个",
                ip, detail[2], detail[1], prefix, prefix, port, out.size());
        return out;
    }

    /**
     * 取本机局域网 IPv4：优先 Wi-Fi 网络，避免拿到蜂窝接口（ccmni / rmnet）
     * 导致子网扫描扫错网段。返回 {ip, 网卡名, 前缀长度}，拿不到返回 null。
     */
    private String[] localIPv4Detail() {
        try {
            ConnectivityManager cm = (ConnectivityManager)
                    ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm != null) {
                Network wifi = null;
                for (Network n : cm.getAllNetworks()) {
                    NetworkCapabilities nc = cm.getNetworkCapabilities(n);
                    if (nc != null && nc.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                        wifi = n;
                        break;
                    }
                }
                if (wifi != null) {
                    LinkProperties lp = cm.getLinkProperties(wifi);
                    if (lp != null) {
                        for (LinkAddress la : lp.getLinkAddresses()) {
                            InetAddress a = la.getAddress();
                            if (a instanceof Inet4Address && !a.isLoopbackAddress()
                                    && !a.isLinkLocalAddress()) {
                                return new String[]{a.getHostAddress(),
                                        String.valueOf(lp.getInterfaceName()),
                                        String.valueOf(la.getPrefixLength())};
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            stage("subnet", "读 Wi-Fi LinkProperties 失败：%s", e);
        }
        // 退化：枚举网卡，优先 wlan*，跳过蜂窝 / 虚拟接口
        try {
            String[] fallback = null;
            for (Enumeration<NetworkInterface> es = NetworkInterface.getNetworkInterfaces();
                 es.hasMoreElements(); ) {
                NetworkInterface ni = es.nextElement();
                String name = ni.getName() == null ? "" : ni.getName();
                if (!ni.isUp() || ni.isLoopback()) continue;
                for (Enumeration<InetAddress> as = ni.getInetAddresses(); as.hasMoreElements(); ) {
                    InetAddress a = as.nextElement();
                    if (!(a instanceof Inet4Address) || a.isLoopbackAddress()
                            || a.isLinkLocalAddress()) continue;
                    String[] got = new String[]{a.getHostAddress(), name, "24"};
                    if (name.startsWith("wlan")) return got;   // Wi-Fi 网卡直接采用
                    boolean cellular = name.startsWith("ccmni") || name.startsWith("rmnet")
                            || name.startsWith("pdp");
                    if (!cellular && fallback == null) fallback = got;
                }
            }
            if (fallback != null) return fallback;
        } catch (Exception e) {
            stage("subnet", "枚举网卡失败：%s", e);
        }
        return null;
    }

    private NetworkInterface wifiInterface() {
        try {
            NetworkInterface wlan = NetworkInterface.getByName("wlan0");
            if (wlan != null && wlan.isUp()) return wlan;
            for (Enumeration<NetworkInterface> es = NetworkInterface.getNetworkInterfaces();
                 es.hasMoreElements(); ) {
                NetworkInterface ni = es.nextElement();
                if (ni.isUp() && !ni.isLoopback()) return ni;
            }
        } catch (Exception ignored) {}
        return null;
    }

    /** 用 LinkProperties 算链路定向广播；拿不到就退回全局广播。 */
    private List<String> broadcastAddresses() {
        List<String> out = new ArrayList<>();
        try {
            ConnectivityManager cm = (ConnectivityManager)
                    ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm != null) {
                Network n = cm.getActiveNetwork();
                LinkProperties lp = n == null ? null : cm.getLinkProperties(n);
                if (lp != null) {
                    for (LinkAddress la : lp.getLinkAddresses()) {
                        if (!(la.getAddress() instanceof Inet4Address)) continue;
                        byte[] ip = la.getAddress().getAddress();
                        int pfx = la.getPrefixLength();
                        if (pfx < 0 || pfx > 32) continue;
                        int mask = pfx == 0 ? 0 : (0xFFFFFFFF << (32 - pfx));
                        int addr = toInt(ip) | ~mask;
                        out.add(intToIp(addr));
                    }
                }
            }
        } catch (Exception ignored) {}
        if (out.isEmpty()) out.add("255.255.255.255");
        return out;
    }

    private static int toInt(byte[] b) {
        return ((b[0] & 255) << 24) | ((b[1] & 255) << 16) | ((b[2] & 255) << 8) | (b[3] & 255);
    }

    private static String intToIp(int v) {
        return ((v >>> 24) & 255) + "." + ((v >>> 16) & 255) + "."
                + ((v >>> 8) & 255) + "." + (v & 255);
    }

    private static byte[] readAll(InputStream is) throws Exception {
        if (is == null) return new byte[0];
        try (InputStream in = is; ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            byte[] buf = new byte[4096];
            int n;
            while ((n = in.read(buf)) != -1) bos.write(buf, 0, n);
            return bos.toByteArray();
        }
    }
}
