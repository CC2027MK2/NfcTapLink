/*
 * NfcTapLink · v3 密码学原语（只用 Android SDK / javax.crypto.Mac，零第三方依赖）
 *
 * 与电脑端 receiver.py、浏览器端 tap.html 严格同构：
 *   k = 标签里的 64 hex；d = sha256(hexToBytes(k))[:16]
 *   proof / server_proof / session root / enc_key / mac_key / keystream / tag
 *   全部是 HMAC-SHA256，不用 AES-GCM，不依赖 WebCrypto。
 * k 只进本地 HMAC，不进任何 URL、日志或网络请求。
 *
 * v6.2：收发都改为流式。1 GB 文件不再整段进 byte[]，峰值内存只剩 1 MB 块；
 * 密钥流按 32B 一块由 HMAC 计数器生成，与电脑端 keystream_blocks 完全一致。
 */
package com.example.nfctaplink;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class V3Crypto {

    public static final String PROTOCOL = "nfctap/3";
    public static final String VERSION = "3.0.0";

    /** 流式分块大小：与电脑端 UPLOAD_CHUNK / CIPHER_CHUNK 一致（1 MB）。 */
    public static final int CHUNK = 1024 * 1024;

    private static final String HMAC = "HmacSHA256";
    private static final byte[] MAGIC = new byte[]{'N', 'T', '3'};
    private static final SecureRandom RNG = new SecureRandom();

    private V3Crypto() {}

    /** 64 hex -> 32 字节密钥；非法字符 / 长度一律拒绝，绝不降级成旧版口令。 */
    public static byte[] keyBytes(String k) throws Exception {
        if (k == null) throw new IllegalArgumentException("缺少配对密钥 k");
        String s = k.trim().toLowerCase(java.util.Locale.ROOT);
        if (s.length() != 64) throw new IllegalArgumentException("k 必须是 64 位十六进制");
        for (int i = 0; i < 64; i++) {
            char c = s.charAt(i);
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
                throw new IllegalArgumentException("k 必须是 64 位十六进制");
        }
        return hexToBytes(s);
    }

    /** d = sha256(hexToBytes(k))[:16]，小写 hex。 */
    public static String deviceId(String k) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] h = md.digest(keyBytes(k));
        return hex(h).substring(0, 16);
    }

    /** 16 随机字节的 hex（32 chars，client_nonce cn）。 */
    public static String randomHex16() {
        return hex(randomBytes(16));
    }

    /** 12 随机字节的 hex（24 chars，上传 X-Nonce）。 */
    public static String randomHex12() {
        return hex(randomBytes(12));
    }

    public static String hmacUtf8Hex(byte[] key, String message) throws Exception {
        return hex(hmac(key, message.getBytes(StandardCharsets.UTF_8)));
    }

    public static byte[] hmacUtf8(byte[] key, String message) throws Exception {
        return hmac(key, message.getBytes(StandardCharsets.UTF_8));
    }

    /** HMAC-SHA256(key, part1 || part2 ...)，拼接按传入顺序，不插入任何分隔符。 */
    public static byte[] hmac(byte[] key, byte[]... parts) throws Exception {
        Mac mac = Mac.getInstance(HMAC);
        mac.init(new SecretKeySpec(key, HMAC));
        for (byte[] p : parts) mac.update(p);
        return mac.doFinal();
    }

    /** 常时间比较；两边都必须是完整 32 字节 HMAC 值或等长 hex 字符串转换后的字节。 */
    public static boolean constantTimeEquals(byte[] a, byte[] b) {
        return MessageDigest.isEqual(a, b);
    }

    /**
     * 发送端流式封包。tag 位于密文之前，只能先扫一遍明文算出整段密文的 HMAC，
     * 再回放一遍把密文写进 socket：两遍读盘、常数内存，与电脑端 receiver.py
     * 的 download_tag / cipher_chunks 同构。
     */
    public static final class Outbound {
        /** "NT3" + nameLen(1B) + name + tag(32)。 */
        public final byte[] header;
        public final long plainLen;
        private final byte[] encKey;

        private Outbound(byte[] header, long plainLen, byte[] encKey) {
            this.header = header;
            this.plainLen = plainLen;
            this.encKey = encKey;
        }

        /** 第二遍：重新生成密钥流，把密文写到 out；长度与第一遍不符即中止。 */
        public void writeCipher(InputStream plain, OutputStream out) throws Exception {
            Ks ks = new Ks(encKey);
            byte[] buf = new byte[CHUNK];
            long total = 0;
            while (total < plainLen) {
                int n = plain.read(buf, 0, (int) Math.min(buf.length, plainLen - total));
                if (n < 0) throw new java.io.IOException("文件在传送过程中变短了，请重试");
                ks.xor(buf, 0, n);
                out.write(buf, 0, n);
                total += n;
            }
            if (plain.read() != -1) throw new java.io.IOException("文件在传送过程中变长了，请重试");
        }
    }

    /**
     * 第一遍：按 dataLen 派生密钥，边读明文边生成密钥流，对密文算 HMAC，
     * 返回含 tag 的载荷头。调用方随后用 writeCipher 回放第二遍。
     */
    public static Outbound prepareUpload(String k, String sn, String cn, String token,
                                         long ts, String nonce, String name,
                                         long dataLen, InputStream plain) throws Exception {
        byte[] key = keyBytes(k);
        byte[] nameBytes = name.getBytes(StandardCharsets.UTF_8);
        if (nameBytes.length == 0 || nameBytes.length > 255) {
            throw new IllegalArgumentException("文件名 UTF-8 字节数必须在 1..255");
        }
        if (dataLen <= 0) throw new IllegalArgumentException("空文件无法发送");

        String len = Long.toString(dataLen);
        byte[] root = hmacUtf8(key, "session|" + sn + "|" + cn + "|" + token);
        byte[] ctx = ("upload|" + ts + "|" + nonce + "|" + name + "|" + len)
                .getBytes(StandardCharsets.UTF_8);
        byte[] encKey = hmac(root, "enc|".getBytes(StandardCharsets.UTF_8), ctx);
        byte[] macKey = hmac(root, "mac|".getBytes(StandardCharsets.UTF_8), ctx);
        byte[] aad = ("nfctap/3|POST|/api/upload|" + token + "|" + ts + "|" + nonce
                + "|" + name + "|" + len).getBytes(StandardCharsets.UTF_8);

        Mac verifier = Mac.getInstance(HMAC);
        verifier.init(new SecretKeySpec(macKey, HMAC));
        verifier.update(aad);
        Ks ks = new Ks(encKey);
        byte[] buf = new byte[CHUNK];
        long total = 0;
        while (total < dataLen) {
            int n = plain.read(buf, 0, (int) Math.min(buf.length, dataLen - total));
            if (n < 0) throw new java.io.IOException("文件在传送过程中变短了，请重试");
            ks.xor(buf, 0, n);
            verifier.update(buf, 0, n);
            total += n;
        }
        if (plain.read() != -1) throw new java.io.IOException("文件在传送过程中变长了，请重试");
        byte[] tag = verifier.doFinal();

        byte[] header = new byte[4 + nameBytes.length + tag.length];
        header[0] = 'N'; header[1] = 'T'; header[2] = '3';
        header[3] = (byte) nameBytes.length;
        System.arraycopy(nameBytes, 0, header, 4, nameBytes.length);
        System.arraycopy(tag, 0, header, 4 + nameBytes.length, tag.length);
        return new Outbound(header, dataLen, encKey);
    }

    /**
     * 接收端流式解包：解析 NT3 头，按块「更新 HMAC + 密钥流就地异或」，
     * 读完后调用 verify() 校验 tag。cipherLen 来自 HTTP Content-Length，
     * 1 GB 文件也不会整段进内存。
     */
    public static final class Inbound {
        public final String name;
        public final long cipherLen;
        private final byte[] tag;
        private final Mac verifier;
        private final Ks ks;

        private Inbound(String name, long cipherLen, byte[] tag, Mac verifier, Ks ks) {
            this.name = name;
            this.cipherLen = cipherLen;
            this.tag = tag;
            this.verifier = verifier;
            this.ks = ks;
        }

        /** 传入一段密文，方法返回时 buf 已就地变成明文。 */
        public void feed(byte[] buf, int off, int len) throws Exception {
            verifier.update(buf, off, len);
            ks.xor(buf, off, len);
        }

        /** 全部密文喂完后校验 tag；不匹配抛异常，调用方必须丢弃已写数据。 */
        public void verify() throws Exception {
            if (!constantTimeEquals(tag, verifier.doFinal())) {
                throw new java.security.GeneralSecurityException("下载文件完整性校验失败");
            }
        }
    }

    /**
     * 解析下载响应头（"NT3" + nameLen + name + tag），派生下载密钥。
     * prefix 必须是响应最前面 4 + nameLen + 32 字节。
     */
    public static Inbound beginDownload(String k, String sn, String cn, String token,
                                        long ts, String nonce, String outboxId,
                                        byte[] prefix, long cipherLen) throws Exception {
        if (prefix == null || prefix.length < 4 + 1 + 32) {
            throw new IllegalArgumentException("下载载荷过短");
        }
        if (prefix[0] != 'N' || prefix[1] != 'T' || prefix[2] != '3') {
            throw new IllegalArgumentException("下载载荷格式错误");
        }
        int nameLen = prefix[3] & 0xff;
        if (nameLen == 0 || prefix.length < 4 + nameLen + 32) {
            throw new IllegalArgumentException("下载载荷长度错误");
        }
        String name = new String(prefix, 4, nameLen, StandardCharsets.UTF_8);
        byte[] tag = new byte[32];
        System.arraycopy(prefix, 4 + nameLen, tag, 0, 32);
        if (cipherLen <= 0) throw new IllegalArgumentException("下载密文为空");

        String len = Long.toString(cipherLen);
        byte[] key = keyBytes(k);
        byte[] root = hmacUtf8(key, "session|" + sn + "|" + cn + "|" + token);
        byte[] ctx = ("download|" + ts + "|" + nonce + "|" + outboxId + "|"
                + name + "|" + len).getBytes(StandardCharsets.UTF_8);
        byte[] encKey = hmac(root, "enc|".getBytes(StandardCharsets.UTF_8), ctx);
        byte[] macKey = hmac(root, "mac|".getBytes(StandardCharsets.UTF_8), ctx);
        byte[] aad = ("nfctap/3|GET|/api/download|" + token + "|" + ts + "|" + nonce
                + "|" + outboxId + "|" + name + "|" + len)
                .getBytes(StandardCharsets.UTF_8);
        Mac verifier = Mac.getInstance(HMAC);
        verifier.init(new SecretKeySpec(macKey, HMAC));
        verifier.update(aad);
        return new Inbound(name, cipherLen, tag, verifier, new Ks(encKey));
    }

    /** counter=0,1,2...：HMAC-SHA256(enc_key, "KS|" || counter 8 字节大端)，32B 一块就地异或。 */
    private static final class Ks {
        private final Mac mac;
        private final byte[] block = new byte[11];
        private final byte[] ks = new byte[32];
        private int pos = 32;
        private long counter = 0;

        Ks(byte[] encKey) throws Exception {
            mac = Mac.getInstance(HMAC);
            mac.init(new SecretKeySpec(encKey, HMAC));
            block[0] = 'K'; block[1] = 'S'; block[2] = '|';
        }

        void xor(byte[] buf, int off, int len) throws Exception {
            while (len > 0) {
                if (pos >= 32) {
                    for (int i = 0; i < 8; i++) block[3 + i] = (byte) (counter >>> (56 - 8 * i));
                    byte[] h = mac.doFinal(block);
                    System.arraycopy(h, 0, ks, 0, 32);
                    counter++;
                    pos = 0;
                }
                int n = Math.min(len, 32 - pos);
                for (int i = 0; i < n; i++) buf[off + i] ^= ks[pos + i];
                off += n;
                len -= n;
                pos += n;
            }
        }
    }

    private static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        RNG.nextBytes(b);
        return b;
    }

    private static byte[] hexToBytes(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(s.charAt(2 * i), 16);
            int lo = Character.digit(s.charAt(2 * i + 1), 16);
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            sb.append(Character.forDigit((x >> 4) & 0xF, 16));
            sb.append(Character.forDigit(x & 0xF, 16));
        }
        return sb.toString();
    }
}
