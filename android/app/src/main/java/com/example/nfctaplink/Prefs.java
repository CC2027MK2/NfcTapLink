/*
 * NfcTapLink · SharedPreferences 键的单一来源。
 * TapActivity 与 MainActivity 必须共用这一份，否则「配置存了但碰标签读不到」。
 * 与 kotlin-src/Prefs.kt 的键值逐字一致（本次实际编译的是 Java 版）。
 */
package com.example.nfctaplink;

public final class Prefs {
    private Prefs() {}

    public static final String PREF = "nfctap";
    public static final String KEY_PENDING_URI = "pending_uri";
    public static final String KEY_PENDING_NAME = "pending_name";
    public static final String KEY_HOST = "host";
    public static final String KEY_PORT = "port";
    public static final String KEY_CODE = "code";
    public static final String KEY_TOKEN = "token";
    public static final String KEY_TOKEN_EXP = "token_exp";
    public static final String KEY_SERVER_NONCE = "server_nonce";
    public static final String KEY_CLIENT_NONCE = "client_nonce";
    /** 会话绑定目标：host:port:device_id。旧版 token 无此绑定，换机后会误复用。 */
    public static final String KEY_TOKEN_BINDING = "token_binding";

    // v2 自动发现：标签里的稳定设备 ID，以及上次成功连接的 host:port。
    // 后者用于「下次碰标签先探缓存地址」，避免每次都做一次组播发现。
    public static final String KEY_DEVICE_ID = "device_id";
    public static final String KEY_LAST_ENDPOINT = "last_endpoint";

    // v4 免寄存：碰标签时的取图模式
    // MODE_AUTO_RECENT = 自动发媒体库最近一张（限时间窗口）
    // MODE_AUTO_ANY    = 自动发媒体库最近一张（不限时间）
    // MODE_PICKER      = 每次拉起系统照片选择器点一张
    // MODE_LEGACY      = 旧行为，只发「分享寄存」的图片
    public static final String KEY_SEND_MODE = "send_mode";
    public static final String KEY_AUTO_WINDOW_MIN = "auto_window_min";
    public static final int MODE_AUTO_RECENT = 0;
    public static final int MODE_AUTO_ANY = 1;
    public static final int MODE_PICKER = 2;
    public static final int MODE_LEGACY = 3;
    public static final int DEFAULT_WINDOW_MIN = 30;

    // 碰标签时的原始参数：存下来是为了「系统照片选择器」返回后
    // Activity 可能已被重建，仍能从 prefs 恢复发现流程，不依赖实例字段。
    public static final String KEY_TAG_HINT = "tag_hint";
    public static final String KEY_TAG_HOST = "tag_host";
    public static final String KEY_TAG_PORT = "tag_port";
}
