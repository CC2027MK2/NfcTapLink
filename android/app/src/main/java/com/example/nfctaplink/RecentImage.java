/*
 * NfcTapLink · 免寄存取图（碰标签时实时取媒体库最新一张）
 *
 * 为什么需要它：原链路要「先在图库分享 → 一碰传寄存，再碰标签发送」两步。
 * 用户希望碰一下就直接发。Android 不允许第三方 App 读取别的 App 当前屏幕，
 * 但**允许读取媒体库**——所以把取图时机从「分享时」挪到「碰标签时」：
 * 碰标签 → 查 MediaStore 最新一张图 → 直接上传，零额外点击、无需预先寄存。
 *
 * 一手依据：
 *   - Android 14「授予照片和视频的部分访问权限」：确认权限后用
 *     ContentResolver 查 MediaStore，排序 DATE_ADDED DESC；部分访问同样可查。
 *   - Android 13+ READ_MEDIA_IMAGES；14+ READ_MEDIA_VISUAL_USER_SELECTED。
 *   - 权限状态不要缓存，每次现查（系统可能在后台改）。
 *
 * 误发防护：只自动发送「最近 windowSec 秒内新增」的图；太旧则交给
 * 系统照片选择器（ACTION_PICK_IMAGES，API 33+，无需存储权限）让用户点一下。
 */
package com.example.nfctaplink;

import android.Manifest;
import android.content.ContentResolver;
import android.content.ContentUris;
import android.content.Context;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.provider.MediaStore;
import android.util.Log;

import java.io.InputStream;

public class RecentImage {

    private static final String TAG = "NfcTapLinkRecent";

    public static final int OK = 0;
    public static final int NO_PERMISSION = 1;
    public static final int NONE = 2;
    public static final int TOO_OLD = 3;
    public static final int ERROR = 4;

    public static class Item {
        public final Uri uri;
        public final String name;
        public final long dateAdded;
        public final long size;
        Item(Uri uri, String name, long dateAdded, long size) {
            this.uri = uri; this.name = name; this.dateAdded = dateAdded; this.size = size;
        }
    }

    public static class Result {
        public final int code;
        public final Item item;
        public final String msg;
        Result(int code, Item item, String msg) {
            this.code = code; this.item = item; this.msg = msg;
        }
    }

    /** 是否有权查媒体库（每次现查，不缓存授权状态）。 */
    public static boolean hasPermission(Context ctx) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ctx.checkSelfPermission(Manifest.permission.READ_MEDIA_IMAGES)
                    == PackageManager.PERMISSION_GRANTED) return true;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE
                    && ctx.checkSelfPermission(
                            "android.permission.READ_MEDIA_VISUAL_USER_SELECTED")
                    == PackageManager.PERMISSION_GRANTED) return true;
            return false;
        }
        return ctx.checkSelfPermission(Manifest.permission.READ_EXTERNAL_STORAGE)
                == PackageManager.PERMISSION_GRANTED;
    }

    /**
     * 取媒体库最新一张图。windowSec <= 0 表示不限时间（仍只取最新一张）。
     * 必须在后台线程调用（会读文件内容）。
     */
    public static Result pick(Context ctx, long windowSec) {
        if (!hasPermission(ctx)) {
            return new Result(NO_PERMISSION, null, "没有读取相册的权限");
        }
        ContentResolver cr = ctx.getContentResolver();
        Uri collection = Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q
                ? MediaStore.Images.Media.getContentUri(MediaStore.VOLUME_EXTERNAL)
                : MediaStore.Images.Media.EXTERNAL_CONTENT_URI;
        String[] proj = {
                MediaStore.Images.Media._ID,
                MediaStore.Images.Media.DISPLAY_NAME,
                MediaStore.Images.Media.DATE_ADDED,
                MediaStore.Images.Media.SIZE,
        };
        Cursor c = null;
        try {
            c = cr.query(collection, proj, null, null,
                    MediaStore.Images.Media.DATE_ADDED + " DESC");
            if (c == null || !c.moveToFirst()) {
                return new Result(NONE, null, "相册里没有图片");
            }
            long id = c.getLong(c.getColumnIndexOrThrow(MediaStore.Images.Media._ID));
            String name = c.getString(c.getColumnIndexOrThrow(MediaStore.Images.Media.DISPLAY_NAME));
            long added = c.getLong(c.getColumnIndexOrThrow(MediaStore.Images.Media.DATE_ADDED));
            Uri uri = ContentUris.withAppendedId(collection, id);

            long now = System.currentTimeMillis() / 1000;
            long age = now - added;
            // windowSec >= 0 表示启用时间窗口（0 = 一律视为过期，便于验证防护）；
            // 负数表示「不限时间」（MODE_AUTO_ANY）。
            if (windowSec >= 0 && (age > windowSec || age < -60)) {
                return new Result(TOO_OLD, new Item(uri, name, added, 0),
                        "最新一张是 " + (age / 60) + " 分钟前的（" + name + "），超出自动发送窗口");
            }
            long size = 0;
            int sizeIdx = c.getColumnIndex(MediaStore.Images.Media.SIZE);
            if (sizeIdx >= 0 && !c.isNull(sizeIdx)) size = c.getLong(sizeIdx);
            if (name == null || name.trim().isEmpty()) name = "photo.jpg";
            Log.i(TAG, "取到最新图 " + name + " / " + size + " B / age=" + age + "s");
            return new Result(OK, new Item(uri, name, added, size), "ok");
        } catch (SecurityException e) {
            return new Result(NO_PERMISSION, null, "相册访问被系统拒绝：" + e.getMessage());
        } catch (Exception e) {
            Log.e(TAG, "取最新图失败", e);
            return new Result(ERROR, null, e.getMessage() == null ? "读取异常" : e.getMessage());
        } finally {
            if (c != null) c.close();
        }
    }
}
