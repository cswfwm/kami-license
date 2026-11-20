package com.kami.license;

import android.content.Context;
import android.provider.Settings;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 卡密客户端。只内置公钥，验签在本地完成，服务端私钥无法伪造。
 *
 * 用法：
 *   LicenseClient c = new LicenseClient(context);
 *   LicenseClient.Result r = c.activate("ABCD-EFGH-IJKL-MNOP");
 *   if (r.ok) { if (c.hasFeature("export")) { ... } }
 *
 * 注意：本类处理了该免费主机前置的 AES 挑战（非浏览器 UA 会收到 aes.js 挑战页），
 * 因此不要替换 User-Agent，也不要走系统 Uri 下载。
 */
public final class LicenseClient {

    /** 服务端公钥（ECDSA P-256），固定写入 APK，用于验证响应签名。 */
    private static final String PUBLIC_KEY_PEM =
            "-----BEGIN PUBLIC KEY-----\n"
          + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgxbmKjxvbzeI3AsJm0LNid4MOrKj\n"
          + "imR93TDcB2T6hWSBrQjhJpBkYHsMRdDK/XZLCeCSCCC9UxEXyuwvuqn+fw==\n"
          + "-----END PUBLIC KEY-----";

    private static final String DEFAULT_BASE = "http://xxxxx-x.uuk.pp.ua";
    private static final String UA =
            "Mozilla/5.0 (Linux; Android 5.1; MI 8) AppleWebKit/537.36 (KHTML, like Gecko) "
          + "Chrome/50.0.2661.89 Mobile Safari/537.36";
    private static final Charset UTF8 = Charset.forName("UTF-8");

    private final Context context;
    private final String baseUrl;
    private final String deviceId;
    private final String deviceName;
    private final String appVersion;

    /** __test cookie 缓存（服务端挑战解出的结果，有效期约 6 小时）。 */
    private final Map<String, String> cookies = new ConcurrentHashMap<String, String>();

    private String cachedLicense;
    private String[] cachedFeatures = new String[0];
    private long cachedExpireAt = -1;

    public LicenseClient(Context ctx) {
        this(ctx, DEFAULT_BASE);
    }

    public LicenseClient(Context ctx, String base) {
        this.context = ctx.getApplicationContext();
        this.baseUrl = base.endsWith("/") ? base.substring(0, base.length() - 1) : base;
        this.deviceId = buildDeviceId();
        this.deviceName = android.os.Build.MANUFACTURER + " " + android.os.Build.MODEL;
        this.appVersion = readVersionName();
    }

    // ---------------------------------------------------------------- 对外接口

    /** 首次激活：绑定设备并领取许可证。 */
    public Result activate(String code) {
        try {
            JSONObject body = new JSONObject();
            body.put("code", code);
            body.put("device_id", deviceId);
            body.put("device_name", deviceName);
            body.put("app_version", appVersion);
            return handleResponse(post("/api.php?action=activate", body));
        } catch (Exception e) {
            return Result.fail("network", e.toString());
        }
    }

    /** 联网复验：建议每次启动调用一次，失败时回退到本地缓存。 */
    public Result verify(String code) {
        try {
            JSONObject body = new JSONObject();
            body.put("code", code);
            body.put("device_id", deviceId);
            body.put("nonce", newNonce());
            body.put("ts", System.currentTimeMillis() / 1000L);
            return handleResponse(post("/api.php?action=verify", body));
        } catch (Exception e) {
            return Result.fail("network", e.toString());
        }
    }

    /** 当前是否解锁某功能（未激活或已过期返回 false）。 */
    public boolean hasFeature(String feature) {
        if (isExpiredLocally()) {
            return false;
        }
        for (String f : cachedFeatures) {
            if (f.equals(feature)) {
                return true;
            }
        }
        return false;
    }

    public String[] features() {
        return cachedFeatures.clone();
    }

    /** 到期时间（毫秒时间戳），-1 表示永久。 */
    public long expireAt() {
        return cachedExpireAt;
    }

    public String deviceId() {
        return deviceId;
    }

    /**
     * 离线可用性判断：到期前或宽限期内返回 true。
     * 超过宽限期必须联网复验，避免长期断网绕过停用。
     */
    public boolean isExpiredLocally() {
        if (cachedExpireAt < 0) {
            return false;
        }
        return System.currentTimeMillis() > cachedExpireAt + GRACE_MS;
    }

    private static final long GRACE_MS = 3L * 24 * 60 * 60 * 1000;

    // ---------------------------------------------------------------- 响应处理

    private Result handleResponse(String raw) throws Exception {
        JSONObject json = new JSONObject(raw);
        if (!json.optBoolean("ok")) {
            return Result.fail(json.optString("error", "unknown"), json.optString("msg", ""));
        }
        String license = json.getString("license");
        String sig = json.getString("sig");
        if (!verifySignature(license, sig)) {
            return Result.fail("bad_signature", "响应签名校验失败");
        }
        String payloadJson = new String(Base64Url.decode(license), UTF8);
        JSONObject payload = new JSONObject(payloadJson);

        if (!deviceId.equals(payload.optString("device"))) {
            return Result.fail("device_mismatch", "许可证与当前设备不匹配");
        }

        JSONArray arr = payload.optJSONArray("features");
        String[] feats = new String[arr == null ? 0 : arr.length()];
        for (int i = 0; i < feats.length; i++) {
            feats[i] = arr.getString(i);
        }
        Object exp = payload.opt("expire_at");
        cachedLicense = license;
        cachedFeatures = feats;
        cachedExpireAt = (exp == null || exp == JSONObject.NULL) ? -1 : payload.getLong("expire_at") * 1000L;

        return Result.ok(payload.optString("plan"), feats, cachedExpireAt);
    }

    private static boolean verifySignature(String licenseB64, String sigB64) {
        try {
            PublicKey key = loadPublicKey();
            Signature sg = Signature.getInstance("SHA256withECDSA");
            sg.initVerify(key);
            sg.update(licenseB64.getBytes(UTF8));
            return sg.verify(Base64Url.decode(sigB64));
        } catch (Exception e) {
            return false;
        }
    }

    private static PublicKey loadPublicKey() throws Exception {
        String body = PUBLIC_KEY_PEM
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        byte[] der = android.util.Base64.decode(body, android.util.Base64.DEFAULT);
        return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(der));
    }

    // ---------------------------------------------------------------- 网络

    private String post(String path, JSONObject body) throws Exception {
        byte[] payload = body.toString().getBytes(UTF8);
        String last = "";
        for (int attempt = 0; attempt < 4; attempt++) {
            HttpURLConnection conn = open(path, "POST");
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
            OutputStream os = conn.getOutputStream();
            os.write(payload);
            os.close();

            int code = conn.getResponseCode();
            String text = read(conn, code);
            conn.disconnect();

            if (text != null && text.contains("slowAES.decrypt")) {
                solveChallenge(text);
                continue;
            }
            if (text != null && text.length() > 0) {
                return text;
            }
            last = text == null ? "" : text;
            // 空响应：主机在缺少 __test cookie 时会丢弃 POST，先取一次 GET 再重试
            primeCookie(path);
        }
        throw new IllegalStateException("empty response from server: " + last);
    }

    private void primeCookie(String path) throws Exception {
        HttpURLConnection conn = open(path, "GET");
        int code = conn.getResponseCode();
        String text = read(conn, code);
        conn.disconnect();
        if (text != null && text.contains("slowAES.decrypt")) {
            solveChallenge(text);
        }
    }

    private HttpURLConnection open(String path, String method) throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL(baseUrl + path).openConnection();
        conn.setRequestMethod(method);
        conn.setConnectTimeout(15000);
        conn.setReadTimeout(20000);
        conn.setRequestProperty("User-Agent", UA);
        conn.setRequestProperty("Accept", "*/*");
        String cookie = cookies.get("__test");
        if (cookie != null) {
            conn.setRequestProperty("Cookie", "__test=" + cookie);
        }
        return conn;
    }

    private static String read(HttpURLConnection conn, int code) throws Exception {
        InputStream is = (code >= 200 && code < 400) ? conn.getInputStream() : conn.getErrorStream();
        if (is == null) {
            return "";
        }
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = is.read(buf)) > 0) {
            bos.write(buf, 0, n);
        }
        is.close();
        return new String(bos.toByteArray(), UTF8);
    }

    // ---------------------------------------------------------------- 前置挑战

    /**
     * 主机对非 Googlebot UA 下发 AES 挑战：页面给出 a,b,c 三段 hex，
     * cookie = AES-128-CBC-decrypt(key=a, iv=b, c)。解出后 6 小时内免挑战。
     */
    private void solveChallenge(String html) throws Exception {
        java.util.List<String> parts = new java.util.ArrayList<String>();
        int idx = 0;
        while (true) {
            int p = html.indexOf("toNumbers(\"", idx);
            if (p < 0) {
                break;
            }
            int start = p + "toNumbers(\"".length();
            int end = html.indexOf("\"", start);
            if (end < 0) {
                break;
            }
            parts.add(html.substring(start, end));
            idx = end;
        }
        if (parts.size() < 3) {
            throw new IllegalStateException("challenge parse failed");
        }
        byte[] key = hexToBytes(parts.get(0));
        byte[] iv = hexToBytes(parts.get(1));
        byte[] ct = hexToBytes(parts.get(2));
        byte[] plain = AesCbc.decrypt(key, iv, ct);
        cookies.put("__test", toHex(plain));
    }

    private static byte[] hexToBytes(String s) {
        int len = s.length() / 2;
        byte[] out = new byte[len];
        for (int i = 0; i < len; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    // ---------------------------------------------------------------- 设备标识

    /**
     * 用 ANDROID_ID 做设备指纹。同一设备重装应用保持不变，
     * 恢复出厂/换机才变化，正好对应「同一台机器」的语义。
     */
    private String buildDeviceId() {
        String androidId = Settings.Secure.getString(context.getContentResolver(), Settings.Secure.ANDROID_ID);
        if (androidId == null || androidId.length() < 6) {
            androidId = "fallback-" + android.os.Build.FINGERPRINT;
        }
        return "a" + Integer.toHexString(androidId.hashCode()) + "-" + androidId.substring(0, Math.min(8, androidId.length()));
    }

    private String readVersionName() {
        try {
            return context.getPackageManager().getPackageInfo(context.getPackageName(), 0).versionName;
        } catch (Exception e) {
            return "0";
        }
    }

    private static String newNonce() {
        byte[] buf = new byte[16];
        new SecureRandom().nextBytes(buf);
        return toHex(buf);
    }

    // ---------------------------------------------------------------- 结果

    public static final class Result {
        public final boolean ok;
        public final String error;
        public final String message;
        public final String plan;
        public final String[] features;
        public final long expireAt;

        private Result(boolean ok, String error, String message, String plan, String[] features, long expireAt) {
            this.ok = ok;
            this.error = error;
            this.message = message;
            this.plan = plan;
            this.features = features;
            this.expireAt = expireAt;
        }

        static Result ok(String plan, String[] features, long expireAt) {
            return new Result(true, "", "", plan, features, expireAt);
        }

        static Result fail(String error, String message) {
            return new Result(false, error, message, "", new String[0], -1);
        }
    }
}
