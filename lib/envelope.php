<?php
declare(strict_types=1);

/**
 * 双层信封。
 *
 * 请求（客户端 → 服务器）：
 *   内层明文 = { action, code, device, device_id, ts, nonce, pubkey, sig, ... }
 *   1. 内层明文加时间戳后 → AES-256-CBC(key1) + HMAC(key_m1)
 *   2. gzip 压缩
 *   3. 二次加密 AES-256-CBC(key2)
 *   4. 包成 {"e":"<b64url>"}
 *
 * 响应（服务器 → 客户端）：
 *   1. 业务 JSON → AES-256-CBC(key1) + HMAC(key_m1)
 *   2. gzip
 *   3. AES-256-CBC(key2)
 *   4. 用服务端 ECDSA 私钥对整个载荷签名 → {"e":"...","s":"..."}
 *
 * 客户端必须先验 ECDSA 签名再解密，因此伪造服务器即使知道对称密钥也无法
 * 让客户端接受其响应（它没有服务端私钥）。
 *
 * 对称密钥随 APK/EXE 分发，必然可被提取；它的作用是挡住随手抓包与批量脚本，
 * 真正的真伪判定由 ECDSA 签名承担。
 */

const ENVELOPE_SKEW = 600;

function env_keys(): array
{
    global $CONFIG;
    return [
        'k1'  => hex2bin($CONFIG['env_key1']),
        'm1'  => hex2bin($CONFIG['env_mac1']),
        'k2'  => hex2bin($CONFIG['env_key2']),
    ];
}

function env_aes_encrypt(string $plain, string $key): string
{
    $iv = random_bytes(16);
    $ct = openssl_encrypt($plain, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
    if ($ct === false) {
        throw new RuntimeException('aes_encrypt_failed');
    }
    return $iv . $ct;
}

function env_aes_decrypt(string $data, string $key): string
{
    if (strlen($data) < 32) {
        throw new RuntimeException('cipher_too_short');
    }
    $iv = substr($data, 0, 16);
    $ct = substr($data, 16);
    $plain = openssl_decrypt($ct, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
    if ($plain === false) {
        throw new RuntimeException('aes_decrypt_failed');
    }
    return $plain;
}

/** 内层加密：AES(key1) 后追加 HMAC(key_m1) */
function env_layer1_seal(string $plain): string
{
    $k = env_keys();
    $ct = env_aes_encrypt($plain, $k['k1']);
    return $ct . hash_hmac('sha256', $ct, $k['m1'], true);
}

function env_layer1_open(string $data): string
{
    $k = env_keys();
    if (strlen($data) < 32 + 32) {
        throw new RuntimeException('layer1_short');
    }
    $ct = substr($data, 0, -32);
    $tag = substr($data, -32);
    if (!hash_equals(hash_hmac('sha256', $ct, $k['m1'], true), $tag)) {
        throw new RuntimeException('layer1_bad_mac');
    }
    return env_aes_decrypt($ct, $k['k1']);
}

/** 外层加密：仅 AES(key2)，不压缩区分 */
function env_layer2_seal(string $data): string
{
    $k = env_keys();
    return env_aes_encrypt($data, $k['k2']);
}

function env_layer2_open(string $data): string
{
    $k = env_keys();
    return env_aes_decrypt($data, $k['k2']);
}

/** 请求解码：二次解密 → 解压 → 内层验 MAC 解密 → JSON */
function envelope_open_request(string $b64): array
{
    $raw = b64u_decode($b64);
    if ($raw === '') {
        throw new RuntimeException('empty_envelope');
    }
    $gzipped = env_layer2_open($raw);
    $plain = @gzdecode($gzipped);
    if ($plain === false) {
        throw new RuntimeException('bad_gzip');
    }
    $json = env_layer1_open($plain);
    $data = json_decode($json, true);
    if (!is_array($data)) {
        throw new RuntimeException('bad_json');
    }
    return $data;
}

/** 响应编码：内层加密 → gzip → 二次加密 → 服务端签名 */
function envelope_seal_response(array $payload): array
{
    global $CONFIG;
    $json = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    $inner = env_layer1_seal($json);
    $gzipped = gzencode($inner, 6);
    $outer = env_layer2_seal($gzipped);
    $b64 = b64u_encode($outer);

    $key = openssl_pkey_get_private($CONFIG['sign_key']);
    if ($key === false) {
        throw new RuntimeException('sign_key_invalid');
    }
    $sig = '';
    if (!openssl_sign($b64, $sig, $key, OPENSSL_ALGO_SHA256)) {
        throw new RuntimeException('response_sign_failed');
    }
    return ['e' => $b64, 's' => b64u_encode($sig)];
}

/** 读取并校验请求信封（时间戳 + 动作），失败直接返回加密错误响应 */
function envelope_read_request(string $expectAction): array
{
    $body = request_body();
    $env = $body['e'] ?? '';
    if (!is_string($env) || $env === '') {
        envelope_fail('bad_envelope', '请求格式不正确');
    }
    try {
        $data = envelope_open_request($env);
    } catch (RuntimeException $e) {
        envelope_fail('bad_envelope', '请求无法解析');
    }

    if (($data['action'] ?? '') !== $expectAction) {
        envelope_fail('bad_action', '动作不匹配');
    }
    $ts = (int)($data['ts'] ?? 0);
    if ($ts <= 0 || abs(time() - $ts) > ENVELOPE_SKEW) {
        envelope_fail('bad_timestamp', '设备时间偏差过大，请校准后重试', 400, ['server_time' => time()]);
    }
    if (strlen((string)($data['nonce'] ?? '')) < 16) {
        envelope_fail('bad_nonce', '缺少 nonce');
    }
    return $data;
}

function envelope_reply(array $payload, int $status = 200): void
{
    json_out(envelope_seal_response($payload), $status);
}

function envelope_fail(string $code, string $msg, int $status = 400, array $extra = []): void
{
    envelope_reply(array_merge([
        'ok' => false,
        'error' => $code,
        'msg' => $msg,
        'server_time' => time(),
    ], $extra), $status);
}
