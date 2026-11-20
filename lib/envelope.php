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

// 当前请求的会话密钥，用于加密响应；由 envelope_read_request 填入
$GLOBALS['ENV_SESSION_KEY'] = null;


function envelope_session_key(): string
{
    $k = $GLOBALS['ENV_SESSION_KEY'];
    if (!is_string($k) || strlen($k) !== 32) {
        throw new RuntimeException('no_session_key');
    }
    return $k;
}

/** 读取并校验请求信封（时间戳 + 动作），失败直接返回加密错误响应 */
function envelope_read_request(string $expectAction): array
{
    $body = request_body();

    if (!is_array($body) || !isset($body['epk'])) {
        // 用固定密钥无法加密错误响应，直接返回明文错误码
        json_out(['ok' => false, 'error' => 'bad_envelope', 'msg' => '请求必须加密'], 400);
    }

    try {
        [$plain, $sessionKey] = ecies_open_request($body);
        $GLOBALS['ENV_SESSION_KEY'] = $sessionKey;
    } catch (RuntimeException $e) {
        json_out(['ok' => false, 'error' => 'bad_envelope', 'msg' => '请求无法解密'], 400);
    }

    $data = json_decode($plain, true);
    if (!is_array($data)) {
        envelope_fail('bad_json', '请求内容无效');
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
    // 会话密钥缺失时（如明文探测请求）退回明文错误，避免 500
    if (!is_string($GLOBALS['ENV_SESSION_KEY']) || strlen($GLOBALS['ENV_SESSION_KEY']) !== 32) {
        json_out($payload, $status);
    }
    json_out(ecies_seal_response($payload, $GLOBALS['ENV_SESSION_KEY']), $status);
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


// ============================================================ ECIES（非对称加密）
//
// 不再使用任何预置对称密钥。每次请求都用 ECDH 临时协商出会话密钥：
//
//   客户端：生成临时 EC 密钥对 (e_priv, e_pub)
//           shared = ECDH(e_priv, server_pub)          ← 服务器公钥，客户端只持有公钥
//           key    = HKDF-SHA256(shared, salt=nonce)
//           ct     = AES-256-GCM(key, iv, plaintext)
//           发送 { epk: e_pub, salt: nonce, iv, ct, tag }
//
//   服务端：shared = ECDH(server_priv, epk)
//           key    = HKDF-SHA256(shared, salt)
//           解密 ct
//
// 抓包者只能看到临时公钥 epk，没有服务器私钥就推不出 shared，
// 因此这是真正的非对称加密，而不是把对称密钥硬塞进客户端。

const EC_PUB_DER_PREFIX = '3059301306072a8648ce3d020106082a8648ce3d030107034200';

/** 把 65 字节 SEC1 未压缩点转成 OpenSSLPKey 可用的 PEM */
function ec_sec1_to_pem(string $sec1): string
{
    $der = hex2bin(EC_PUB_DER_PREFIX) . $sec1;
    return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
}

/** 从配置取服务端 EC 私钥资源 */
function ec_server_key()
{
    global $CONFIG;
    $key = openssl_pkey_get_private($CONFIG['ec_priv']);
    if ($key === false) {
        throw new RuntimeException('ec_priv_invalid');
    }
    return $key;
}

function ec_server_pub_sec1(): string
{
    $d = openssl_pkey_get_details(ec_server_key());
    return "\x04" . $d['ec']['x'] . $d['ec']['y'];
}

/** ECDH + HKDF 派生会话密钥；返回 [encKey(32), macKey(32)] */
function ecies_derive(string $shared, string $salt): array
{
    $okm = hash_hkdf('sha256', $shared, 64, 'kami-v1', $salt);
    return [substr($okm, 0, 32), substr($okm, 32, 32)];
}

/**
 * 解密客户端请求。返回 [明文 JSON 字符串, 会话密钥对]。
 * 会话密钥对用于给响应加密。
 */
function ecies_open_request(array $env): array
{
    $epk = b64u_decode((string)($env['epk'] ?? ''));
    $salt = b64u_decode((string)($env['salt'] ?? ''));
    $iv = b64u_decode((string)($env['iv'] ?? ''));
    $ct = b64u_decode((string)($env['ct'] ?? ''));
    $tag = b64u_decode((string)($env['tag'] ?? ''));

    if (strlen($epk) !== 65 || $epk[0] !== "\x04" || strlen($salt) < 8
        || strlen($iv) !== 12 || $ct === '' || strlen($tag) !== 16) {
        throw new RuntimeException('ecies_bad_fields');
    }

    $peerPem = ec_sec1_to_pem($epk);
    $peer = openssl_pkey_get_public($peerPem);
    if ($peer === false) {
        throw new RuntimeException('ecies_bad_epk');
    }
    $shared = openssl_pkey_derive($peer, ec_server_key());
    if ($shared === false || strlen($shared) === 0) {
        throw new RuntimeException('ecies_derive_failed');
    }

    [$encKey] = ecies_derive($shared, $salt);
    $plain = openssl_decrypt($ct, 'aes-256-gcm', $encKey, OPENSSL_RAW_DATA, $iv, $tag);
    if ($plain === false) {
        throw new RuntimeException('ecies_decrypt_failed');
    }
    return [$plain, $encKey];
}

/** 用请求协商出的会话密钥加密响应 */
function ecies_seal_response(array $payload, string $sessionKey): array
{
    global $CONFIG;
    $iv = random_bytes(12);
    $json = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    $tag = '';
    $ct = openssl_encrypt($json, 'aes-256-gcm', $sessionKey, OPENSSL_RAW_DATA, $iv, $tag);
    if ($ct === false) {
        throw new RuntimeException('ecies_seal_failed');
    }

    // 对 iv|ct|tag 的原始字节签名。客户端先验签再解密，
    // 因此即便攻击者拿到会话密钥（例如 TLS 被破），也造不出合法响应。
    $key = openssl_pkey_get_private($CONFIG['sign_key']);
    if ($key === false) {
        throw new RuntimeException('sign_key_invalid');
    }
    $sig = '';
    if (!openssl_sign($iv . $ct . $tag, $sig, $key, OPENSSL_ALGO_SHA256)) {
        throw new RuntimeException('seal_sign_failed');
    }

    return [
        'iv'  => b64u_encode($iv),
        'ct'  => b64u_encode($ct),
        'tag' => b64u_encode($tag),
        's'   => b64u_encode($sig),
    ];
}
