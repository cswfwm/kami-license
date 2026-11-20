<?php
declare(strict_types=1);

/**
 * 功能数据下发。
 *
 * 思路：客户端只内置加密后的功能数据，解密它需要一把密钥，
 * 而这把密钥只能从服务端拿到。服务端换掉或消失，客户端就得不到可用数据。
 *
 * 每份功能数据的密钥由「license 签名 + 服务端私钥派生」生成，
 * 客户端无法自行构造——它只能拿着服务端给的密钥去解。
 *
 * 这解决的是「离线破解」：改本地文件没有意义，因为数据本身是加密的。
 */

/** 功能数据的加密密钥：由 license 签名派生，同一设备同一 license 恒定 */
function feature_data_key(string $licenseSig, string $deviceId): string
{
    global $CONFIG;
    // 用服务端私钥参与派生，客户端无从伪造
    $key = openssl_pkey_get_private($CONFIG['sign_key']);
    if ($key === false) {
        throw new RuntimeException('sign_key_invalid');
    }
    // 同上：ECDSA 签名不确定，改用 HMAC
    $secret = hash('sha256', (string)$CONFIG['sign_key'] . '|feature-secret-v1', true);
    return hash_hmac('sha256', 'feature-data-v1|' . $deviceId . '|' . $licenseSig, $secret, true);
}

/**
 * 为某设备生成一次性的功能数据下发包。
 *
 * 内容包含：
 *   - features  功能清单（与 license 一致）
 *   - payload   加密后的功能数据（客户端解密后才能用）
 *   - ttl       建议的有效期，过期需要重新拉取
 */
function feature_data_issue(array $licensePayload, string $licenseSig, string $deviceId): array
{
    $features = $licensePayload['features'] ?? [];
    $key = feature_data_key($licenseSig, $deviceId);

    // 功能数据本体。真实业务可换成配置、模板、素材等需要保密的内容。
    $body = json_encode([
        'features' => $features,
        'plan'     => $licensePayload['plan'] ?? '',
        'device'   => $deviceId,
        'issued_at'=> time(),
    ], JSON_UNESCAPED_UNICODE);

    $iv = random_bytes(12);
    $tag = '';
    $ct = openssl_encrypt($body, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
    if ($ct === false) {
        throw new RuntimeException('encrypt_failed');
    }

    return [
        'iv'  => b64u_encode($iv),
        'ct'  => b64u_encode($ct),
        'tag' => b64u_encode($tag),
        // 解密密钥随数据下发；客户端离开服务器就拿不到它
        'key' => bin2hex($key),
        // 客户端用这个指纹确认拿到的数据与自己的 license 匹配
        'bind' => substr(hash('sha256', $licenseSig . '|' . $deviceId), 0, 32),
        'ttl'  => 600,
    ];
}
