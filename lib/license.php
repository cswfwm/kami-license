<?php
declare(strict_types=1);

// 许可证签发：payload 为 JSON 的 base64url，签名为 ECDSA P-256/SHA-256 的 DER 编码。
// 客户端只内置公钥，故无法伪造；私钥保存在 _data/private_key.pem（.htaccess 拒绝访问）。
function license_sign(array $payload): array
{
    global $CONFIG;
    $b64 = b64u_encode(json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
    $key = openssl_pkey_get_private($CONFIG['sign_key']);
    if ($key === false) {
        throw new RuntimeException('sign_key_invalid');
    }
    $sig = '';
    if (!openssl_sign($b64, $sig, $key, OPENSSL_ALGO_SHA256)) {
        throw new RuntimeException('sign_failed');
    }
    return ['payload' => $b64, 'sig' => b64u_encode($sig)];
}

function license_payload(array $card, array $device): array
{
    global $CONFIG;
    $features = json_decode((string)$card['features'], true);
    if (!is_array($features)) {
        $features = [];
    }
    $expire = $card['expire_at'] !== null ? (int)$card['expire_at'] : null;
    return [
        'v'           => 1,
        'card'        => (int)$card['id'],
        'mask'        => (string)$card['code_mask'],
        'plan'        => (string)$card['plan'],
        'features'    => array_values($features),
        'device'      => (string)$device['device_id'],
        'issued_at'   => time(),
        'expire_at'   => $expire,
        // 离线宽限期：到期后仍允许离线使用一段时间，之后必须联网复验
        'grace_until' => $expire === null ? null : $expire + 86400 * (int)($CONFIG['grace_days'] ?? 3),
    ];
}

// 卡密去掉易混淆字符（0/O、1/I），分组便于人工抄写
function card_code_generate(): string
{
    $alphabet = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
    $max = strlen($alphabet) - 1;
    $groups = [];
    for ($g = 0; $g < 4; $g++) {
        $s = '';
        for ($i = 0; $i < 4; $i++) {
            $s .= $alphabet[random_int(0, $max)];
        }
        $groups[] = $s;
    }
    return implode('-', $groups);
}

function card_normalize(string $code): string
{
    return strtoupper(preg_replace('/[^A-Za-z0-9]/', '', $code) ?? '');
}

function card_hash(string $code): string
{
    return hash('sha256', card_normalize($code));
}

function card_mask(string $code): string
{
    $n = card_normalize($code);
    return substr($n, 0, 4) . '-****-****-' . substr($n, -4);
}
