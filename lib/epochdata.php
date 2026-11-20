<?php
declare(strict_types=1);

/**
 * 数据分段轮换：让抓到的数据包自动失效。
 *
 * 问题：客户端一旦解密出功能数据，攻击者就能把它硬编码进破解版。
 * 加密本身挡不住「解密一次再复制」。
 *
 * 解法：功能数据按时间片（epoch）轮换。
 *   - 每个 epoch（默认 10 分钟）服务端生成一份新数据
 *   - 数据里绑定 epoch 编号与失效时间
 *   - 破解版硬编码的那份，最多活 20 分钟就失效
 *
 * 代价：必须联网。这是用可用性换安全性。
 */

/** epoch 长度（秒）。10 分钟意味着破解版最多再撑 20 分钟 */
const EPOCH_SECONDS = 600;

/** 当前 epoch 编号 */
function current_epoch(): int
{
    return intdiv(time(), EPOCH_SECONDS);
}

/**
 * epoch 内容密钥。
 *
 * 由「服务端私钥 + epoch 编号」派生，客户端无法预先计算未来 epoch 的密钥，
 * 因此不能一次性把所有 epoch 的数据都生成出来。
 */
function epoch_key(int $epoch): string
{
    global $CONFIG;
    // ECDSA 签名用随机 nonce，同一输入两次结果不同，不能用于派生。
    // 用私钥派生的密钥做 HMAC：结果确定，且同样需要私钥才能计算。
    $secret = hash('sha256', (string)$CONFIG['sign_key'] . '|epoch-secret-v1', true);
    return hash_hmac('sha256', 'epoch-key-v1|' . $epoch, $secret, true);
}

/**
 * 生成某个 epoch 的功能数据。
 * 内容除功能清单外，还包含 epoch 与失效时间，客户端据此判断是否过期。
 */
function epoch_data_issue(array $licensePayload, string $licenseSig, string $deviceId): array
{
    $epoch = current_epoch();
    $expire = ($epoch + 2) * EPOCH_SECONDS;  // 当前与下一个 epoch 有效

    $body = json_encode([
        'epoch'     => $epoch,
        'expire'    => $expire,
        'features'  => $licensePayload['features'] ?? [],
        'plan'      => $licensePayload['plan'] ?? '',
        'device'    => $deviceId,
        'issued_at' => time(),
    ], JSON_UNESCAPED_UNICODE);

    $key = epoch_key($epoch);
    $iv = random_bytes(12);
    $tag = '';
    $ct = openssl_encrypt($body, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
    if ($ct === false) {
        throw new RuntimeException('epoch_encrypt_failed');
    }

    return [
        'iv'     => b64u_encode($iv),
        'ct'     => b64u_encode($ct),
        'tag'    => b64u_encode($tag),
        'key'    => bin2hex($key),
        'epoch'  => $epoch,
        'expire' => $expire,
        'ttl'    => EPOCH_SECONDS,
    ];
}
