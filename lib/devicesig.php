<?php
declare(strict_types=1);

/**
 * 设备专属密钥：首次激活时客户端生成 ECDSA P-256 密钥对，
 * 只把公钥上传；之后的每个请求都用自己的私钥签名。
 *
 * 好处是 APK 里不存在任何共享密钥，逆向拿不到「万能钥匙」，
 * 泄漏只影响单台设备。它挡不住别人为自己那台新设备合法注册，
 * 真正的授权裁决仍在服务端（卡密状态、设备上限、功能列表）。
 */

// 签名覆盖的内容：动作 + 设备标识 + 时间戳 + nonce，防止换动作或换设备复用
function device_sign_base(string $action, string $deviceId, int $ts, string $nonce): string
{
    return $action . "\n" . $deviceId . "\n" . $ts . "\n" . $nonce;
}

function device_pubkey_fetch(string $deviceId): ?string
{
    $st = db()->prepare('SELECT pubkey FROM device_keys WHERE device_id = ? LIMIT 1');
    $st->execute([$deviceId]);
    $k = $st->fetchColumn();
    return $k === false ? null : (string)$k;
}

function device_pubkey_store(string $deviceId, string $pubkeyB64): bool
{
    try {
        db()->prepare('INSERT INTO device_keys (device_id, pubkey, created_at) VALUES (?,?,?)')
            ->execute([$deviceId, $pubkeyB64, time()]);
        return true;
    } catch (PDOException $e) {
        // 唯一键冲突说明该设备已注册过，不允许顶替公钥
        if ((string)$e->getCode() === '23000') {
            return false;
        }
        throw $e;
    }
}

function device_signature_valid(string $pubkeyB64, string $base, string $sigB64): bool
{
    $der = b64u_decode($pubkeyB64);
    if ($der === '') {
        return false;
    }
    $pem = "-----BEGIN PUBLIC KEY-----\n"
        . chunk_split(base64_encode($der), 64, "\n")
        . "-----END PUBLIC KEY-----\n";
    $key = openssl_pkey_get_public($pem);
    if ($key === false) {
        return false;
    }
    $sig = b64u_decode($sigB64);
    if ($sig === '') {
        return false;
    }
    return openssl_verify($base, $sig, $key, OPENSSL_ALGO_SHA256) === 1;
}

/**
 * 校验请求携带的设备签名。
 *
 * @param bool $allowRegister 激活时允许首次注册公钥；复验时必须已注册
 */
function device_require_signed(array $body, string $action, string $deviceId, int $ts, string $nonce, bool $allowRegister = false): void
{
    $pubkey = field($body, 'pubkey', 512);
    $sig = field($body, 'sig', 512);
    if ($sig === '') {
        fail('missing_signature', '请求未签名');
    }

    $stored = device_pubkey_fetch($deviceId);
    if ($stored === null) {
        if (!$allowRegister || $pubkey === '') {
            fail('device_unknown', '该设备未注册密钥', 403);
        }
        if (!device_signature_valid($pubkey, device_sign_base($action, $deviceId, $ts, $nonce), $sig)) {
            fail('bad_signature', '设备签名无效', 403);
        }
        if (!device_pubkey_store($deviceId, $pubkey)) {
            // 并发注册：回读已存的公钥再验一次
            $stored = device_pubkey_fetch($deviceId);
            if ($stored === null || !device_signature_valid($stored, device_sign_base($action, $deviceId, $ts, $nonce), $sig)) {
                fail('bad_signature', '设备密钥注册冲突', 403);
            }
        }
        return;
    }

    if (!device_signature_valid($stored, device_sign_base($action, $deviceId, $ts, $nonce), $sig)) {
        fail('bad_signature', '设备签名无效', 403);
    }
}
