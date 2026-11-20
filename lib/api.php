<?php
declare(strict_types=1);

function api_log(?int $cardId, string $action, string $result, string $deviceId): void
{
    try {
        db()->prepare('INSERT INTO api_log (card_id, action, result, device_id, ip, ua, created_at) VALUES (?,?,?,?,?,?,?)')
            ->execute([$cardId, $action, $result, $deviceId, client_ip(), client_ua(), time()]);
    } catch (Throwable $e) {
        // 记日志失败不应影响主流程
    }
}

function fail(string $code, string $msg, int $status = 400, array $extra = [], ?int $logCardId = null, ?string $logDevice = null): void
{
    if (db()->inTransaction()) {
        db()->rollBack();
    }
    if ($logCardId !== null) {
        api_log($logCardId, 'activate', $code, (string)$logDevice);
    }
    envelope_reply(array_merge(['ok' => false, 'error' => $code, 'msg' => $msg], $extra), $status);
}

// 同一 IP 一小时内失败次数上限，用于限制撞库与试卡
function throttle_ok(string $action, int $limit = 30): bool
{
    $st = db()->prepare('SELECT COUNT(*) FROM api_log WHERE ip = ? AND action = ? AND result <> ? AND created_at > ?');
    $st->execute([client_ip(), $action, 'ok', time() - 3600]);
    return (int)$st->fetchColumn() < $limit;
}

function find_card(string $code): ?array
{
    $st = db()->prepare('SELECT * FROM cards WHERE code_hash = ? LIMIT 1');
    $st->execute([card_hash($code)]);
    $row = $st->fetch();
    return $row === false ? null : $row;
}

function card_is_expired(array $card): bool
{
    return $card['expire_at'] !== null && (int)$card['expire_at'] <= time();
}

function active_device_count(int $cardId): int
{
    // 激活流程在事务中调用，必须复用同一连接才能看到锁内的最新数据
    $st = db()->prepare('SELECT COUNT(*) FROM devices WHERE card_id = ? AND revoked = 0');
    $st->execute([$cardId]);
    return (int)$st->fetchColumn();
}

// 防重放：同一卡密的同一 nonce 只接受一次
function nonce_claim(int $cardId, string $nonce): bool
{
    $now = time();
    try {
        db()->prepare('INSERT INTO nonces (card_id, nonce, used_at) VALUES (?,?,?)')
            ->execute([$cardId, $nonce, $now]);
    } catch (PDOException $e) {
        if ((string)$e->getCode() === '23000') {
            return false;
        }
        throw $e;
    }
    // 抽签清理过期 nonce，避免表无限增长
    if (random_int(1, 50) === 1) {
        db()->prepare('DELETE FROM nonces WHERE used_at < ?')->execute([$now - 3600]);
    }
    return true;
}

function api_plans(): void
{
    envelope_read_request('plans');
    $out = [];
    foreach (plan_catalog() as $key => $p) {
        $out[] = [
            'plan'     => $key,
            'label'    => $p['label'],
            'desc'     => $p['desc'],
            'days'     => $p['days'],
            'devices'  => $p['devices'],
            'features' => $p['features'],
        ];
    }
    envelope_reply(['ok' => true, 'plans' => $out, 'server_time' => time()]);
}

function api_activate(): void
{
    $body = envelope_read_request('activate');
    $code       = field($body, 'code', 64);
    $deviceId   = field($body, 'device_id', 64);
    $deviceName = field($body, 'device_name', 64);
    $appVersion = field($body, 'app_version', 32);
    $nonce      = field($body, 'nonce', 64);
    $ts         = (int)($body['ts'] ?? 0);

    if ($code === '' || $deviceId === '') {
        fail('bad_request', '缺少卡密或设备标识');
    }
    if (strlen($deviceId) < 6) {
        fail('bad_device', '设备标识过短');
    }
    if ($ts <= 0 || abs(time() - $ts) > 600 || strlen($nonce) < 16) {
        fail('bad_timestamp', '请求缺少有效时间戳与 nonce', 400, ['server_time' => time()]);
    }
    device_require_signed($body, 'activate', $deviceId, $ts, $nonce, true);

    // 固化设备特征，后续每次取数据都要比对
    [$fpOk, $fpReason] = device_fp_check($deviceId, is_array($body['fp'] ?? null) ? $body['fp'] : []);
    if (!$fpOk) {
        api_log(null, 'activate', 'fp_mismatch', $deviceId);
        fail('fp_mismatch', '设备特征与首次激活不一致', 403);
    }
    if (!throttle_ok('activate')) {
        api_log(null, 'activate', 'throttled', $deviceId);
        fail('too_many', '尝试次数过多，请稍后再试', 429);
    }

    $card = find_card($code);
    if ($card === null) {
        api_log(null, 'activate', 'not_found', $deviceId);
        fail('invalid_code', '卡密不存在');
    }
    $cardId = (int)$card['id'];

    // 签名已保证请求不可篡改，此处再拦一次重放
    if (!nonce_claim($cardId, $nonce)) {
        api_log($cardId, 'activate', 'replay', $deviceId);
        fail('replay', '重复请求被拒绝', 409);
    }

    if ($card['status'] === 'disabled') {
        api_log($cardId, 'activate', 'disabled', $deviceId);
        fail('disabled', '卡密已被停用', 403);
    }
    if (card_is_expired($card)) {
        api_log($cardId, 'activate', 'expired', $deviceId);
        fail('expired', '卡密已过期', 403);
    }

    // 激活必须整体串行：并发请求会同时通过「设备数检查」，导致超额绑定。
    // 用卡密行锁把「查设备 / 插设备 / 更新卡密」纳入同一事务。
    $pdo = db();
    $pdo->beginTransaction();
    try {
        $lock = $pdo->prepare('SELECT * FROM cards WHERE id = ? FOR UPDATE');
        $lock->execute([$cardId]);
        $card = $lock->fetch();
        if ($card === false) {
            $pdo->rollBack();
            fail('invalid_code', '卡密不存在');
        }

        $st = $pdo->prepare('SELECT * FROM devices WHERE card_id = ? AND device_id = ? LIMIT 1');
        $st->execute([$cardId, $deviceId]);
        $device = $st->fetch();

        if ($device !== false && (int)$device['revoked'] === 1) {
            fail('device_revoked', '该设备已被管理员解绑', 403, [], $cardId, $deviceId);
        }

        $now = time();
        if ($device === false) {
            if (active_device_count($cardId) >= (int)$card['max_devices']) {
                fail('device_limit', '该卡密已达设备数上限', 403, [], $cardId, $deviceId);
            }
            $pdo->prepare('INSERT INTO devices (card_id, device_id, device_name, app_version, first_ip, last_ip, first_seen, last_seen) VALUES (?,?,?,?,?,?,?,?)')
                ->execute([$cardId, $deviceId, $deviceName, $appVersion, client_ip(), client_ip(), $now, $now]);
            $device = ['id' => (int)$pdo->lastInsertId(), 'device_id' => $deviceId];
        } else {
            $pdo->prepare('UPDATE devices SET last_seen = ?, last_ip = ? WHERE id = ?')
                ->execute([$now, client_ip(), (int)$device['id']]);
        }

        if ($card['status'] === 'unused') {
            $expireAt = (int)$card['duration_days'] > 0 ? $now + (int)$card['duration_days'] * 86400 : null;
            $pdo->prepare('UPDATE cards SET status = ?, activated_at = ?, expire_at = ? WHERE id = ?')
                ->execute(['active', $now, $expireAt, $cardId]);
            $card['status'] = 'active';
            $card['expire_at'] = $expireAt;
        }
        $pdo->commit();
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        api_log($cardId, 'activate', 'error', $deviceId);
        fail('server_error', '服务端繁忙，请重试', 500);
    }

    $license = license_sign(license_payload($card, $device));
    api_log($cardId, 'activate', 'ok', $deviceId);
    $payload = json_decode(b64u_decode($license['payload']), true) ?: [];
    $featureData = epoch_data_issue($payload, $license['sig'], $deviceId);
    envelope_reply([
        'ok' => true,
        'license' => $license['payload'],
        'sig' => $license['sig'],
        'data' => $featureData,
        'server_time' => $now,
    ]);
}

function api_verify(): void
{
    // 先只看信封，取出设备标识后再回验内层 device 与外层一致
    $body = envelope_read_request('verify');
    $code     = field($body, 'code', 64);
    $deviceId = field($body, 'device_id', 64);
    $nonce    = field($body, 'nonce', 64);
    $ts       = (int)($body['ts'] ?? 0);

    if ($code === '' || $deviceId === '' || $nonce === '') {
        fail('bad_request', '参数不完整');
    }
    if (strlen($nonce) < 16 || !preg_match('/^[A-Za-z0-9_-]+$/', $nonce)) {
        fail('bad_nonce', 'nonce 无效');
    }
    if ($ts <= 0 || abs(time() - $ts) > 600) {
        fail('bad_timestamp', '设备时间偏差过大', 400, ['server_time' => time()]);
    }
    device_require_signed($body, 'verify', $deviceId, $ts, $nonce);

    [$fpOk, $fpReason] = device_fp_check($deviceId, is_array($body['fp'] ?? null) ? $body['fp'] : []);
    if (!$fpOk) {
        api_log(null, 'verify', 'fp_mismatch', $deviceId);
        fail('fp_mismatch', '设备特征与首次激活不一致', 403);
    }

    // 同一设备短时间内来自多个 IP：一份授权被多人共用
    if (device_ip_spread($deviceId) > 3) {
        api_log(null, 'verify', 'ip_spread', $deviceId);
        fail('ip_spread', '该设备正被多个网络同时使用', 403);
    }
    if (!throttle_ok('verify')) {
        api_log(null, 'verify', 'throttled', $deviceId);
        fail('too_many', '请求过于频繁', 429);
    }

    $card = find_card($code);
    if ($card === null) {
        api_log(null, 'verify', 'not_found', $deviceId);
        fail('invalid_code', '卡密不存在');
    }
    $cardId = (int)$card['id'];

    if (!nonce_claim($cardId, $nonce)) {
        api_log($cardId, 'verify', 'replay', $deviceId);
        fail('replay', '重复请求被拒绝', 409);
    }

    if ($card['status'] === 'disabled') {
        api_log($cardId, 'verify', 'disabled', $deviceId);
        fail('disabled', '卡密已被停用', 403);
    }
    if (card_is_expired($card)) {
        api_log($cardId, 'verify', 'expired', $deviceId);
        fail('expired', '卡密已过期', 403);
    }

    $st = db()->prepare('SELECT * FROM devices WHERE card_id = ? AND device_id = ? LIMIT 1');
    $st->execute([$cardId, $deviceId]);
    $device = $st->fetch();
    if ($device === false) {
        api_log($cardId, 'verify', 'device_mismatch', $deviceId);
        fail('device_mismatch', '该设备未激活此卡密', 403);
    }
    if ((int)$device['revoked'] === 1) {
        api_log($cardId, 'verify', 'device_revoked', $deviceId);
        fail('device_revoked', '该设备已被解绑', 403);
    }

    $now = time();
    db()->prepare('UPDATE devices SET last_seen = ?, last_ip = ? WHERE id = ?')
        ->execute([$now, client_ip(), (int)$device['id']]);

    $license = license_sign(license_payload($card, $device));
    api_log($cardId, 'verify', 'ok', $deviceId);
    $payload = json_decode(b64u_decode($license['payload']), true) ?: [];
    $featureData = epoch_data_issue($payload, $license['sig'], $deviceId);
    envelope_reply([
        'ok' => true,
        'license' => $license['payload'],
        'sig' => $license['sig'],
        'data' => $featureData,
        'server_time' => $now,
    ]);
}

/**
 * 返回服务端 EC 公钥。公钥本就内置在客户端，此处仅为公钥轮换预留。
 * 不再提供明文分支：请求同样要加密，避免攻击者零成本探测。
 * 不返回指纹，减少站点身份特征。
 */
function api_key(): void
{
    envelope_read_request('key');
    envelope_reply([
        'ok' => true,
        'pubkey' => b64u_encode(ec_server_pub_sec1()),
        'server_time' => time(),
    ]);
}

/**
 * 单独拉取功能数据。需要有效 license + 设备已绑定。
 * 客户端按 ttl 定时刷新，服务端关停或换私服就拿不到可用数据。
 */
function api_data(): void
{
    $body = envelope_read_request('data');
    $deviceId = field($body, 'device_id', 64);
    $licenseB64 = field($body, 'license', 2048);
    $sig = field($body, 'sig', 512);
    $nonce = field($body, 'nonce', 64);
    $ts = (int)($body['ts'] ?? 0);

    if ($deviceId === '' || $licenseB64 === '' || $sig === '') {
        fail('bad_request', '参数不完整');
    }
    device_require_signed($body, 'data', $deviceId, $ts, $nonce);

    [$fpOk, $fpReason] = device_fp_check($deviceId, is_array($body['fp'] ?? null) ? $body['fp'] : []);
    if (!$fpOk) {
        fail('fp_mismatch', '设备特征与首次激活不一致', 403);
    }

    // 同一设备短时间内从多个 IP 拉数据：一份数据被多人共用
    if (device_ip_spread($deviceId) > 3) {
        api_log(null, 'data', 'ip_spread', $deviceId);
        fail('ip_spread', '该设备正被多个网络同时使用', 403);
    }

    $payload = json_decode(b64u_decode($licenseB64), true);
    if (!is_array($payload) || ($payload['device'] ?? '') !== $deviceId) {
        fail('device_mismatch', '许可证与设备不匹配', 403);
    }

    // license 必须由本服务端签发，否则拒绝下发数据
    $pub = openssl_pkey_get_public("-----BEGIN PUBLIC KEY-----\n"
        . chunk_split(base64_encode(openssl_pkey_get_details(
            openssl_pkey_get_private($GLOBALS['CONFIG']['sign_key']))['key']), 64, "\n")
        . "-----END PUBLIC KEY-----\n");
    if ($pub === false || openssl_verify($licenseB64, b64u_decode($sig), $pub, OPENSSL_ALGO_SHA256) !== 1) {
        fail('bad_signature', '许可证无效', 403);
    }

    // 卡密当前状态仍然有效才发数据（可随时停用）
    $st = db()->prepare('SELECT c.* FROM devices d JOIN cards c ON c.id = d.card_id
                         WHERE d.device_id = ? AND d.revoked = 0 LIMIT 1');
    $st->execute([$deviceId]);
    $card = $st->fetch();
    if ($card === false) {
        fail('device_unknown', '设备未绑定有效卡密', 403);
    }
    if ($card['status'] === 'disabled') {
        fail('disabled', '卡密已被停用', 403);
    }
    if (card_is_expired($card)) {
        fail('expired', '卡密已过期', 403);
    }

    envelope_reply([
        'ok' => true,
        'data' => epoch_data_issue($payload, $sig, $deviceId),
        'server_time' => time(),
    ]);
}

function api_dispatch(): void
{
    $action = strtolower((string)($_GET['action'] ?? ''));
    if (!schema_ready()) {
        fail('not_initialized', '服务端尚未初始化，请先运行 install.php', 503);
    }
    switch ($action) {
        case 'key':
            api_key();
            break;
        case 'plans':
            api_plans();
            break;
        case 'activate':
            api_activate();
            break;
        case 'verify':
            api_verify();
            break;
        case 'data':
            api_data();
            break;
        default:
            fail('unknown_action', '未知接口', 404);
    }
}
