<?php
declare(strict_types=1);

/**
 * 设备特征绑定。
 *
 * 客户端在激活时上报一组「这台机器才有」的特征，服务端固化后，
 * 每次拉取功能数据都要重新比对。目的是挡住两类破解：
 *
 *   1. 把已激活的数据包连同设备密钥一起拷到另一台机器
 *   2. 改设备标识绕过设备上限
 *
 * 注意：这些特征客户端都能伪造，服务端只能校验「前后一致」，
 * 不能证明「这是真机」。它能防迁移与批量，防不住从头伪造一台。
 */

/**
 * 计算特征摘要。boot_id 每次开机都变，只参与同一开机周期内的比对，
 * 不写入固化记录——否则用户重启一次就要重新激活。
 */
function fp_digest(array $fp): string
{
    $parts = [];
    foreach (['model', 'brand', 'device', 'product', 'board', 'hardware'] as $k) {
        $parts[] = trim((string)($fp[$k] ?? ''));
    }
    return hash('sha256', implode('|', $parts));
}

function device_fp_schema(): string
{
    return "CREATE TABLE IF NOT EXISTS device_fp (
        id         INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
        device_id  VARCHAR(64)  NOT NULL,
        digest     CHAR(64)     NOT NULL,
        boot_id    VARCHAR(64)  NOT NULL DEFAULT '',
        first_ip   VARCHAR(45)  NOT NULL DEFAULT '',
        last_ip    VARCHAR(45)  NOT NULL DEFAULT '',
        mismatch   INT UNSIGNED NOT NULL DEFAULT 0,
        created_at INT UNSIGNED NOT NULL,
        seen_at    INT UNSIGNED NOT NULL,
        UNIQUE KEY uk_device (device_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";
}

/**
 * 比对并更新设备特征。
 *
 * @return array [是否通过, 原因]
 */
function device_fp_check(string $deviceId, array $fp): array
{
    try {
        db()->exec(device_fp_schema());
    } catch (Throwable $e) {
        // 建表失败不应阻断主流程
        return [true, 'schema_unavailable'];
    }

    $digest = fp_digest($fp);
    $bootId = substr((string)($fp['boot_id'] ?? ''), 0, 64);
    $ip = client_ip();
    $now = time();

    $st = db()->prepare('SELECT * FROM device_fp WHERE device_id = ? LIMIT 1');
    $st->execute([$deviceId]);
    $row = $st->fetch();

    if ($row === false) {
        db()->prepare('INSERT INTO device_fp (device_id, digest, boot_id, first_ip, last_ip, created_at, seen_at)
                       VALUES (?,?,?,?,?,?,?)')
            ->execute([$deviceId, $digest, $bootId, $ip, $ip, $now, $now]);
        return [true, 'registered'];
    }

    if (!hash_equals((string)$row['digest'], $digest)) {
        // 硬件特征变化：可能是换机、系统升级，或伪造
        db()->prepare('UPDATE device_fp SET mismatch = mismatch + 1, last_ip = ?, seen_at = ? WHERE device_id = ?')
            ->execute([$ip, $now, $deviceId]);
        $mismatch = (int)$row['mismatch'] + 1;
        if ($mismatch >= 3) {
            return [false, 'fp_mismatch'];
        }
        // 前两次容忍：系统升级可能改变 Build 字段
        return [true, 'fp_mismatch_tolerated'];
    }

    db()->prepare('UPDATE device_fp SET last_ip = ?, boot_id = ?, seen_at = ? WHERE device_id = ?')
        ->execute([$ip, $bootId, $now, $deviceId]);
    return [true, 'ok'];
}

/**
 * 同一设备在极短时间内从多个 IP 使用 —— 典型的「一份数据多人用」。
 *
 * @return int 最近 10 分钟内出现过的不同 IP 数
 */
function device_ip_spread(string $deviceId, int $windowSec = 600): int
{
    try {
        $st = db()->prepare('SELECT COUNT(DISTINCT ip) FROM api_log WHERE device_id = ? AND created_at > ?');
        $st->execute([$deviceId, time() - $windowSec]);
        return (int)$st->fetchColumn();
    } catch (Throwable $e) {
        return 0;
    }
}
