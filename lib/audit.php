<?php
declare(strict_types=1);

/**
 * 后台操作审计。
 *
 * 后台一旦被攻破，攻击者能做的是「发卡、停卡、解绑设备」这类正常管理操作，
 * 单看数据分不出是他干的还是你干的。所以必须记录「谁、什么时候、从哪、做了什么」。
 *
 * 记录写库而非文件：主机 open_basedir 限制文件写入路径，且数据库更难被随手删除。
 */

function audit_schema(): string
{
    return "CREATE TABLE IF NOT EXISTS admin_audit (
        id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
        action     VARCHAR(32)  NOT NULL,
        target     VARCHAR(64)  NOT NULL DEFAULT '',
        detail     VARCHAR(255) NOT NULL DEFAULT '',
        ip         VARCHAR(45)  NOT NULL DEFAULT '',
        ua         VARCHAR(160) NOT NULL DEFAULT '',
        created_at INT UNSIGNED NOT NULL,
        KEY idx_created (created_at),
        KEY idx_action (action)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";
}

function audit_log(string $action, string $target = '', string $detail = ''): void
{
    static $ready = null;
    try {
        if ($ready === null) {
            db()->exec(audit_schema());
            $ready = true;
        }
        db()->prepare('INSERT INTO admin_audit (action, target, detail, ip, ua, created_at) VALUES (?,?,?,?,?,?)')
            ->execute([
                substr($action, 0, 32),
                substr($target, 0, 64),
                substr($detail, 0, 255),
                client_ip(),
                client_ua(),
                time(),
            ]);
    } catch (Throwable $e) {
        // 审计失败不能阻断业务，但要在日志里留下痕迹
        error_log('audit_failed: ' . $e->getMessage());
    }
}

/** 最近若干条审计记录，供后台页面展示 */
function audit_recent(int $limit = 100): array
{
    try {
        db()->exec(audit_schema());
        $st = db()->prepare('SELECT * FROM admin_audit ORDER BY id DESC LIMIT ?');
        $st->bindValue(1, $limit, PDO::PARAM_INT);
        $st->execute();
        return $st->fetchAll();
    } catch (Throwable $e) {
        return [];
    }
}

/** 检测异常：同一 IP 在短时间内大量敏感操作 */
function audit_suspicious(int $windowSec = 600, int $threshold = 30): array
{
    try {
        db()->exec(audit_schema());
        $st = db()->prepare('SELECT ip, COUNT(*) AS n FROM admin_audit
                             WHERE created_at > ? GROUP BY ip HAVING n >= ? ORDER BY n DESC LIMIT 10');
        $st->execute([time() - $windowSec, $threshold]);
        return $st->fetchAll();
    } catch (Throwable $e) {
        return [];
    }
}

/**
 * 数据完整性自检。
 *
 * 后台被入侵后，攻击者通常不会留下明显痕迹，但会在数据上暴露：
 *   - 短时间大量发卡
 *   - 卡密绑定设备数超过上限
 *   - 同一设备绑定多张有效卡
 *   - 非后台途径写入的记录（note 为空）
 */
function audit_integrity(): array
{
    $out = ['issues' => [], 'stats' => []];

    try {
        $st = db()->query('SELECT COUNT(*) FROM cards WHERE created_at > ' . (time() - 86400));
        $out['stats']['cards_24h'] = (int)$st->fetchColumn();

        $st = db()->query("SELECT COUNT(*) FROM cards WHERE created_at > " . (time() - 86400)
            . " AND note = ''");
        $noNote = (int)$st->fetchColumn();
        $out['stats']['cards_24h_no_note'] = $noNote;
        if ($noNote > 20) {
            $out['issues'][] = "最近 24 小时有 {$noNote} 张卡密无备注，可能是脚本直接写库";
        }

        $st = db()->query('SELECT c.code_mask, c.max_devices, COUNT(d.id) AS bound
                           FROM cards c LEFT JOIN devices d ON d.card_id = c.id AND d.revoked = 0
                           GROUP BY c.id HAVING bound > c.max_devices LIMIT 20');
        foreach ($st->fetchAll() as $r) {
            $out['issues'][] = "卡密 {$r['code_mask']} 绑定 {$r['bound']} 台，超过上限 {$r['max_devices']}";
        }

        $st = db()->query('SELECT device_id, COUNT(*) AS n FROM devices WHERE revoked = 0
                           GROUP BY device_id HAVING n > 3 LIMIT 20');
        foreach ($st->fetchAll() as $r) {
            $out['issues'][] = "设备 {$r['device_id']} 绑定了 {$r['n']} 张卡密";
        }
    } catch (Throwable $e) {
        $out['issues'][] = '自检执行失败：' . $e->getMessage();
    }

    return $out;
}
