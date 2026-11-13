<?php
declare(strict_types=1);

// 登录失败限流：同一 IP 与同一账号各自计数，1 小时窗口。
// 计数落在 session 之外，避免清 cookie 绕过。
function admin_attempt_log(string $result): void
{
    try {
        db()->prepare('INSERT INTO admin_attempts (ip, username, result, created_at) VALUES (?,?,?,?)')
            ->execute([client_ip(), field($_POST, 'user', 64), $result, time()]);
    } catch (Throwable $e) {
        // 记录失败不阻断登录流程
    }
}

function admin_attempt_count(string $where, array $args): int
{
    $st = db()->prepare('SELECT COUNT(*) FROM admin_attempts WHERE result = ? AND created_at > ? AND ' . $where);
    $st->execute(array_merge(['fail', time() - 3600], $args));
    return (int)$st->fetchColumn();
}

// 账密任一正确即通过，否则返回等待秒数
function admin_login_throttle(): int
{
    $ipFails = admin_attempt_count('ip = ?', [client_ip()]);
    $userFails = admin_attempt_count('username = ?', [field($_POST, 'user', 64)]);
    $fails = max($ipFails, $userFails);
    if ($fails < 5) {
        return 0;
    }
    if ($fails >= 15) {
        return 3600;
    }
    return min(3600, 60 * ($fails - 4));
}

function admin_attempt_cleanup(): void
{
    if (random_int(1, 20) === 1) {
        db()->prepare('DELETE FROM admin_attempts WHERE created_at < ?')->execute([time() - 86400]);
    }
}
