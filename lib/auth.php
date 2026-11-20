<?php
declare(strict_types=1);

function admin_session_start(): void
{
    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_set_cookie_params(['httponly' => true, 'samesite' => 'Lax', 'secure' => !empty($_SERVER['HTTPS'])]);
        session_name('KAMISID');
        session_start();
    }
}

function admin_logged_in(): bool
{
    admin_session_start();
    return !empty($_SESSION['admin']);
}

function admin_require_login(): void
{
    if (!admin_logged_in()) {
        header('Location: ?p=login');
        exit;
    }
}

function admin_csrf(): string
{
    admin_session_start();
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(16));
    }
    return $_SESSION['csrf'];
}

function admin_check_csrf(): void
{
    if (!hash_equals(admin_csrf(), (string)($_POST['csrf'] ?? ''))) {
        http_response_code(400);
        exit('CSRF 校验失败');
    }
}

function admin_login_attempt(string $user, string $pass): bool
{
    global $CONFIG;
    // 每次登录都做密码校验，避免通过响应时间判断用户名是否存在
    $ok = password_verify($pass, $CONFIG['admin']['pass_hash']);
    if (!hash_equals($CONFIG['admin']['user'], $user) || !$ok) {
        return false;
    }
    admin_session_start();
    session_regenerate_id(true);
    $_SESSION['admin'] = true;
    return true;
}

function h($s): string
{
    return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function ts_fmt($ts): string
{
    return ($ts === null || (int)$ts <= 0) ? '—' : date('Y-m-d H:i', (int)$ts);
}

function admin_flash(string $msg): void
{
    admin_session_start();
    $_SESSION['flash'] = $msg;
}

function admin_take_flash(): string
{
    admin_session_start();
    $m = (string)($_SESSION['flash'] ?? '');
    unset($_SESSION['flash']);
    return $m;
}
