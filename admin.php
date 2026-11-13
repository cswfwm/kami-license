<?php
declare(strict_types=1);
require __DIR__ . '/lib/bootstrap.php';
require __DIR__ . '/lib/auth.php';
require __DIR__ . '/lib/throttle.php';
require __DIR__ . '/lib/web/layout.php';

$page = (string)($_GET['p'] ?? 'dashboard');

if ($page === 'logout') {
    admin_session_start();
    $_SESSION = [];
    session_destroy();
    header('Location: ?p=login');
    exit;
}

if ($page === 'login') {
    $error = '';
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        admin_check_csrf();
        $wait = admin_login_throttle();
        if ($wait > 0) {
            http_response_code(429);
            $error = "尝试次数过多，请 {$wait} 秒后再试";
        } elseif (admin_login_attempt(field($_POST, 'user', 64), (string)($_POST['pass'] ?? ''))) {
            admin_attempt_log('ok');
            header('Location: ?p=dashboard');
            exit;
        } else {
            admin_attempt_log('fail');
            admin_attempt_cleanup();
            $error = '用户名或密码错误';
        }
    }
    render_login($error);
    exit;
}

admin_require_login();

if (!schema_ready()) {
    render_layout('未初始化', '<div class="card"><h2>数据库未初始化</h2><p>请先删除 install.php 前的部署步骤：运行 <code>install.php</code> 完成建表与配置。</p></div>');
    exit;
}

require __DIR__ . '/lib/web/actions.php';
require __DIR__ . '/lib/web/pages.php';
admin_handle_actions();

switch ($page) {
    case 'dashboard':
        page_dashboard();
        break;
    case 'cards':
        page_cards();
        break;
    case 'devices':
        page_devices();
        break;
    case 'logs':
        page_logs();
        break;
    default:
        http_response_code(404);
        render_layout('未找到', '<div class="card"><h2>页面不存在</h2></div>');
}
