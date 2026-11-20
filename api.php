<?php
declare(strict_types=1);
require __DIR__ . '/lib/bootstrap.php';

if (!isset($_GET['action'])) {
    // 不泄漏服务名、版本与端点列表
    json_out(['ok' => false, 'error' => 'not_found'], 404);
}

api_dispatch();
