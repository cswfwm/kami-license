<?php
declare(strict_types=1);
/**
 * 配置模板。部署时由 tools/install.php 生成 lib/config.php 并填入真实值。
 * 切勿把生成后的 config.php 提交到公开仓库。
 */
return [
    'db'   => ['host' => 'sql106.uuk.pp.ua', 'name' => '', 'user' => '', 'pass' => ''],
    'sign_key' => '',
    'admin' => ['user' => 'admin', 'pass_hash' => ''],
    'timezone' => 'Asia/Shanghai',
    'grace_days' => 3,
    'nonce_window' => 300,
];
