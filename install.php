<?php
declare(strict_types=1);
/**
 * 一次性安装脚本。部署后立即删除。
 * 需要 install_key 才能执行，避免被别人先跑。
 */
define('APP_ROOT', __DIR__);

$result = ['ok' => false, 'steps' => []];

function step(string $name, bool $ok, string $detail = ''): void
{
    $GLOBALS['result']['steps'][] = ['step' => $name, 'ok' => $ok, 'detail' => $detail];
}

function done(): void
{
    http_response_code($GLOBALS['result']['ok'] ? 200 : 500);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($GLOBALS['result'], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    exit;
}

$installKeyFile = __DIR__ . '/_data/install.key';
if (!is_file($installKeyFile)) {
    step('install_key', false, '缺少 _data/install.key');
    done();
}
$expected = trim((string)file_get_contents($installKeyFile));
$given = (string)($_GET['key'] ?? '');
if ($expected === '' || !hash_equals($expected, $given)) {
    step('install_key', false, 'key 不匹配');
    done();
}

if (is_file(__DIR__ . '/lib/config.php')) {
    step('already_installed', false, 'lib/config.php 已存在，如需重装请先删除');
    done();
}

$cfgFile = __DIR__ . '/_data/config.values.json';
if (!is_file($cfgFile)) {
    step('config_values', false, '缺少 _data/config.values.json');
    done();
}
$v = json_decode((string)file_get_contents($cfgFile), true);
if (!is_array($v)) {
    step('config_values', false, 'JSON 解析失败');
    done();
}
step('config_values', true);

try {
    $dsn = sprintf('mysql:host=%s;dbname=%s;charset=utf8mb4', $v['db_host'], $v['db_name']);
    $pdo = new PDO($dsn, $v['db_user'], $v['db_pass'], [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
    step('db_connect', true, 'MariaDB 连接成功');
} catch (Throwable $e) {
    step('db_connect', false, $e->getMessage());
    done();
}

require __DIR__ . '/lib/db.php';
$GLOBALS['CONFIG'] = ['db' => ['host' => $v['db_host'], 'name' => $v['db_name'], 'user' => $v['db_user'], 'pass' => $v['db_pass']]];

foreach (schema_sql() as $i => $sql) {
    try {
        $pdo->exec($sql);
        $tables = ['cards', 'devices', 'nonces', 'api_log'];
        step('table:' . $tables[$i], true);
    } catch (Throwable $e) {
        step('table:' . ($tables[$i] ?? $i), false, $e->getMessage());
        done();
    }
}

$priv = (string)@file_get_contents(__DIR__ . '/_data/private_key.pem');
if (trim($priv) === '' || openssl_pkey_get_private($priv) === false) {
    step('sign_key', false, 'private_key.pem 缺失或无效');
    done();
}
step('sign_key', true);

$config = [
    'db' => [
        'host' => $v['db_host'],
        'name' => $v['db_name'],
        'user' => $v['db_user'],
        'pass' => $v['db_pass'],
    ],
    'sign_key' => $priv,
    'admin' => [
        'user' => $v['admin_user'],
        'pass_hash' => password_hash($v['admin_pass'], PASSWORD_DEFAULT),
    ],
    'timezone' => $v['timezone'] ?? 'Asia/Shanghai',
    'grace_days' => 3,
    'nonce_window' => 300,
];

$php = "<?php\ndeclare(strict_types=1);\n\nreturn " . var_export($config, true) . ";\n";
if (@file_put_contents(__DIR__ . '/lib/config.php', $php) === false) {
    step('write_config', false, '写入 lib/config.php 失败，请检查目录权限');
    done();
}
step('write_config', true);

$result['ok'] = true;
done();
