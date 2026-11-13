<?php
declare(strict_types=1);

define('APP_ROOT', dirname(__DIR__));
define('DATA_DIR', APP_ROOT . '/_data');

$configFile = APP_ROOT . '/lib/config.php';
if (!is_file($configFile)) {
    http_response_code(500);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['ok' => false, 'error' => 'not_configured'], JSON_UNESCAPED_UNICODE);
    exit;
}

$CONFIG = require $configFile;
date_default_timezone_set($CONFIG['timezone'] ?? 'UTC');
mb_internal_encoding('UTF-8');

require __DIR__ . '/db.php';
require __DIR__ . '/plans.php';
require __DIR__ . '/license.php';
require __DIR__ . '/devicesig.php';
require __DIR__ . '/envelope.php';
require __DIR__ . '/api.php';

function b64u_encode(string $raw): string
{
    return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
}

function b64u_decode(string $str): string
{
    $pad = strlen($str) % 4;
    if ($pad) {
        $str .= str_repeat('=', 4 - $pad);
    }
    $raw = base64_decode(strtr($str, '-_', '+/'), true);
    return $raw === false ? '' : $raw;
}

function json_out(array $data, int $status = 200): void
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function client_ip(): string
{
    return substr((string)($_SERVER['REMOTE_ADDR'] ?? ''), 0, 45);
}

function client_ua(): string
{
    return substr((string)($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 160);
}

function request_body(): array
{
    $ctype = strtolower((string)($_SERVER['CONTENT_TYPE'] ?? ''));
    $raw = file_get_contents('php://input');
    if ($raw === false || $raw === '') {
        return $_POST;
    }
    if (str_contains($ctype, 'application/json')) {
        $data = json_decode($raw, true);
        return is_array($data) ? $data : [];
    }
    return $_POST;
}

function field(array $src, string $key, int $maxLen = 200): string
{
    $v = $src[$key] ?? '';
    if (!is_string($v)) {
        return '';
    }
    return mb_substr(trim($v), 0, $maxLen);
}
