<?php
declare(strict_types=1);

function db(): PDO
{
    static $pdo = null;
    if ($pdo instanceof PDO) {
        return $pdo;
    }
    global $CONFIG;
    $c = $CONFIG['db'];
    $dsn = sprintf('mysql:host=%s;dbname=%s;charset=utf8mb4', $c['host'], $c['name']);
    $pdo = new PDO($dsn, $c['user'], $c['pass'], [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
    return $pdo;
}

function schema_sql(): array
{
    return [
        "CREATE TABLE IF NOT EXISTS cards (
            id            INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            code_hash     CHAR(64)     NOT NULL,
            code_mask     VARCHAR(32)  NOT NULL,
            plan          VARCHAR(32)  NOT NULL,
            features      JSON         NOT NULL,
            duration_days INT          NOT NULL DEFAULT 0,
            max_devices   TINYINT      NOT NULL DEFAULT 1,
            note          VARCHAR(128) NOT NULL DEFAULT '',
            status        ENUM('unused','active','disabled') NOT NULL DEFAULT 'unused',
            created_at    INT UNSIGNED NOT NULL,
            activated_at  INT UNSIGNED NULL,
            expire_at     INT UNSIGNED NULL,
            UNIQUE KEY uk_code (code_hash),
            KEY idx_status (status)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

        "CREATE TABLE IF NOT EXISTS devices (
            id           INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            card_id      INT UNSIGNED NOT NULL,
            device_id    VARCHAR(64)  NOT NULL,
            device_name  VARCHAR(64)  NOT NULL DEFAULT '',
            app_version  VARCHAR(32)  NOT NULL DEFAULT '',
            first_ip     VARCHAR(45)  NOT NULL DEFAULT '',
            last_ip      VARCHAR(45)  NOT NULL DEFAULT '',
            first_seen   INT UNSIGNED NOT NULL,
            last_seen    INT UNSIGNED NOT NULL,
            revoked      TINYINT      NOT NULL DEFAULT 0,
            UNIQUE KEY uk_card_device (card_id, device_id),
            KEY idx_device (device_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

        "CREATE TABLE IF NOT EXISTS nonces (
            id      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            card_id INT UNSIGNED NOT NULL,
            nonce   CHAR(32)     NOT NULL,
            used_at INT UNSIGNED NOT NULL,
            UNIQUE KEY uk_card_nonce (card_id, nonce),
            KEY idx_used (used_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

        "CREATE TABLE IF NOT EXISTS api_log (
            id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            card_id    INT UNSIGNED NULL,
            action     VARCHAR(16)  NOT NULL,
            result     VARCHAR(32)  NOT NULL,
            device_id  VARCHAR(64)  NOT NULL DEFAULT '',
            ip         VARCHAR(45)  NOT NULL DEFAULT '',
            ua         VARCHAR(160) NOT NULL DEFAULT '',
            created_at INT UNSIGNED NOT NULL,
            KEY idx_created (created_at),
            KEY idx_card (card_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

        "CREATE TABLE IF NOT EXISTS admin_attempts (
            id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            ip         VARCHAR(45)  NOT NULL,
            username   VARCHAR(64)  NOT NULL DEFAULT '',
            result     VARCHAR(16)  NOT NULL,
            created_at INT UNSIGNED NOT NULL,
            KEY idx_ip_time (ip, created_at),
            KEY idx_user_time (username, created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

        "CREATE TABLE IF NOT EXISTS device_keys (
            id         INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            device_id  VARCHAR(64)  NOT NULL,
            pubkey     VARCHAR(512) NOT NULL,
            created_at INT UNSIGNED NOT NULL,
            UNIQUE KEY uk_device (device_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
    ];
}

function schema_ready(): bool
{
    try {
        $st = db()->query("SHOW TABLES LIKE 'cards'");
        return $st !== false && $st->fetchColumn() === 'cards';
    } catch (Throwable $e) {
        return false;
    }
}
