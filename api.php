<?php
declare(strict_types=1);
require __DIR__ . '/lib/bootstrap.php';

if (!isset($_GET['action'])) {
    json_out([
        'ok'          => true,
        'service'     => 'kami-license',
        'version'     => 1,
        'endpoints'   => ['?action=plans', '?action=activate', '?action=verify'],
        'server_time' => time(),
    ]);
}

api_dispatch();
