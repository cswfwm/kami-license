<?php
declare(strict_types=1);

// 功能分级：卡密按套餐下发一组 feature key，客户端据此解锁对应能力。
function plan_catalog(): array
{
    return [
        'basic' => [
            'label'    => '基础版',
            'desc'     => '单设备，永久',
            'days'     => 0,
            'devices'  => 1,
            'features' => ['core'],
        ],
        'pro' => [
            'label'    => '专业版',
            'desc'     => '单设备，365 天',
            'days'     => 365,
            'devices'  => 1,
            'features' => ['core', 'export', 'batch'],
        ],
        'trial7' => [
            'label'    => '7 天试用',
            'desc'     => '单设备，7 天限期',
            'days'     => 7,
            'devices'  => 1,
            'features' => ['core', 'export'],
        ],
        'team' => [
            'label'    => '团队版',
            'desc'     => '3 台设备，365 天',
            'days'     => 365,
            'devices'  => 3,
            'features' => ['core', 'export', 'batch', 'api'],
        ],
    ];
}

function plan_get(string $plan): ?array
{
    return plan_catalog()[$plan] ?? null;
}
