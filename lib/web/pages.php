<?php
declare(strict_types=1);

function page_dashboard(): void
{
    $row = db()->query("SELECT
        COUNT(*) AS total,
        SUM(status = 'unused') AS unused,
        SUM(status = 'active') AS active,
        SUM(status = 'disabled') AS disabled,
        SUM(status = 'active' AND expire_at IS NOT NULL AND expire_at <= UNIX_TIMESTAMP()) AS expired
        FROM cards")->fetch();
    $dev = db()->query('SELECT COUNT(*) AS total, SUM(revoked = 0) AS alive FROM devices')->fetch();
    $st = db()->prepare('SELECT COUNT(*) FROM api_log WHERE action = ? AND created_at > ?');
    $st->execute(['verify', time() - 86400]);
    $verifyToday = (int)$st->fetchColumn();

    $recent = db()->query('SELECT action, result, device_id, ip, created_at FROM api_log ORDER BY id DESC LIMIT 12')->fetchAll();

    ob_start(); ?>
    <?php if ($m = admin_take_flash()): ?><div class="flash"><?= h($m) ?></div><?php endif; ?>
    <h1>概览</h1>
    <div class="stats" style="margin-bottom:16px">
      <div class="stat"><div class="n"><?= (int)$row['total'] ?></div><div class="l">卡密总数</div></div>
      <div class="stat"><div class="n"><?= (int)$row['unused'] ?></div><div class="l">未激活</div></div>
      <div class="stat"><div class="n"><?= (int)$row['active'] ?></div><div class="l">已激活</div></div>
      <div class="stat"><div class="n"><?= (int)$row['expired'] ?></div><div class="l">已过期</div></div>
      <div class="stat"><div class="n"><?= (int)$dev['alive'] ?></div><div class="l">在线设备</div></div>
      <div class="stat"><div class="n"><?= $verifyToday ?></div><div class="l">24h 校验</div></div>
    </div>
    <div class="card">
      <h2>最近调用</h2>
      <?php if (!$recent): ?>
        <p class="muted">暂无记录</p>
      <?php else: ?>
      <table>
        <thead><tr><th>时间</th><th>动作</th><th>结果</th><th>设备</th><th>IP</th></tr></thead>
        <tbody>
        <?php foreach ($recent as $r): ?>
          <tr>
            <td class="muted"><?= h(ts_fmt($r['created_at'])) ?></td>
            <td><?= h($r['action']) ?></td>
            <td><span class="tag <?= $r['result'] === 'ok' ? 'active' : 'disabled' ?>"><?= h($r['result']) ?></span></td>
            <td class="mono muted"><?= h($r['device_id'] !== '' ? substr($r['device_id'], 0, 16) : '—') ?></td>
            <td class="mono muted"><?= h($r['ip']) ?></td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
      <?php endif; ?>
    </div>
    <?php
    render_layout('概览', ob_get_clean(), ['current' => 'dashboard']);
}

function page_cards(): void
{
    $plans = plan_catalog();
    $filter = (string)($_GET['status'] ?? '');
    $where = '';
    $args = [];
    if (in_array($filter, ['unused', 'active', 'disabled'], true)) {
        $where = ' WHERE status = ?';
        $args[] = $filter;
    }
    $st = db()->prepare('SELECT * FROM cards' . $where . ' ORDER BY id DESC LIMIT 300');
    $st->execute($args);
    $rows = $st->fetchAll();
    $boundMap = [];
    foreach (db()->query('SELECT card_id, COUNT(*) AS n FROM devices WHERE revoked = 0 GROUP BY card_id') as $r) {
        $boundMap[(int)$r['card_id']] = (int)$r['n'];
    }

    admin_session_start();
    $generated = [];
    if (!empty($_GET['generated']) && !empty($_SESSION['generated'])) {
        $generated = $_SESSION['generated'];
        unset($_SESSION['generated']);
    }

    ob_start(); ?>
    <?php if ($m = admin_take_flash()): ?><div class="flash"><?= h($m) ?></div><?php endif; ?>
    <h1>卡密管理</h1>

    <?php if ($generated): ?>
    <div class="card">
      <h2>本次生成 <?= count($generated) ?> 张卡密</h2>
      <p class="muted">卡密只在此处显示一次，请立即保存。</p>
      <div class="codes"><?= h(implode("\n", $generated)) ?></div>
    </div>
    <?php endif; ?>

    <div class="card">
      <h2>生成卡密</h2>
      <form method="post" action="?p=cards">
        <input type="hidden" name="csrf" value="<?= h(admin_csrf()) ?>">
        <input type="hidden" name="do" value="generate">
        <div class="row">
          <div class="field">
            <label>套餐</label>
            <select name="plan">
              <?php foreach ($plans as $k => $p): ?>
                <option value="<?= h($k) ?>"><?= h($p['label']) ?> — <?= h($p['desc']) ?>（<?= h(implode(',', $p['features'])) ?>）</option>
              <?php endforeach; ?>
            </select>
          </div>
          <div class="field">
            <label>数量（1-200）</label>
            <input type="number" name="count" value="1" min="1" max="200">
          </div>
          <div class="field">
            <label>备注</label>
            <input type="text" name="note" placeholder="如：闲鱼批次 A" maxlength="128">
          </div>
          <div class="field">
            <label>&nbsp;</label>
            <button class="btn" type="submit">生成</button>
          </div>
        </div>
      </form>
    </div>

    <div class="card">
      <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:12px">
        <h2 style="margin:0">卡密列表</h2>
        <span class="muted">
          筛选：
          <a href="?p=cards">全部</a> ·
          <a href="?p=cards&status=unused">未激活</a> ·
          <a href="?p=cards&status=active">已激活</a> ·
          <a href="?p=cards&status=disabled">已停用</a>
        </span>
      </div>
      <?php if (!$rows): ?>
        <p class="muted">没有符合条件的卡密</p>
      <?php else: ?>
      <div style="overflow-x:auto">
      <table>
        <thead><tr><th>ID</th><th>卡密</th><th>套餐</th><th>状态</th><th>设备</th><th>激活时间</th><th>到期时间</th><th>备注</th><th>操作</th></tr></thead>
        <tbody>
        <?php foreach ($rows as $c):
            $devUsed = $boundMap[(int)$c['id']] ?? 0;
        ?>
          <tr>
            <td class="muted"><?= (int)$c['id'] ?></td>
            <td class="mono"><?= h($c['code_mask']) ?></td>
            <td><?= h($plans[$c['plan']]['label'] ?? $c['plan']) ?></td>
            <td><span class="tag <?= h($c['status']) ?>"><?= h(['unused' => '未激活', 'active' => '已激活', 'disabled' => '已停用'][$c['status']] ?? $c['status']) ?></span></td>
            <td class="muted"><?= $devUsed ?>/<?= (int)$c['max_devices'] ?></td>
            <td class="muted"><?= h(ts_fmt($c['activated_at'])) ?></td>
            <td class="muted"><?= (int)$c['duration_days'] === 0 ? '永久' : h(ts_fmt($c['expire_at'])) ?></td>
            <td class="muted"><?= h($c['note']) ?></td>
            <td>
              <form method="post" action="?p=cards" style="display:inline">
                <input type="hidden" name="csrf" value="<?= h(admin_csrf()) ?>">
                <input type="hidden" name="id" value="<?= (int)$c['id'] ?>">
                <?php if ($c['status'] === 'disabled'): ?>
                  <input type="hidden" name="do" value="enable">
                  <button class="btn sec sm" type="submit">恢复</button>
                <?php else: ?>
                  <input type="hidden" name="do" value="disable">
                  <button class="btn danger sm" type="submit">停用</button>
                <?php endif; ?>
              </form>
            </td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
      </div>
      <p class="muted" style="margin-top:10px">列表最多显示最近 300 条。</p>
      <?php endif; ?>
    </div>
    <?php
    render_layout('卡密管理', ob_get_clean(), ['current' => 'cards']);
}

function page_devices(): void
{
    $rows = db()->query('SELECT d.*, c.code_mask, c.plan FROM devices d LEFT JOIN cards c ON c.id = d.card_id ORDER BY d.last_seen DESC LIMIT 300')->fetchAll();
    $plans = plan_catalog();

    ob_start(); ?>
    <?php if ($m = admin_take_flash()): ?><div class="flash"><?= h($m) ?></div><?php endif; ?>
    <h1>设备绑定</h1>
    <div class="card">
      <?php if (!$rows): ?>
        <p class="muted">暂无设备</p>
      <?php else: ?>
      <div style="overflow-x:auto">
      <table>
        <thead><tr><th>卡密</th><th>套餐</th><th>设备标识</th><th>名称</th><th>版本</th><th>首次</th><th>最近</th><th>IP</th><th>状态</th><th>操作</th></tr></thead>
        <tbody>
        <?php foreach ($rows as $d): ?>
          <tr>
            <td class="mono muted"><?= h($d['code_mask']) ?></td>
            <td class="muted"><?= h($plans[$d['plan']]['label'] ?? $d['plan']) ?></td>
            <td class="mono"><?= h(substr($d['device_id'], 0, 18)) ?></td>
            <td><?= h($d['device_name'] ?: '—') ?></td>
            <td class="muted"><?= h($d['app_version'] ?: '—') ?></td>
            <td class="muted"><?= h(ts_fmt($d['first_seen'])) ?></td>
            <td class="muted"><?= h(ts_fmt($d['last_seen'])) ?></td>
            <td class="mono muted"><?= h($d['last_ip']) ?></td>
            <td><span class="tag <?= (int)$d['revoked'] ? 'disabled' : 'active' ?>"><?= (int)$d['revoked'] ? '已解绑' : '正常' ?></span></td>
            <td style="white-space:nowrap">
              <form method="post" action="?p=devices" style="display:inline">
                <input type="hidden" name="csrf" value="<?= h(admin_csrf()) ?>">
                <input type="hidden" name="id" value="<?= (int)$d['id'] ?>">
                <?php if ((int)$d['revoked']): ?>
                  <input type="hidden" name="do" value="restore_device">
                  <button class="btn sec sm" type="submit">恢复</button>
                <?php else: ?>
                  <input type="hidden" name="do" value="revoke_device">
                  <button class="btn sec sm" type="submit">解绑</button>
                <?php endif; ?>
              </form>
              <form method="post" action="?p=devices" style="display:inline" onsubmit="return confirm('彻底删除该设备记录？删除后该设备可重新激活，但不保留历史。')">
                <input type="hidden" name="csrf" value="<?= h(admin_csrf()) ?>">
                <input type="hidden" name="id" value="<?= (int)$d['id'] ?>">
                <input type="hidden" name="do" value="delete_device">
                <button class="btn danger sm" type="submit">删除</button>
              </form>
            </td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
      </div>
      <?php endif; ?>
    </div>
    <div class="card muted">
      解绑后该设备立即失效；若套餐允许更多设备，用户可在新设备上重新激活。
    </div>
    <?php
    render_layout('设备绑定', ob_get_clean(), ['current' => 'devices']);
}

function page_logs(): void
{
    $rows = db()->query('SELECT * FROM api_log ORDER BY id DESC LIMIT 200')->fetchAll();
    ob_start(); ?>
    <h1>调用日志</h1>
    <div class="card">
      <?php if (!$rows): ?>
        <p class="muted">暂无记录</p>
      <?php else: ?>
      <table>
        <thead><tr><th>时间</th><th>动作</th><th>结果</th><th>卡密ID</th><th>设备</th><th>IP</th></tr></thead>
        <tbody>
        <?php foreach ($rows as $r): ?>
          <tr>
            <td class="muted"><?= h(ts_fmt($r['created_at'])) ?></td>
            <td><?= h($r['action']) ?></td>
            <td><span class="tag <?= $r['result'] === 'ok' ? 'active' : 'disabled' ?>"><?= h($r['result']) ?></span></td>
            <td class="muted"><?= $r['card_id'] === null ? '—' : (int)$r['card_id'] ?></td>
            <td class="mono muted"><?= h($r['device_id'] !== '' ? substr($r['device_id'], 0, 16) : '—') ?></td>
            <td class="mono muted"><?= h($r['ip']) ?></td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
      <?php endif; ?>
    </div>
    <?php
    render_layout('调用日志', ob_get_clean(), ['current' => 'logs']);
}
