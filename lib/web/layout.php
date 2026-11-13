<?php
declare(strict_types=1);

function render_layout(string $title, string $body, array $opts = []): void
{
    global $CONFIG;
    $user = $opts['user'] ?? 'admin';
    $nav = [
        'dashboard' => '概览',
        'cards'     => '卡密管理',
        'devices'   => '设备绑定',
        'logs'      => '调用日志',
    ];
    $current = $opts['current'] ?? '';
    ?><!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= h($title) ?> · 卡密管理</title>
<style>
  * { box-sizing: border-box; }
  body { margin:0; background:#f5f6f8; color:#1f2328; font:14px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif; }
  header { background:#20262e; color:#e6e9ee; padding:0 16px; display:flex; align-items:center; gap:20px; height:52px; }
  header .brand { font-weight:600; letter-spacing:.02em; }
  header nav { display:flex; gap:4px; flex:1; overflow-x:auto; }
  header nav a { color:#aeb6c2; text-decoration:none; padding:6px 12px; border-radius:6px; white-space:nowrap; }
  header nav a:hover { background:#2b333d; color:#fff; }
  header nav a.on { background:#3b4757; color:#fff; }
  header .who { color:#8d97a5; font-size:13px; white-space:nowrap; }
  header .who a { color:#c9d1db; margin-left:10px; }
  main { max-width:1120px; margin:0 auto; padding:20px 16px 60px; }
  .card { background:#fff; border:1px solid #e3e6ea; border-radius:10px; padding:18px; margin-bottom:16px; }
  h1 { font-size:20px; margin:0 0 16px; }
  h2 { font-size:16px; margin:0 0 12px; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th, td { text-align:left; padding:8px 10px; border-bottom:1px solid #eef0f3; vertical-align:middle; }
  th { color:#6b7280; font-weight:600; background:#fafbfc; white-space:nowrap; }
  tr:hover td { background:#fafbfd; }
  code { background:#f2f4f7; padding:1px 5px; border-radius:4px; font-size:12px; }
  .mono { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }
  .tag { display:inline-block; padding:1px 8px; border-radius:10px; font-size:12px; white-space:nowrap; }
  .tag.unused { background:#eef2ff; color:#4353b5; }
  .tag.active { background:#e7f7ee; color:#18794e; }
  .tag.disabled { background:#fdeced; color:#b42318; }
  .tag.gray { background:#f0f2f5; color:#5b6470; }
  input, select, button, textarea { font:inherit; }
  input[type=text], input[type=password], input[type=number], select, textarea {
    padding:8px 10px; border:1px solid #d4d8de; border-radius:7px; background:#fff; width:100%;
  }
  .btn { display:inline-block; padding:8px 16px; border:0; border-radius:7px; background:#2f6feb; color:#fff; cursor:pointer; font-weight:500; }
  .btn:hover { background:#255ecb; }
  .btn.sec { background:#eef1f5; color:#2b3440; }
  .btn.sec:hover { background:#e2e6ec; }
  .btn.danger { background:#d1453b; }
  .btn.danger:hover { background:#b8392f; }
  .btn.sm { padding:4px 10px; font-size:12px; }
  .row { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; align-items:end; }
  .field label { display:block; font-size:12px; color:#6b7280; margin-bottom:4px; }
  .flash { background:#e7f7ee; border:1px solid #b7e4cb; color:#166534; padding:10px 14px; border-radius:8px; margin-bottom:14px; }
  .err { background:#fdeced; border:1px solid #f5c2c0; color:#b42318; padding:10px 14px; border-radius:8px; margin-bottom:14px; }
  .stats { display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:12px; }
  .stat { background:#fff; border:1px solid #e3e6ea; border-radius:10px; padding:14px 16px; }
  .stat .n { font-size:24px; font-weight:600; }
  .stat .l { color:#6b7280; font-size:12px; }
  .muted { color:#8b93a1; font-size:12px; }
  .codes { font-family:ui-monospace,monospace; background:#0f1720; color:#d7e2f0; padding:14px; border-radius:8px; overflow-x:auto; white-space:pre; }
  @media (max-width:640px){ header .who{display:none} main{padding:14px 10px 40px} }
</style>
</head>
<body>
<header>
  <span class="brand">卡密后台</span>
  <nav>
    <?php foreach ($nav as $k => $label): ?>
      <a href="?p=<?= h($k) ?>" class="<?= $current === $k ? 'on' : '' ?>"><?= h($label) ?></a>
    <?php endforeach; ?>
  </nav>
  <span class="who"><?= h($user) ?><a href="?p=logout">退出</a></span>
</header>
<main>
<?= $body ?>
</main>
</body>
</html><?php
}

function render_login(string $error): void
{
    ?><!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>登录 · 卡密后台</title>
<style>
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#20262e;
       font:14px/1.6 -apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei",sans-serif;color:#1f2328}
  .box{background:#fff;padding:28px;border-radius:12px;width:min(360px,92vw);box-shadow:0 12px 40px rgba(0,0,0,.25)}
  h1{font-size:18px;margin:0 0 18px}
  label{display:block;font-size:12px;color:#6b7280;margin:12px 0 4px}
  input{width:100%;box-sizing:border-box;padding:10px 12px;border:1px solid #d4d8de;border-radius:8px;font:inherit}
  button{width:100%;margin-top:20px;padding:11px;border:0;border-radius:8px;background:#2f6feb;color:#fff;font:inherit;font-weight:500;cursor:pointer}
  .err{background:#fdeced;color:#b42318;padding:9px 12px;border-radius:7px;font-size:13px;margin-bottom:6px}
</style>
</head>
<body>
<form class="box" method="post" action="?p=login">
  <h1>卡密管理后台</h1>
  <?php if ($error !== ''): ?><div class="err"><?= h($error) ?></div><?php endif; ?>
  <input type="hidden" name="csrf" value="<?= h(admin_csrf()) ?>">
  <label>用户名</label>
  <input type="text" name="user" autocomplete="username" required>
  <label>密码</label>
  <input type="password" name="pass" autocomplete="current-password" required>
  <button type="submit">登录</button>
</form>
</body>
</html><?php
}
