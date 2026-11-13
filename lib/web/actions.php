<?php
declare(strict_types=1);

function admin_handle_actions(): void
{
    $do = (string)($_POST['do'] ?? '');
    if ($do === '') {
        return;
    }
    admin_check_csrf();

    if ($do === 'generate') {
        $planKey = field($_POST, 'plan', 32);
        $count = max(1, min(200, (int)($_POST['count'] ?? 1)));
        $note = field($_POST, 'note', 128);
        $plan = plan_get($planKey);
        if ($plan === null) {
            admin_flash('未知套餐');
            header('Location: ?p=cards');
            exit;
        }
        $codes = [];
        $stmt = db()->prepare('INSERT INTO cards (code_hash, code_mask, plan, features, duration_days, max_devices, note, created_at) VALUES (?,?,?,?,?,?,?,?)');
        for ($i = 0; $i < $count; $i++) {
            for ($try = 0; $try < 5; $try++) {
                $code = card_code_generate();
                try {
                    $stmt->execute([
                        card_hash($code),
                        card_mask($code),
                        $planKey,
                        json_encode($plan['features'], JSON_UNESCAPED_UNICODE),
                        (int)$plan['days'],
                        (int)$plan['devices'],
                        $note,
                        time(),
                    ]);
                    $codes[] = $code;
                    break;
                } catch (PDOException $e) {
                    if ((string)$e->getCode() !== '23000') {
                        throw $e;
                    }
                }
            }
        }
        admin_session_start();
        $_SESSION['generated'] = $codes;
        header('Location: ?p=cards&generated=1');
        exit;
    }

    if ($do === 'disable' || $do === 'enable') {
        $id = (int)($_POST['id'] ?? 0);
        db()->prepare('UPDATE cards SET status = ? WHERE id = ? AND status <> ?')
            ->execute([$do === 'disable' ? 'disabled' : 'unused', $id, $do === 'disable' ? 'disabled' : 'unused']);
        admin_flash($do === 'disable' ? '卡密已停用' : '卡密已恢复');
        header('Location: ?p=cards');
        exit;
    }

    if ($do === 'revoke_device' || $do === 'restore_device' || $do === 'delete_device') {
        $id = (int)($_POST['id'] ?? 0);
        if ($do === 'delete_device') {
            db()->prepare('DELETE FROM devices WHERE id = ?')->execute([$id]);
        } else {
            db()->prepare('UPDATE devices SET revoked = ? WHERE id = ?')
                ->execute([$do === 'revoke_device' ? 1 : 0, $id]);
        }
        admin_flash('设备状态已更新');
        header('Location: ?p=devices');
        exit;
    }
}
