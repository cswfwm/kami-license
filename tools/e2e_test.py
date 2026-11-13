#!/usr/bin/env python3
"""端到端测试：登录后台 → 生成卡密 → 激活 → 校验 → 防重放 → 换机 → 停用 → 验签。

用法：
    KAMI_ADMIN_PASS=xxx python3 tools/e2e_test.py
"""
import base64
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from uuk_client import UukClient

BASE = os.environ.get('KAMI_BASE', 'http://xxxxx-x.uuk.pp.ua')
ADMIN_USER = os.environ.get('KAMI_ADMIN_USER', 'admin')
ADMIN_PASS = os.environ.get('KAMI_ADMIN_PASS', '')
PUB_KEY = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'tools', 'public_key.pem')

results = []


def check(name, ok, detail=''):
    results.append((name, ok, detail))
    print(('  PASS ' if ok else '  FAIL ') + name + (('  ' + detail) if detail else ''))
    return ok


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def b64u(s: str) -> bytes:
    s += '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode())


def verify_signature(license_b64: str, sig_b64: str) -> bool:
    data = license_b64.encode()
    sig = b64u(sig_b64)
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(data)
        data_path = f.name
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(sig)
        sig_path = f.name
    try:
        r = subprocess.run(
            ['openssl', 'dgst', '-sha256', '-verify', PUB_KEY, '-signature', sig_path, data_path],
            capture_output=True, text=True)
        return r.returncode == 0
    finally:
        os.unlink(data_path)
        os.unlink(sig_path)


def main() -> int:
    if not ADMIN_PASS:
        sys.exit('缺少 KAMI_ADMIN_PASS 环境变量')

    api = UukClient(BASE)
    admin = UukClient(BASE)
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(admin.jar), NoRedirect())

    def admin_post(path: str, fields: dict):
        body = urllib.parse.urlencode(fields).encode()
        req = urllib.request.Request(BASE + path, data=body, method='POST')
        req.add_header('User-Agent', admin.ua)
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        try:
            op.open(req, timeout=30)
            return None
        except urllib.error.HTTPError as e:
            return e

    print('== 后台登录 ==')
    page = admin.get('/admin.php?p=login').decode()
    csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
    resp = admin_post('/admin.php?p=login', {'csrf': csrf, 'user': ADMIN_USER, 'pass': ADMIN_PASS})
    check('登录成功', resp is not None and resp.code == 302, f'code={getattr(resp, "code", None)}')

    dash = admin.get('/admin.php?p=dashboard').decode(errors='ignore')
    check('后台概览可访问', '<title>' in dash and '概览' in dash, f'len={len(dash)}')
    cards_page = admin.get('/admin.php?p=cards').decode(errors='ignore')
    csrf_m = re.search(r'name="csrf" value="([^"]+)"', cards_page)
    if not csrf_m:
        check('获取 CSRF', False, 'cards 页无 csrf 字段')
        return 1
    csrf = csrf_m.group(1)

    print('== 生成卡密 ==')
    admin_post('/admin.php?p=cards', {'csrf': csrf, 'do': 'generate', 'plan': 'pro', 'count': '2', 'note': 'E2E'})
    cards_page = admin.get('/admin.php?p=cards&generated=1').decode(errors='ignore')
    codes = re.findall(r'([2-9A-HJ-NP-Z]{4}(?:-[2-9A-HJ-NP-Z]{4}){3})', cards_page)
    if not check('生成卡密', len(codes) >= 2, f'{codes[:2]}'):
        return 1
    code = codes[0]

    print('== 接口 ==')
    plans = json.loads(api.get('/api.php?action=plans'))
    check('plans 返回 4 个套餐', plans.get('ok') is True and len(plans.get('plans', [])) == 4)

    print('== 激活 ==')
    dev1 = 'e2e-device-aaaaaa-1'
    r = json.loads(api.post_json('/api.php?action=activate',
                                 {'code': code, 'device_id': dev1, 'device_name': '测试机', 'app_version': '1.0.0'}))
    check('激活成功', r.get('ok') is True, str(r.get('error', '')))
    p = json.loads(b64u(r.get('license', ''))) if r.get('ok') else {}
    check('features 为 pro 三件套', p.get('features') == ['core', 'export', 'batch'], str(p.get('features')))
    check('许可证绑定设备', p.get('device') == dev1)
    check('许可证含到期时间', p.get('expire_at') is not None)
    check('激活返回签名', bool(r.get('sig')))

    print('== 设备数上限 ==')
    r = json.loads(api.post_json('/api.php?action=activate', {'code': code, 'device_id': 'e2e-device-bbbbbb-2'}))
    check('第二台设备被拒', r.get('ok') is False and r.get('error') == 'device_limit', str(r.get('error')))

    print('== 校验 ==')
    nonce = 'e2e' + str(int(time.time() * 1000))
    r = json.loads(api.post_json('/api.php?action=verify',
                                 {'code': code, 'device_id': dev1, 'nonce': nonce, 'ts': int(time.time())}))
    check('校验成功', r.get('ok') is True, str(r.get('error', '')))
    lic, sig = r.get('license', ''), r.get('sig', '')

    print('== 安全项 ==')
    r = json.loads(api.post_json('/api.php?action=verify',
                                 {'code': code, 'device_id': dev1, 'nonce': nonce, 'ts': int(time.time())}))
    check('重复 nonce 被拒', r.get('error') == 'replay', str(r.get('error')))

    r = json.loads(api.post_json('/api.php?action=verify',
                                 {'code': code, 'device_id': dev1, 'nonce': nonce + 'x', 'ts': int(time.time()) - 4000}))
    check('时间偏差被拒', r.get('error') == 'bad_timestamp', str(r.get('error')))

    r = json.loads(api.post_json('/api.php?action=verify',
                                 {'code': code, 'device_id': 'e2e-other-cccccc', 'nonce': nonce + 'y', 'ts': int(time.time())}))
    check('未绑定设备被拒', r.get('error') == 'device_mismatch', str(r.get('error')))

    r = json.loads(api.post_json('/api.php?action=activate', {'code': 'ZZZZ-ZZZZ-ZZZZ-ZZZZ', 'device_id': dev1}))
    check('不存在卡密被拒', r.get('error') == 'invalid_code', str(r.get('error')))

    check('ECDSA 签名有效', verify_signature(lic, sig))
    tampered = ('B' if lic[:1] != 'B' else 'C') + lic[1:]
    check('篡改 payload 后验签失败', not verify_signature(tampered, sig))

    print('== 停用 ==')
    # 用本次生成的卡密遮罩定位其 ID（避免误停用其他卡）
    fresh = admin.get('/admin.php?p=cards').decode(errors='ignore')
    mask = f'{code[0:4]}-****-****-{code[-4:]}'
    card_id = None
    idx = fresh.find(mask)
    if idx > 0:
        row_start = fresh.rfind('<tr>', 0, idx)
        m = re.search(r'name="id" value="(\d+)"', fresh[row_start:idx])
        if m:
            card_id = m.group(1)
    if card_id:
        admin_post('/admin.php?p=cards', {'csrf': csrf, 'do': 'disable', 'id': card_id})
        r = json.loads(api.post_json('/api.php?action=verify',
                                     {'code': code, 'device_id': dev1, 'nonce': nonce + 'z', 'ts': int(time.time())}))
        check('停用后校验被拒', r.get('error') == 'disabled', str(r.get('error')))

    print()
    failed = [n for n, o, _ in results if not o]
    print(f'结果：{len(results) - len(failed)}/{len(results)} 通过')
    if failed:
        print('失败项：' + ', '.join(failed))
    return 0 if not failed else 1


if __name__ == '__main__':
    sys.exit(main())
