#!/usr/bin/env python3
"""把 kami-license 部署到 uuk 免费主机（FTP）。

用法：
    python3 tools/deploy.py            # 上传全部文件
    python3 tools/deploy.py --probe    # 只上传探针并检查环境

凭据从环境变量读取，避免写进仓库：
    FTP_HOST FTP_USER FTP_PASS   （默认 ftp.uuk.pp.ua / uu666_43403946 / 见 hosting-accounts.json）
"""
import argparse
import ftplib
import io
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SKIP_DIRS = {'_data', '.git', 'android', 'tools', '__pycache__'}
SKIP_FILES = {'.gitignore', 'config.sample.php'}


def connect() -> ftplib.FTP:
    host = os.environ.get('FTP_HOST', 'ftp.uuk.pp.ua')
    user = os.environ.get('FTP_USER', 'uu666_43403946')
    password = os.environ.get('FTP_PASS')
    if not password:
        sys.exit('缺少 FTP_PASS 环境变量')
    ftp = ftplib.FTP(host, timeout=40)
    ftp.login(user, password)
    return ftp


def ensure_dir(ftp: ftplib.FTP, path: str) -> None:
    parts = [p for p in path.strip('/').split('/') if p]
    cur = ''
    for p in parts:
        cur += '/' + p
        try:
            ftp.mkd(cur)
        except ftplib.error_perm:
            pass


def collect() -> list[tuple[str, bytes]]:
    out = []
    for base, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            if name in SKIP_FILES or name.endswith('.pyc'):
                continue
            full = os.path.join(base, name)
            rel = os.path.relpath(full, ROOT).replace(os.sep, '/')
            with open(full, 'rb') as fh:
                out.append((rel, fh.read()))
    return out


def upload(ftp: ftplib.FTP, remote_root: str, files: list[tuple[str, bytes]]) -> None:
    for rel, data in files:
        remote = f'{remote_root}/{rel}'
        ensure_dir(ftp, os.path.dirname(remote))
        ftp.storbinary('STOR ' + remote, io.BytesIO(data))
        print(f'  -> {remote}  ({len(data)} B)')


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--probe', action='store_true', help='只上传探针文件')
    ap.add_argument('--remote', default='/htdocs', help='远端根目录')
    args = ap.parse_args()

    ftp = connect()
    if args.probe:
        code = f"""<?php
header('Content-Type: application/json');
$o = ['php' => PHP_VERSION];
foreach (['pdo_mysql','sodium','openssl','json','mbstring'] as $e) {{
    $o['ext'][$e] = extension_loaded($e);
}}
$o['timezone'] = date_default_timezone_get();
$o['docroot'] = __DIR__;
echo json_encode($o, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
"""
        ftp.storbinary('STOR /htdocs/_probe.php', io.BytesIO(code.encode()))
        print('探针已上传：http://xxxxx-x.uuk.pp.ua/_probe.php')
        ftp.quit()
        return

    files = collect()
    print(f'共 {len(files)} 个文件')
    upload(ftp, args.remote, files)
    ftp.quit()
    print('完成')


if __name__ == '__main__':
    main()
