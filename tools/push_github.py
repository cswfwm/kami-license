#!/usr/bin/env python3
"""用 Git Data API 把 /tmp/kami-git 的提交推到 GitHub（不走 git push）。

用法：python3 tools/push_github.py [repo-name] [token-file]
"""
import base64
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

API = 'https://api.github.com'


def call(method: str, path: str, token: str, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(API + path, data=data, method=method)
    req.add_header('Authorization', f'token {token}')
    req.add_header('Accept', 'application/vnd.github+json')
    req.add_header('User-Agent', 'kami-license-push')
    if data:
        req.add_header('Content-Type', 'application/json')
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            body = r.read()
            return r.status, (json.loads(body) if body else {})
    except urllib.error.HTTPError as e:
        body = e.read()
        return e.code, (json.loads(body) if body else {'raw': body.decode('utf-8', 'replace')})


def main() -> int:
    repo = sys.argv[1] if len(sys.argv) > 1 else 'kami-license'
    token_file = sys.argv[2] if len(sys.argv) > 2 else os.path.expanduser('~/workspace/github_token.txt')
    token = open(token_file).read().strip()
    src = '/tmp/kami-git'

    files = subprocess.run(['git', 'ls-files'], cwd=src, capture_output=True, text=True).stdout.split()
    if not files:
        sys.exit('没有文件可推送')

    status, user = call('GET', '/user', token)
    if status != 200:
        sys.exit(f'token 无效: {status} {user}')
    owner = user['login']
    print(f'账号: {owner}，文件数: {len(files)}')

    status, info = call('GET', f'/repos/{owner}/{repo}', token)
    if status == 200:
        print(f'仓库已存在，复用: {info["html_url"]}')
    elif status == 404:
        status, info = call('POST', '/user/repos', token, {
            'name': repo,
            'description': 'PHP 卡密服务 + Android 验签客户端（功能分级授权、ECDSA 签名、设备绑定）',
            'private': False,
        })
        if status not in (200, 201):
            sys.exit(f'创建仓库失败: {status} {info}')
        print(f'已创建仓库: {info["html_url"]}')
    else:
        sys.exit(f'查询仓库失败: {status} {info}')

    blobs = []
    for f in files:
        with open(os.path.join(src, f), 'rb') as fh:
            content = base64.b64encode(fh.read()).decode()
        st, res = call('POST', f'/repos/{owner}/{repo}/git/blobs', token,
                       {'content': content, 'encoding': 'base64'})
        if st not in (200, 201):
            sys.exit(f'上传 blob 失败 {f}: {st} {res}')
        blobs.append({'path': f, 'mode': '100644', 'type': 'blob', 'sha': res['sha']})
        print(f'  blob {f}')

    st, tree = call('POST', f'/repos/{owner}/{repo}/git/trees', token, {'tree': blobs})
    if st not in (200, 201):
        sys.exit(f'建 tree 失败: {st} {tree}')

    st, commit = call('POST', f'/repos/{owner}/{repo}/git/commits', token, {
        'message': 'feat: PHP 卡密服务与 Android 验签客户端',
        'tree': tree['sha'],
    })
    if st not in (200, 201):
        sys.exit(f'建 commit 失败: {st} {commit}')

    st, _ = call('GET', f'/repos/{owner}/{repo}/git/refs/heads/main', token)
    if st == 200:
        st, res = call('PATCH', f'/repos/{owner}/{repo}/git/refs/heads/main', token,
                       {'sha': commit['sha'], 'force': True})
    else:
        st, res = call('POST', f'/repos/{owner}/{repo}/git/refs', token,
                       {'ref': 'refs/heads/main', 'sha': commit['sha']})
    if st not in (200, 201):
        sys.exit(f'更新引用失败: {st} {res}')

    print(f'完成: https://github.com/{owner}/{repo}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
