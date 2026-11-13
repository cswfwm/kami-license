#!/usr/bin/env python3
"""kami 信封协议参考实现（用于验证服务端，并作为 Java/Zig 实现的对照基准）。

请求：
    inner = {"action":..., "code":..., "device":..., "ts":..., "nonce":..., ...}
    l1    = AES256CBC(key1, json(inner)) || HMAC-SHA256(mac1, ciphertext)
    gz    = gzip(l1)
    l2    = AES256CBC(key2, gz)
    body  = {"e": b64url(l2)}

响应：
    {"e": <同上结构>, "s": b64url(ECDSA-SHA256(sign_key, "e" 的字符串))}
    先验 s 再解密，因此伪造服务器无法让客户端接受响应。
"""
import base64
import gzip
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import tempfile
import time
import urllib.request

K1 = bytes.fromhex("434867350eeff8e80b9e45945efc788a4ebf53c8aac3a53b5cbad8e6de809e31")
M1 = bytes.fromhex("49d51644a975002e2b3fc7a560fa69aeeb7fb67c16ab7453cb1feed105328df1")
K2 = bytes.fromhex("93753a96158e8f95de1f388eb5680d2c932ad1b58640f0c9d50d21b3f875a935")

BASE = "http://xxxxx-x.uuk.pp.ua"
PUBKEY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "public_key.pem")


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def aes_encrypt(key: bytes, plain: bytes) -> bytes:
    """AES-256-CBC 加密，返回 iv||ciphertext。用 openssl CLI 保证与 PHP 完全一致。"""
    iv = os.urandom(16)
    p = subprocess.run(
        ["openssl", "enc", "-aes-256-cbc", "-K", key.hex(), "-iv", iv.hex()],
        input=plain, capture_output=True, check=True)
    return iv + p.stdout


def aes_decrypt(key: bytes, data: bytes) -> bytes:
    iv, ct = data[:16], data[16:]
    p = subprocess.run(
        ["openssl", "enc", "-d", "-aes-256-cbc", "-K", key.hex(), "-iv", iv.hex()],
        input=ct, capture_output=True, check=True)
    return p.stdout


def seal_request(inner: dict) -> str:
    l1 = aes_encrypt(K1, json.dumps(inner, ensure_ascii=False).encode())
    l1 += hmac.new(M1, l1, hashlib.sha256).digest()
    l2 = aes_encrypt(K2, gzip.compress(l1))
    return b64u(l2)


def open_response(env: dict) -> dict:
    e, s = env["e"], env["s"]
    # 1) 先验签：确认响应确实来自持有私钥的真实服务器
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(e.encode())
        msg_path = f.name
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b64u_dec(s))
        sig_path = f.name
    try:
        r = subprocess.run(["openssl", "dgst", "-sha256", "-verify", PUBKEY,
                            "-signature", sig_path, msg_path],
                           capture_output=True, text=True)
        if r.returncode != 0:
            raise SystemExit("响应签名校验失败：可能不是真实服务器")
    finally:
        os.unlink(msg_path)
        os.unlink(sig_path)

    # 2) 解密：外层 AES → gunzip → 内层验 MAC 再 AES
    gz = aes_decrypt(K2, b64u_dec(e))
    l1 = gzip.decompress(gz)
    ct, tag = l1[:-32], l1[-32:]
    if not hmac.compare_digest(hmac.new(M1, ct, hashlib.sha256).digest(), tag):
        raise SystemExit("内层 MAC 校验失败")
    return json.loads(aes_decrypt(K1, ct))


def post(action: str, inner: dict) -> dict:
    inner = dict(inner)
    inner["action"] = action
    inner.setdefault("ts", int(time.time()))
    inner.setdefault("nonce", secrets.token_hex(16))
    body = json.dumps({"e": seal_request(inner)}).encode()
    req = urllib.request.Request(f"{BASE}/api.php?action={action}", data=body, method="POST")
    req.add_header("User-Agent", "Mozilla/5.0 (compatible; Googlebot/2.1)")
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=30) as r:
        return open_response(json.loads(r.read()))


if __name__ == "__main__":
    import sys
    action = sys.argv[1] if len(sys.argv) > 1 else "plans"
    inner = {}
    if action in ("activate", "verify"):
        inner = {"code": sys.argv[2], "device": sys.argv[3], "device_id": sys.argv[3]}
    print(json.dumps(post(action, inner), ensure_ascii=False, indent=2))
