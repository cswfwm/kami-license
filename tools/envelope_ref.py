#!/usr/bin/env python3
"""kami ECIES 参考实现（验证服务端，并作为 Java/Zig 的对照基准）。

协议（真正的非对称加密，客户端只持服务端公钥）：

    e_priv, e_pub = EC P-256 临时密钥对
    shared        = ECDH(e_priv, server_pub)
    key           = HKDF-SHA256(shared, salt, info="kami-v1", 32 bytes)
    ct, tag       = AES-256-GCM(key, iv, plaintext)
    请求 = {epk: e_pub(65B SEC1), salt, iv, ct, tag}

    响应用同一把 key 加密回传：{iv, ct, tag}

抓包者只有 epk，没有服务端私钥就推不出 shared。
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

BASE = "http://xxxxx-x.uuk.pp.ua"
PUBKEY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "public_key.pem")

# 服务端 EC 公钥（SEC1 未压缩点，65 字节）
SERVER_PUB_SEC1 = bytes.fromhex(
    "0488532675a270a734c607e40457893c2e7654b4bd913141256c782546face4b91"
    "63d9b4cad1a00a1dfeac7150475198fe50f8011e641f672361956e370177630a")

SPKI_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _openssl(args, data=None):
    return subprocess.run(args, input=data, capture_output=True, check=True).stdout


def ec_keypair():
    """生成临时 EC 密钥对，返回 (priv_pem, pub_sec1)。"""
    with tempfile.TemporaryDirectory() as d:
        priv = os.path.join(d, "k.pem")
        _openssl(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", priv])
        pub = _openssl(["openssl", "ec", "-in", priv, "-pubout", "-outform", "DER"])
        return open(priv, "rb").read(), pub[-65:]


def ecdh(priv_pem: bytes, peer_sec1: bytes) -> bytes:
    """ECDH 派生共享密钥。"""
    with tempfile.TemporaryDirectory() as d:
        priv = os.path.join(d, "p.pem")
        peer = os.path.join(d, "peer.der")
        open(priv, "wb").write(priv_pem)
        open(peer, "wb").write(SPKI_PREFIX + peer_sec1)
        return _openssl(["openssl", "pkeyutl", "-derive", "-inkey", priv,
                         "-peerform", "DER", "-peerkey", peer])


def hkdf(shared: bytes, salt: bytes, n: int = 32) -> bytes:
    """HKDF-SHA256，info="kami-v1"。"""
    prk = hmac.new(salt, shared, hashlib.sha256).digest()
    okm = b""
    t = b""
    i = 1
    while len(okm) < n:
        t = hmac.new(prk, t + b"kami-v1" + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:n]


def aes_gcm_encrypt(key: bytes, iv: bytes, plain: bytes):
    """openssl enc 不支持 GCM，改用 cryptography 库。"""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    out = AESGCM(key).encrypt(iv, plain, None)
    return out[:-16], out[-16:]


def aes_gcm_decrypt(key: bytes, iv: bytes, ct: bytes, tag: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    return AESGCM(key).decrypt(iv, ct + tag, None)


def post(action: str, inner: dict, server_pub: bytes = SERVER_PUB_SEC1):
    """发送加密请求并解密响应。"""
    inner = dict(inner)
    inner["action"] = action
    inner.setdefault("ts", int(time.time()))
    inner.setdefault("nonce", secrets.token_hex(16))

    priv, pub = ec_keypair()
    salt = os.urandom(16)
    key = hkdf(ecdh(priv, server_pub), salt)
    iv = os.urandom(12)
    ct, tag = aes_gcm_encrypt(key, iv, json.dumps(inner, ensure_ascii=False).encode())

    body = json.dumps({
        "epk": b64u(pub), "salt": b64u(salt), "iv": b64u(iv),
        "ct": b64u(ct), "tag": b64u(tag),
    }).encode()

    req = urllib.request.Request(f"{BASE}/api.php?action={action}", data=body, method="POST")
    req.add_header("User-Agent", "Mozilla/5.0 (compatible; Googlebot/2.1)")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read()
    except urllib.error.HTTPError as e:
        raw = e.read()

    env = json.loads(raw)
    if "ct" not in env:
        return env
    return json.loads(aes_gcm_decrypt(key, b64u_dec(env["iv"]),
                                      b64u_dec(env["ct"]), b64u_dec(env["tag"])))


def verify_license_sig(license_b64: str, sig_b64: str) -> bool:
    """校验许可证的服务端 ECDSA 签名（确认响应确实来自真实服务器）。"""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(license_b64.encode())
        mp = f.name
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b64u_dec(sig_b64))
        sp = f.name
    try:
        r = subprocess.run(["openssl", "dgst", "-sha256", "-verify", PUBKEY_PATH,
                            "-signature", sp, mp], capture_output=True, text=True)
        return r.returncode == 0
    finally:
        os.unlink(mp)
        os.unlink(sp)


if __name__ == "__main__":
    import sys
    action = sys.argv[1] if len(sys.argv) > 1 else "plans"
    inner = {}
    if action in ("activate", "verify"):
        dev = sys.argv[3] if len(sys.argv) > 3 else "refdevice001"
        inner = {"code": sys.argv[2], "device": dev, "device_id": dev}
    out = post(action, inner)
    print(json.dumps(out, ensure_ascii=False, indent=2))
    if out.get("license") and out.get("sig"):
        print("\n许可证签名校验:", "PASS" if verify_license_sig(out["license"], out["sig"]) else "FAIL")
