#!/usr/bin/env python3
"""kami-license 服务端黑盒攻击测试（ECIES 协议版）。

协议：
  1. GET  ?action=key            -> 获取服务端 EC 公钥（SEC1 65 字节）
  2. POST ?action=<act>  body=   {epk,salt,iv,ct,tag}
     客户端临时 EC 密钥对，ECDH 派生 -> HKDF(sha256, info='kami-v1') -> encKey
     AES-256-GCM(encKey) 加密内层 JSON
  3. 响应：同样用 encKey 加密，附 ECDSA 签名

测试项：传输篡改、重放、时效、畸形输入、越权降级、并发、限流、协议降级。
"""
import base64
import gzip
import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
import concurrent.futures

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from uuk_client import UukClient

BASE = "http://xxxxx-x.uuk.pp.ua"
results = []


def rec(name, ok, detail):
    results.append((name, ok, detail))
    print(f"  [{'✓ 挡住' if ok else '✗ 失败'}] {name}")
    print(f"        {detail}")


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64u_dec(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def run(cmd, data=None, check=False):
    r = subprocess.run(cmd, input=data, capture_output=True)
    if check and r.returncode != 0:
        raise RuntimeError(r.stderr.decode()[:200])
    return r.stdout


# ---------- EC 密钥与 ECIES ----------

def ec_keygen(path="/tmp/_cli_ec.pem"):
    """生成 P-256 密钥对，返回 (私钥路径, sec1_pub_65B)。"""
    run(["openssl", "ecparam", "-name", "prime256v1", "-genkey",
         "-noout", "-out", path], check=True)
    p = run(["openssl", "ec", "-in", path, "-pubout", "-outform", "DER"],
            check=True)
    return path, p[-65:]


def ecdh_shared(client_priv_pem, server_pub_sec1):
    """客户端私钥 + 服务端公钥(SEC1 65B) -> ECDH 共享密钥。"""
    # SEC1 未压缩点转 PEM 公钥（openssl ec -pubin 可直接吃 PEM PUBLIC KEY）
    der = sec1_to_der(server_pub_sec1)
    with open("/tmp/_srv_pub.der", "wb") as fh:
        fh.write(der)
    run(["openssl", "pkey", "-pubin", "-inform", "DER",
         "-in", "/tmp/_srv_pub.der", "-out", "/tmp/_srv_pub.pem"], check=True)
    with open(client_priv_pem if isinstance(client_priv_pem, str) else "/tmp/_cli_ec.pem",
              "rb") as fh:
        pass
    with open("/tmp/_cli_ec.pem", "rb") as fh:
        priv = fh.read()
    with open("/tmp/_cli.pem", "wb") as fh:
        fh.write(priv)
    shared = run(["openssl", "pkeyutl", "-derive",
                  "-inkey", "/tmp/_cli.pem", "-peerkey", "/tmp/_srv_pub.pem"])
    return shared


def sec1_to_der(sec1):
    """SEC1 未压缩点(65B) -> DER SubjectPublicKeyInfo（P-256，手工构造）。"""
    # SPKI = SEQ { SEQ { OID ecPublicKey, OID prime256v1 }, BITSTRING point }
    alg = bytes.fromhex(
        "301306072a8648ce3d020106082a8648ce3d030107")
    bit_str = b"\x03" + bytes([len(sec1) + 1]) + b"\x00" + sec1
    body = alg + bit_str
    return b"\x30" + bytes([len(body)]) + body


def ecdh_shared(client_priv_path, server_pub_sec1):
    """客户端私钥 + 服务端公钥(SEC1 65B) -> ECDH 共享密钥。"""
    der = sec1_to_der(server_pub_sec1)
    pem = (b"-----BEGIN PUBLIC KEY-----\n"
           + base64.encodebytes(der)
           + b"-----END PUBLIC KEY-----\n")
    tag = os.path.basename(client_priv_path).replace(".", "_")
    srv_pem = f"/tmp/_srv_{tag}.pem"
    with open(srv_pem, "wb") as fh:
        fh.write(pem)
    shared = run(["openssl", "pkeyutl", "-derive",
                  "-inkey", client_priv_path, "-peerkey", srv_pem])
    return shared


def hkdf(shared, salt):
    """HKDF-SHA256(info='kami-v1')，输出 32 字节。openssl kdf 需用 key: 传 IKM。"""
    r = run(["openssl", "kdf", "-keylen", "32",
             "-kdfopt", "digest:SHA256",
             "-kdfopt", "info:kami-v1",
             "-kdfopt", "salt:" + salt.hex(),
             "-kdfopt", "key:" + shared.hex(),
             "HKDF"])
    return r


def gcm_encrypt(key, plain):
    iv = os.urandom(12)
    r = subprocess.run(
        ["openssl", "enc", "-aes-256-gcm", "-K", key.hex(), "-iv", iv.hex()],
        input=plain, capture_output=True)
    # openssl 3 把 tag 附在末尾 16 字节
    out = r.stdout
    return iv, out[:-16], out[-16:]


def gcm_decrypt(key, iv, ct, tag):
    r = subprocess.run(
        ["openssl", "enc", "-d", "-aes-256-gcm", "-K", key.hex(),
         "-iv", iv.hex()],
        input=ct + tag, capture_output=True)
    return r.stdout


class Session:
    """一次请求的完整 ECIES 会话。"""

    def __init__(self, base=BASE):
        self.base = base
        self.cli = UukClient(base)
        self.server_pub = None

    def fetch_key(self):
        # key 接口允许明文引导：带 plain 字段、不带 e
        r = self.cli.post_json("/api.php?action=key",
                               {"plain": True, "action": "key",
                                "ts": int(time.time()),
                                "nonce": secrets.token_hex(8)})
        d = json.loads(r)
        self.server_pub = b64u_dec(d["pubkey"])
        return d

    def post(self, action, inner, _server_pub=None):
        pub = _server_pub or self.server_pub
        if pub is None:
            self.fetch_key()
            pub = self.server_pub
        priv, cli_pub = ec_keygen()
        shared = ecdh_shared(priv, pub)
        salt = os.urandom(16)
        key = hkdf(shared, salt)
        plain = json.dumps(inner, separators=(",", ":"), ensure_ascii=False).encode()
        iv, ct, tag = gcm_encrypt(key, plain)
        body = {
            "epk": b64u(cli_pub), "salt": b64u(salt), "iv": b64u(iv),
            "ct": b64u(ct), "tag": b64u(tag),
        }
        raw = self.cli.post_json(f"/api.php?action={action}", body)
        return self._parse(raw, key)

    def _parse(self, raw, key):
        try:
            obj = json.loads(raw)
        except Exception:
            return {"_raw": raw[:160].decode("utf-8", "replace")}, raw
        if "ct" in obj and "iv" in obj and "tag" in obj:
            try:
                pt = gcm_decrypt(key, b64u_dec(obj["iv"]),
                                 b64u_dec(obj["ct"]), b64u_dec(obj["tag"]))
                return json.loads(pt), raw
            except Exception as e:
                return {"_decrypt_failed": str(e)[:60]}, raw
        return obj, raw


def show(d, n=160):
    return json.dumps(d, ensure_ascii=False)[:n]


def main():
    print("=" * 74)
    print("kami-license 黑盒攻击测试（ECIES 协议）")
    print("=" * 74)

    s = Session()

    # ---------- 0 基线 ----------
    print("\n[0] 基线")
    try:
        k = s.fetch_key()
        print(f"  action=key: ok={k.get('ok')} fp={k.get('fp')} "
              f"pubkey={len(b64u_dec(k['pubkey']))}B")
    except Exception as e:
        print(f"  ✗ 获取公钥失败: {e}")
        return

    ts = int(time.time())
    inner = {"action": "plans", "ts": ts, "nonce": secrets.token_hex(8)}
    p, _ = s.post("plans", inner)
    print(f"  action=plans: {show(p)}")

    # ---------- 1 传输层篡改 ----------
    print("\n[1] 传输层篡改")

    # 1a 篡改 ct 一个字节
    priv, cli_pub = ec_keygen()
    shared = ecdh_shared(priv, s.server_pub)
    salt = os.urandom(16)
    key = hkdf(shared, salt)
    plain = json.dumps({"action": "plans", "ts": int(time.time()),
                        "nonce": secrets.token_hex(8)}).encode()
    iv, ct, tag = gcm_encrypt(key, plain)
    bad_ct = bytearray(ct)
    bad_ct[0] ^= 0xFF
    r = s.cli.post_json("/api.php?action=plans", {
        "epk": b64u(cli_pub), "salt": b64u(salt), "iv": b64u(iv),
        "ct": b64u(bytes(bad_ct)), "tag": b64u(tag)})
    d = json.loads(r)
    rec("篡改 ct（密文）", d.get("ok") is False,
        f"error={d.get('error')} msg={d.get('msg')}")

    # 1b 篡改 tag
    bad_tag = bytearray(tag); bad_tag[0] ^= 0xFF
    r = s.cli.post_json("/api.php?action=plans", {
        "epk": b64u(cli_pub), "salt": b64u(salt), "iv": b64u(iv),
        "ct": b64u(ct), "tag": b64u(bytes(bad_tag))})
    d = json.loads(r)
    rec("篡改 GCM tag", d.get("ok") is False,
        f"error={d.get('error')} msg={d.get('msg')}")

    # 1c 篡改 epk
    bad_epk = bytearray(cli_pub); bad_epk[10] ^= 0xFF
    r = s.cli.post_json("/api.php?action=plans", {
        "epk": b64u(bytes(bad_epk)), "salt": b64u(salt), "iv": b64u(iv),
        "ct": b64u(ct), "tag": b64u(tag)})
    d = json.loads(r)
    rec("篡改 epk", d.get("ok") is False,
        f"error={d.get('error')} msg={d.get('msg')}")

    # ---------- 2 重放 ----------
    print("\n[2] 重放攻击")
    nonce = secrets.token_hex(8)
    inner = {"action": "verify", "code": "TEST-REPLAY-0001",
             "device_id": "dev-replay", "ts": int(time.time()), "nonce": nonce,
             "sig": "A" * 86, "pubkey": ""}
    p1, _ = s.post("verify", inner)
    print(f"  首次: {show(p1, 120)}")
    p2, _ = s.post("verify", inner)
    print(f"  重放: {show(p2, 120)}")
    blocked = isinstance(p2, dict) and p2.get("ok") is False and \
        p2.get("error") in ("replay", "bad_timestamp", "invalid_code", "device_unknown")
    rec("相同 nonce 重放", blocked,
        f"第二次 error={p2.get('error') if isinstance(p2, dict) else '?'}")

    # ---------- 3 时效 ----------
    print("\n[3] 时效绕过（ts 偏移，ENVELOPE_SKEW=600s）")
    for label, delta in [("过去 11 分钟", -660), ("过去 1 小时", -3600),
                         ("未来 1 小时", 3600), ("ts=0", None)]:
        t = 0 if delta is None else int(time.time()) + delta
        inner = {"action": "plans", "ts": t, "nonce": secrets.token_hex(8)}
        p, _ = s.post("plans", inner)
        err = p.get("error") if isinstance(p, dict) else None
        rec(label, err == "bad_timestamp",
            f"error={err} {(p.get('msg') if isinstance(p, dict) else '') or ''}")

    # ---------- 4 畸形输入 ----------
    print("\n[4] 畸形输入")
    bad_bodies = [
        ("缺 epk", {}),
        ("epk 长度错", {"epk": b64u(b"\x04" + b"\x01" * 30), "salt": b64u(os.urandom(16)),
                       "iv": b64u(os.urandom(12)), "ct": b64u(b"x"), "tag": b64u(os.urandom(16))}),
        ("ct 空", {"epk": b64u(cli_pub), "salt": b64u(os.urandom(16)),
                  "iv": b64u(os.urandom(12)), "ct": "", "tag": b64u(os.urandom(16))}),
        ("tag 短", {"epk": b64u(cli_pub), "salt": b64u(os.urandom(16)),
                   "iv": b64u(os.urandom(12)), "ct": b64u(b"abc"), "tag": b64u(b"x")}),
        ("全字段 null", {"epk": None, "salt": None, "iv": None, "ct": None, "tag": None}),
        ("epk 前缀错", {"epk": b64u(b"\x05" + b"\x01" * 64), "salt": b64u(os.urandom(16)),
                       "iv": b64u(os.urandom(12)), "ct": b64u(b"x"), "tag": b64u(os.urandom(16))}),
        ("超长 salt", {"epk": b64u(cli_pub), "salt": b64u(os.urandom(5000)),
                      "iv": b64u(os.urandom(12)), "ct": b64u(b"x"), "tag": b64u(os.urandom(16))}),
    ]
    for label, body in bad_bodies:
        try:
            r = s.cli.post_json("/api.php?action=plans", body)
            t = r[:150].decode("utf-8", "replace")
            leaky = any(k in t.lower() for k in
                        ["fatal error", "warning:", "stack trace", "pdoexception",
                         "syntax error", "undefined index", "deprecated"])
            rec(label, not leaky, f"{len(r)}B {t[:120]}")
        except Exception as ex:
            rec(label, False, f"异常 {str(ex)[:70]}")

    # ---------- 5 越权与降级 ----------
    print("\n[5] 越权与协议降级")
    probes = [
        ("action 不匹配（内层 plans/外层 verify）",
         "verify", {"action": "plans", "ts": int(time.time()),
                    "nonce": secrets.token_hex(8)}),
        ("内层伪造 admin",
         "verify", {"action": "admin", "ts": int(time.time()),
                    "nonce": secrets.token_hex(8)}),
        ("verify 无签名",
         "verify", {"action": "verify", "code": "X", "device_id": "d",
                    "ts": int(time.time()), "nonce": secrets.token_hex(8)}),
        ("verify 伪造 sig",
         "verify", {"action": "verify", "code": "X", "device_id": "d",
                    "ts": int(time.time()), "nonce": secrets.token_hex(8),
                    "sig": "ZmFrZQ", "pubkey": ""}),
        ("activate 伪造 plan",
         "activate", {"action": "activate", "code": "X", "device_id": "d",
                      "plan": "team", "ts": int(time.time()),
                      "nonce": secrets.token_hex(8)}),
        ("明文降级（不带 epk）",
         "plans", {"action": "plans", "ts": int(time.time()),
                   "nonce": secrets.token_hex(8), "plain": True}),
    ]
    for label, act, inner in probes:
        if "plain" in inner:
            r = s.cli.post_json("/api.php?action=plans",
                                {"action": "plans", "ts": int(time.time()),
                                 "nonce": secrets.token_hex(8)})
            d = json.loads(r)
            blocked = d.get("ok") is False and d.get("error") == "bad_envelope"
            rec(label, blocked, f"error={d.get('error')} msg={d.get('msg')}")
            continue
        p, _ = s.post(act, inner)
        err = p.get("error") if isinstance(p, dict) else None
        leaked = isinstance(p, dict) and any(
            k in json.dumps(p, ensure_ascii=False).lower()
            for k in ['"cards"', "all_cards", '"api_keys"'])
        rec(label, err is not None and not leaked, f"error={err}")

    # ---------- 6 并发 ----------
    print("\n[6] 并发竞争（同 nonce 8 并发）")
    nonce = secrets.token_hex(8)
    inner = {"action": "verify", "code": "TEST-RACE-0001",
             "device_id": "dev-race", "ts": int(time.time()), "nonce": nonce,
             "sig": "A" * 86}

    def one(_i):
        ss = Session()
        try:
            ss.fetch_key()
            p, _ = ss.post("verify", inner)
            return p.get("error", "OK") if isinstance(p, dict) else "?"
        except Exception as ex:
            return f"ERR:{str(ex)[:25]}"

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        outs = list(ex.map(one, range(8)))
    uniq = {}
    for o in outs:
        uniq[o] = uniq.get(o, 0) + 1
    print(f"  结果分布: {uniq}")
    rec("并发同 nonce", len(uniq) <= 2,
        f"{len(uniq)} 种结果（>2 表示 nonce 有竞态窗口）")

    # ---------- 7 限流 ----------
    print("\n[7] 限流（连续 35 次失败）")
    ss = Session()
    ss.fetch_key()
    seen = []
    for i in range(35):
        inner = {"action": "verify", "code": f"WRONG{i:04d}",
                 "device_id": "dev-flood", "ts": int(time.time()),
                 "nonce": secrets.token_hex(8), "sig": "A" * 86}
        try:
            p, _ = ss.post("verify", inner)
            seen.append(p.get("error", "OK") if isinstance(p, dict) else "?")
        except Exception as ex:
            seen.append(f"ERR:{str(ex)[:20]}")
    from collections import Counter
    print(f"  错误分布: {dict(Counter(seen))}")
    rec("失败限流(>30)", "too_many" in seen, f"是否出现 too_many: {'too_many' in seen}")

    # ---------- 汇总 ----------
    print("\n" + "=" * 74)
    okc = sum(1 for _, o, _ in results if o)
    print(f"汇总：防护生效 {okc}/{len(results)}")
    bad = [(n, d) for n, o, d in results if not o]
    if bad:
        print("\n需关注：")
        for n, d in bad:
            print(f"  - {n}\n      {d[:170]}")
    else:
        print("未发现可绕过项")


if __name__ == "__main__":
    main()
