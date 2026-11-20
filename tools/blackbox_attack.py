#!/usr/bin/env python3
"""kami-license 服务端黑盒攻击测试。

覆盖：响应篡改、重放、时效绕过、畸形输入、越权降级、并发竞争、限流。
只发请求，不修改任何服务端代码。
"""
import base64
import gzip
import hashlib
import hmac
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

K1 = bytes.fromhex("434867350eeff8e80b9e45945efc788a4ebf53c8aac3a53b5cbad8e6de809e31")
M1 = bytes.fromhex("49d51644a975002e2b3fc7a560fa69aeeb7fb67c16ab7453cb1feed105328df1")
K2 = bytes.fromhex("93753a96158e8f95de1f388eb5680d2c932ad1b58640f0c9d50d21b3f875a935")

BASE = "http://xxxxx-x.uuk.pp.ua"
PUBKEY = os.path.join(HERE, "public_key.pem")

results = []


def rec(name, ok, detail):
    results.append((name, ok, detail))
    print(f"  [{'✓ 挡住' if ok else '✗ 可绕过'}] {name}")
    print(f"        {detail}")


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64u_dec(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def aes_enc(key, plain):
    iv = os.urandom(16)
    p = subprocess.run(["openssl", "enc", "-aes-256-cbc", "-K", key.hex(),
                        "-iv", iv.hex()], input=plain, capture_output=True, check=True)
    return iv + p.stdout


def aes_dec(key, data):
    iv, ct = data[:16], data[16:]
    p = subprocess.run(["openssl", "enc", "-d", "-aes-256-cbc", "-K", key.hex(),
                        "-iv", iv.hex()], input=ct, capture_output=True)
    return p.stdout


def build_body(inner):
    raw = json.dumps(inner, separators=(",", ":"), ensure_ascii=False).encode()
    mac = hmac.new(M1, raw, hashlib.sha256).digest()
    return aes_enc(K2, gzip.compress(mac + raw))


def parse_resp(body):
    """返回 (payload, raw_obj, verified)。verified=签名与 MAC 都通过。"""
    try:
        obj = json.loads(body)
    except Exception:
        return None, None, None
    if "e" not in obj or "s" not in obj:
        return None, obj, None
    sig_ok = False
    try:
        with open("/tmp/_sig.bin", "wb") as fh:
            fh.write(b64u_dec(obj["s"]))
        with open("/tmp/_msg.txt", "wb") as fh:
            fh.write(obj["e"].encode())
        r = subprocess.run(["openssl", "dgst", "-sha256", "-verify", PUBKEY,
                            "-signature", "/tmp/_sig.bin", "/tmp/_msg.txt"],
                           capture_output=True)
        sig_ok = b"Verified OK" in r.stdout
    except Exception:
        pass
    try:
        l1 = aes_dec(K2, b64u_dec(obj["e"]))
        gz = gzip.decompress(l1) if l1[:2] == b"\x1f\x8b" else l1
        mac, payload = gz[:32], gz[32:]
        mac_ok = hmac.compare_digest(mac, hmac.new(M1, payload, hashlib.sha256).digest())
        return json.loads(payload), obj, sig_ok and mac_ok
    except Exception:
        return None, obj, sig_ok


def post(inner, client=None):
    c = client or UukClient(BASE)
    return c.post_json("/api.php", {"e": b64u(build_body(inner))})


def txt(payload, raw):
    if payload is not None:
        return json.dumps(payload, ensure_ascii=False)[:150]
    if raw is not None:
        return json.dumps(raw, ensure_ascii=False)[:150]
    return "(无法解析)"


def main():
    print("=" * 72)
    print("kami-license 服务端黑盒攻击测试")
    print("=" * 72)

    # ---------- 0 基线 ----------
    print("\n[0] 基线：正常 plans 请求")
    base_inner = {"action": "plans", "ts": int(time.time()),
                  "nonce": secrets.token_hex(8)}
    resp = post(base_inner)
    payload, raw, verified = parse_resp(resp)
    print(f"  {len(resp)}B  签名+MAC 校验={verified}")
    print(f"  {txt(payload, raw)}")

    # ---------- 1 响应篡改 ----------
    print("\n[1] 响应篡改：客户端能否识别伪造响应")
    if raw and "e" in raw:
        t1 = dict(raw)
        e = t1["e"]
        mid = len(e) // 2
        t1["e"] = e[:mid] + ("A" if e[mid] != "A" else "B") + e[mid + 1:]
        p, _, v = parse_resp(json.dumps(t1).encode())
        rec("篡改信封 e", (v is False) or (p is None),
            f"验签={v} 解密={'成功' if p else '失败'}")

        t2 = dict(raw)
        s = t2["s"]
        t2["s"] = ("A" if s[0] != "A" else "B") + s[1:]
        p, _, v = parse_resp(json.dumps(t2).encode())
        rec("篡改签名 s", v is False, f"验签={v}")
    else:
        print("  跳过：基线响应无 e 字段")

    # ---------- 2 重放 ----------
    print("\n[2] 重放：相同 nonce 再次提交")
    n = secrets.token_hex(8)
    inner = {"action": "verify", "code": "TEST-REPLAY-0001",
             "device": "dev-replay", "ts": int(time.time()), "nonce": n}
    r1 = post(inner)
    p1, _, _ = parse_resp(r1)
    print(f"  首次: {txt(p1, None)}")
    r2 = post(inner)
    p2, _, _ = parse_resp(r2)
    print(f"  重放: {txt(p2, None)}")
    blocked = False
    if p2 is not None:
        t = json.dumps(p2, ensure_ascii=False).lower()
        blocked = ("nonce" in t) or ("replay" in t) or ("重放" in t) or (p2.get("ok") is False)
    rec("相同 nonce 重放", blocked, txt(p2, None))

    # ---------- 3 时效 ----------
    print("\n[3] 时效绕过：ts 时间戳偏移")
    for label, delta in [("过去 11 分钟", -660), ("过去 1 小时", -3600),
                         ("未来 1 小时", 3600), ("ts=0", 0)]:
        inner = {"action": "verify", "code": "TEST-TS-0001", "device": "dev-ts",
                 "ts": delta if delta == 0 else int(time.time()) + delta,
                 "nonce": secrets.token_hex(8)}
        r = post(inner)
        p, _, _ = parse_resp(r)
        t = txt(p, r[:120].decode("utf-8", "replace") if not p else None)
        lower = t.lower()
        blocked = any(k in lower for k in
                      ["ts", "时间", "过期", "expire", "invalid", "stale"])
        rec(f"{label} ts", blocked, t)

    # ---------- 4 畸形输入 ----------
    print("\n[4] 畸形输入：服务端稳健性")
    cases = [
        ("空对象", {}),
        ("e 空串", {"e": ""}),
        ("e 非法 base64", {"e": "!!!not-base64!!!"}),
        ("e 随机字节", {"e": b64u(os.urandom(64))}),
        ("超长 e(200KB)", {"e": "A" * 200000}),
        ("缺 s 字段", {"e": b64u(os.urandom(32))}),
        ("类型错误", {"e": 12345, "s": []}),
        ("SQL 注入串", {"e": "'; DROP TABLE cards; --"}),
        ("路径穿越", {"e": "../../../etc/passwd"}),
        ("null 值", {"e": None, "s": None}),
    ]
    for label, body in cases:
        try:
            cl = UukClient(BASE)
            r = cl.post_json("/api.php", body)
            t = r[:130].decode("utf-8", "replace")
            leaky = any(k in t.lower() for k in
                        ["fatal error", "warning:", "notice:", "stack trace",
                         "syntax error", "pdoexception", "undefined index",
                         "undefined variable", "deprecated"])
            rec(label, not leaky, f"{len(r)}B {t[:110]}")
        except Exception as ex:
            rec(label, False, f"异常 {str(ex)[:70]}")

    # ---------- 5 越权降级 ----------
    print("\n[5] 越权与降级")
    probes = [
        ("action=admin (不存在)", {"action": "admin", "ts": int(time.time()),
                                 "nonce": secrets.token_hex(8)}),
        ("action=list_cards", {"action": "list_cards", "ts": int(time.time()),
                               "nonce": secrets.token_hex(8)}),
        ("伪造 plan=team", {"action": "activate", "code": "X", "device": "d",
                            "plan": "team", "ts": int(time.time()),
                            "nonce": secrets.token_hex(8)}),
        ("伪造 features 全开", {"action": "verify", "code": "X", "device": "d",
                               "features": ["core", "export", "batch", "admin"],
                               "ts": int(time.time()),
                               "nonce": secrets.token_hex(8)}),
        ("伪造 max_devices=999", {"action": "activate", "code": "X", "device": "d",
                                  "max_devices": 999, "ts": int(time.time()),
                                  "nonce": secrets.token_hex(8)}),
    ]
    for label, inner in probes:
        r = post(inner)
        p, _, _ = parse_resp(r)
        t = txt(p, None)
        lower = t.lower()
        leaked = any(k in lower for k in ['"cards"', "all_cards", '"api_keys"',
                                          '"admin":true', "admin\": true"])
        granted = ('"team"' in lower and '"ok":true' in lower) or \
                  ('"admin"' in lower and '"features"' in lower and '"ok":true' in lower)
        rec(label, not (leaked or granted), t)

    # ---------- 6 并发竞争 ----------
    print("\n[6] 并发竞争：同一 nonce 并发 8 次")
    n = secrets.token_hex(8)
    inner = {"action": "verify", "code": "TEST-RACE-0001", "device": "dev-race",
             "ts": int(time.time()), "nonce": n}
    body = {"e": b64u(build_body(inner))}

    def one(_i):
        try:
            cl = UukClient(BASE)
            r = cl.post_json("/api.php", body)
            p, _, _ = parse_resp(r)
            return json.dumps(p, ensure_ascii=False)[:70] if p else "?"
        except Exception as ex:
            return f"ERR:{str(ex)[:30]}"

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        outs = list(ex.map(one, range(8)))
    uniq = {}
    for o in outs:
        uniq[o] = uniq.get(o, 0) + 1
    print(f"  响应去重: {len(uniq)} 种")
    for k, v in list(uniq.items())[:4]:
        print(f"    ×{v}  {k}")
    rec("并发同 nonce", len(uniq) <= 2,
        f"{len(uniq)} 种不同响应（>2 说明 nonce 校验有竞态窗口）")

    # ---------- 7 限流 ----------
    print("\n[7] 限流：连续 35 次失败")
    cl = UukClient(BASE)
    seen = []
    for i in range(35):
        inner = {"action": "verify", "code": f"WRONG-{i:04d}",
                 "device": "dev-flood", "ts": int(time.time()),
                 "nonce": secrets.token_hex(8)}
        try:
            r = post(inner, cl)
            p, _, _ = parse_resp(r)
            seen.append(json.dumps(p, ensure_ascii=False)[:70] if p else "?")
        except Exception as ex:
            seen.append(f"ERR:{str(ex)[:30]}")
    limited = any(("too_many" in s) or ("频繁" in s) or ("limit" in s.lower())
                  for s in seen)
    rec("失败次数限流(>30)", limited, f"末尾响应: {seen[-2:]}")

    # ---------- 汇总 ----------
    print("\n" + "=" * 72)
    print("汇总")
    print("=" * 72)
    okc = sum(1 for _, ok, _ in results if ok)
    print(f"防护生效: {okc}/{len(results)}")
    bad = [(n, d) for n, ok, d in results if not ok]
    print("\n需要关注：" if bad else "\n未发现可绕过项")
    for n, d in bad:
        print(f"  - {n}")
        print(f"      {d[:160]}")


if __name__ == "__main__":
    main()
