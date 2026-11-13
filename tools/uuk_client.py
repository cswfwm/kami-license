#!/usr/bin/env python3
"""与 uuk 免费主机通信的 HTTP 客户端。

该主机前置 openresty 会对非 Googlebot 的 UA 下发 AES 挑战（aes.js + __test cookie）。
本模块复现该挑战：用页面给的 key/iv 做 AES-128-CBC 解密，把结果作为 __test cookie。

用法：
    from uuk_client import UukClient
    c = UukClient('http://xxxxx-x.uuk.pp.ua')
    print(c.get('/api.php?action=plans'))
"""
import base64
import hashlib
import http.cookiejar
import re
import struct
import urllib.error
import urllib.parse
import urllib.request

AES_SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]
AES_RCON = [0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]


def _xtime(a: int) -> int:
    a <<= 1
    return (a ^ 0x1b) & 0xff if a & 0x100 else a


def _mul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        b >>= 1
        a = _xtime(a)
    return p


def _expand_key(key: bytes) -> list[int]:
    nk = len(key) // 4
    nr = nk + 6
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        temp = list(w[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [AES_SBOX[b] for b in temp]
            temp[0] ^= AES_RCON[i // nk]
        elif nk > 6 and i % nk == 4:
            temp = [AES_SBOX[b] for b in temp]
        w.append([w[i - nk][j] ^ temp[j] for j in range(4)])
    return [b for word in w for b in word]


def _inv_shift_rows(s: list[int]) -> list[int]:
    return [s[0], s[13], s[10], s[7],
            s[4], s[1], s[14], s[11],
            s[8], s[5], s[2], s[15],
            s[12], s[9], s[6], s[3]]


INV_SBOX = [0] * 256
for _i, _v in enumerate(AES_SBOX):
    INV_SBOX[_v] = _i


def aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    rk = _expand_key(key)          # 扁平字节序列，每 16 字节一轮密钥
    nr = len(key) // 4 + 6
    out = bytearray()
    prev = iv
    for off in range(0, len(data) - len(data) % 16, 16):
        block = list(data[off:off + 16])
        base = 16 * nr
        s = [block[i] ^ rk[base + i] for i in range(16)]
        for rnd in range(nr - 1, 0, -1):
            s = _inv_shift_rows(s)
            s = [INV_SBOX[b] for b in s]
            base = 16 * rnd
            s = [v ^ rk[base + i] for i, v in enumerate(s)]
            t = [0] * 16
            for c in range(4):
                col = s[4 * c:4 * c + 4]
                t[4 * c + 0] = _mul(col[0], 14) ^ _mul(col[1], 11) ^ _mul(col[2], 13) ^ _mul(col[3], 9)
                t[4 * c + 1] = _mul(col[0], 9) ^ _mul(col[1], 14) ^ _mul(col[2], 11) ^ _mul(col[3], 13)
                t[4 * c + 2] = _mul(col[0], 13) ^ _mul(col[1], 9) ^ _mul(col[2], 14) ^ _mul(col[3], 11)
                t[4 * c + 3] = _mul(col[0], 11) ^ _mul(col[1], 13) ^ _mul(col[2], 9) ^ _mul(col[3], 14)
            s = t
        s = _inv_shift_rows(s)
        s = [INV_SBOX[b] for b in s]
        s = [v ^ rk[i] for i, v in enumerate(s)]
        out.extend(bytes(a ^ b for a, b in zip(s, prev)))
        prev = bytes(block)
    return bytes(out)


CHALLENGE_RE = re.compile(rb'toNumbers\("([0-9a-f]+)"\)')


class UukClient:
    def __init__(self, base: str, ua: str = 'Mozilla/5.0 (Linux; Android 5.1; MI 8) AppleWebKit/537.36 Chrome/50.0 Mobile Safari/537.36'):
        self.base = base.rstrip('/')
        self.ua = ua
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def _request(self, path: str, data: bytes | None = None, headers: dict | None = None) -> tuple[int, bytes]:
        url = self.base + path if path.startswith('/') else path
        req = urllib.request.Request(url, data=data, method='POST' if data is not None else 'GET')
        req.add_header('User-Agent', self.ua)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with self.opener.open(req, timeout=30) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def _solve_challenge(self, body: bytes, path: str) -> bool:
        parts = CHALLENGE_RE.findall(body)
        if len(parts) < 3:
            return False
        key = bytes.fromhex(parts[0].decode())
        iv = bytes.fromhex(parts[1].decode())
        ct = bytes.fromhex(parts[2].decode())
        plain = aes_cbc_decrypt(key, iv, ct)
        cookie = plain.hex()
        host = urllib.parse.urlparse(self.base).hostname or ''
        c = http.cookiejar.Cookie(
            version=0, name='__test', value=cookie, port=None, port_specified=False,
            domain=host, domain_specified=True, domain_initial_dot=False,
            path='/', path_specified=True, secure=False, expires=None,
            discard=False, comment=None, comment_url=None, rest={})
        self.jar.set_cookie(c)
        return True

    def get(self, path: str, headers: dict | None = None) -> bytes:
        body = b''
        for _ in range(3):
            status, body = self._request(path, None, headers)
            if b'slowAES.decrypt' in body and self._solve_challenge(body, path):
                continue
            if body:
                return body
        return body

    def post_json(self, path: str, payload: dict) -> bytes:
        import json
        data = json.dumps(payload).encode()
        hdrs = {'Content-Type': 'application/json'}
        return self._send_retry(path, data, hdrs)

    def post_form(self, path: str, fields: dict) -> bytes:
        data = urllib.parse.urlencode(fields).encode()
        hdrs = {'Content-Type': 'application/x-www-form-urlencoded'}
        return self._send_retry(path, data, hdrs)

    def _send_retry(self, path: str, data: bytes, hdrs: dict) -> bytes:
        """主机在无 __test cookie 时会让 POST 返回空响应，需重试一次。"""
        last = b''
        for _ in range(4):
            status, body = self._request(path, data, hdrs)
            if b'slowAES.decrypt' in body:
                self._solve_challenge(body, path)
                continue
            if body:
                return body
            last = body
            # 空响应：先完成一次 GET 以取得挑战 cookie，再重试 POST
            self.get(path)
        return last
