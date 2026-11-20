# kami-license

PHP 卡密（授权码）服务 + Android 验签客户端。功能分级授权，服务端 ECDSA 签名，客户端只持公钥。

线上地址：<http://xxxxx-x.uuk.pp.ua>

## 能力

| 项目 | 说明 |
|---|---|
| 功能分级 | 卡密按套餐下发 `features` 数组，客户端按 key 解锁功能 |
| 防伪造 | 响应用 ECDSA P-256/SHA-256 签名，客户端内置公钥验签 |
| 设备绑定 | 每张卡密限 N 台设备，绑定 ANDROID_ID 派生指纹 |
| 到期控制 | 按天计费或永久；到期后进入 3 天离线宽限期，之后强制联网 |
| 防重放 | 校验请求带 nonce + ts，服务端 10 分钟窗口去重 |
| 后台管理 | 生成/停用卡密、查看设备、解绑、调用日志 |

## 目录

```
api.php                 客户端接口（plans / activate / verify）
admin.php               管理后台
install.php             一次性建表脚本（装完即删）
lib/
  bootstrap.php         配置加载、JSON 输出、请求解析
  db.php                PDO + 建表 SQL
  plans.php             套餐与功能清单
  license.php           ECDSA 签发、卡密生成
  api.php               三个接口的业务逻辑
  auth.php              后台登录与 CSRF
  web/layout.php        页面框架
  web/pages.php         概览/卡密/设备/日志
  web/actions.php       后台表单动作
android/
  LicenseClient.java    客户端主类（激活、复验、验签、功能判断）
  AesCbc.java           纯 Java AES-128-CBC（解主机前置挑战）
  Base64Url.java        base64url 解码
tools/
  deploy.py             FTP 部署
  e2e_test.py           端到端测试（17 项）
  uuk_client.py         带 __test 挑战求解的 HTTP 客户端
  public_key.pem        公钥
```

## 套餐与功能

在 [lib/plans.php](lib/plans.php) 里改，新增功能只需往 `features` 里加 key：

| plan | 天数 | 设备 | features |
|---|---|---|---|
| basic | 永久 | 1 | core |
| pro | 365 | 1 | core, export, batch |
| trial7 | 7 | 1 | core, export |
| team | 365 | 3 | core, export, batch, api |

## 接口

### `GET /api.php?action=plans`
返回套餐清单，客户端可用它动态渲染购买页。

### `POST /api.php?action=activate`

```json
{"code":"ABCD-EFGH-IJKL-MNOP","device_id":"a1b2c3d4-e5f6g7h8","device_name":"Pixel","app_version":"1.0.0"}
```

成功返回：

```json
{"ok":true,"license":"<base64url payload>","sig":"<base64url ECDSA 签名>","server_time":1794502101}
```

payload 解码后：

```json
{"v":1,"card":1,"mask":"ABCD-****-****-MNOP","plan":"pro",
 "features":["core","export","batch"],"device":"a1b2c3d4-e5f6g7h8",
 "issued_at":1794502101,"expire_at":1826038101,"grace_until":1826297301}
```

### `POST /api.php?action=verify`

```json
{"code":"ABCD-EFGH-IJKL-MNOP","device_id":"a1b2c3d4-e5f6g7h8",
 "nonce":"3f9c...（16 字节 hex）","ts":1794502101}
```

错误码：

| error | 含义 |
|---|---|
| `invalid_code` | 卡密不存在 |
| `disabled` | 已被管理员停用 |
| `expired` | 已过期 |
| `device_mismatch` | 该设备未激活此卡密 |
| `device_limit` | 达到设备数上限 |
| `device_revoked` | 该设备被解绑 |
| `replay` | nonce 重复（重放） |
| `bad_timestamp` | 客户端时间偏差超 10 分钟 |
| `too_many` | 同 IP 一小时内失败过多 |

## ECIES 非对称加密（v1.4.0 起）

服务端**不再持有任何预置对称密钥**。每次请求用 ECDH 临时协商，客户端只内置服务端公钥。

```
客户端：
  1. 生成临时 EC P-256 密钥对 (e_priv, e_pub)
  2. shared = ECDH(e_priv, server_pub)
  3. key    = HKDF-SHA256(shared, salt, info="kami-v1")
  4. (ct, tag) = AES-256-GCM(key, iv, 明文)
  5. 发送 {epk, salt, iv, ct, tag}

服务端：
  shared = ECDH(server_priv, epk)   → 同一把 key → 解密
  响应用同一把 key 加密回传 {iv, ct, tag}
```

**这是真正的非对称加密**：抓包者只能看到临时公钥 `epk`，没有服务端私钥就无法推出 `shared`。
即使完全逆向 APK/EXE，也无法解开**别人**的请求——因为每次请求的会话密钥都不同。

服务端配置：`lib/config.php` 的 `ec_priv`（EC 私钥 PEM），公钥 SEC1 硬编码在三个客户端里。

### 已验证

| 场景 | 结果 |
|---|---|
| 正常加密通信 | PASS |
| 截获密文尝试解密 | 失败（GCM 认证不通过） |
| 用错误公钥协商 | 服务端 `bad_envelope` |
| 篡改 GCM tag | 服务端拒绝 |
| 重放旧时间戳 | `bad_timestamp` |
| 明文请求 | `请求必须加密` |

## 设备专属密钥（v1.1.0 起）

每个请求都必须由设备自己的私钥签名，APK 内**不含任何共享对称密钥**。

首次激活时客户端生成 ECDSA P-256 密钥对，只把公钥交给服务端存进 `device_keys`；
之后 `verify` 用本机私钥签名，服务端拿已注册的公钥验签。

签名覆盖内容（换动作、换设备、改时间戳都会导致验签失败）：

```
<action>\n<device_id>\n<ts>\n<nonce>
```

错误码补充：

| error | 含义 |
|---|---|
| `missing_signature` | 请求未带 `sig` |
| `bad_signature` | 签名与已注册公钥不匹配 |
| `device_unknown` | 该设备未注册密钥（仅激活时允许注册） |

取舍：这挡不住别人为自己那台新设备走一遍合法注册，真正的授权裁决仍在服务端
（卡密状态、设备上限、功能列表）。它解决的是「逆向 APK 后拿到万能钥匙」。

## Android 接入

把 [android/](android/) 下三个类放进工程（包名 `com.kami.license` 或自行改），加两条权限：

```xml
<uses-permission android:name="android.permission.INTERNET"/>
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/>
```

调用：

```java
LicenseClient lic = new LicenseClient(context);

// 用户输入卡密后激活
LicenseClient.Result r = lic.activate(code);
if (!r.ok) {
    toast(r.error + ": " + r.message);   // 具体失败原因
    return;
}

// 每次启动复验一次；失败可先按本地缓存放行，超过宽限期再拦
LicenseClient.Result v = lic.verify(code);

// 判断功能
if (lic.hasFeature("export")) {
    enableExport();
}
```

要点：

- **不要在 `hasFeature` 之外信任本地状态**。真正值钱的功能，数据或参数应由服务端下发，而不是仅靠客户端一个 if。
- 卡密代码存 `SharedPreferences`，`verify` 每次启动调用一次即可，别每次点击都请求。
- 到期后 `isExpiredLocally()` 会返回 true，但宽限期内仍应放行；超过宽限期必须联网成功。
- 客户端内置的只有公钥（`LicenseClient.PUBLIC_KEY_PEM`），泄露无风险。

## 部署

```bash
# 1. 上传（密码走环境变量，不落盘）
FTP_PASS=*** python3 tools/deploy.py

# 2. 首次安装（install.key 在 _data/install.key）
curl -A 'Mozilla/5.0 (compatible; Googlebot/2.1)' \
  "http://xxxxx-x.uuk.pp.ua/install.php?key=<install.key>"

# 3. 装完立刻删除 install.php 与 _data/install.key
```

### 该主机的两个硬约束

1. **前置 AES 挑战**：非 Googlebot UA 会收到 `aes.js` 挑战页，必须在客户端算出 `__test` cookie 才能访问。`LicenseClient.solveChallenge()` 已实现，**不要改 User-Agent**。
2. **open_basedir**：PHP 只能读 `htdocs` 内的文件，因此私钥放在 `_data/private_key.pem`，靠 `_data/.htaccess` 的 `Require all denied` 挡住外网（已验证返回 403）。

## 验证

```bash
KAMI_ADMIN_PASS=*** python3 tools/e2e_test.py
```

覆盖：后台登录、生成卡密、激活、features 下发、设备上限、校验、重放拦截、时间偏差、换机拦截、签名有效性与篡改检测、停用后拒绝。

## 运行期自检（v1.4.0 起）

`RuntimeGuard` 每 60 秒执行一次：

1. **联网探测**：直连 `baidu.com:443`（3 秒超时，失败换 `www.baidu.com`）。
   用 TCP 连接而不是 ping，因为 ICMP 常被网络屏蔽。
2. **反调试**：`Debug.isDebuggerConnected()`、`/proc/self/status` 的 `TracerPid`、
   frida 默认端口 27042。

检测到调试环境时在界面上提示，不直接退出——避免误伤用户，也方便调试自己的构建。
这类检测都能被 hook 绕过，作用是抬高门槛并留下线索，不是不可突破的防护。

## 功能数据下发（v1.7.0 起）

客户端只持有加密后的功能数据，解密密钥只能从服务端拿。**服务端不可达就没有可用数据**，
这是把授权判断彻底放服务端的落地方式，用于封堵离线破解。

### 接口

`activate` / `verify` 的响应中附带 `data` 字段，也可用 `?action=data` 单独拉取：

```json
{"data": {"iv": "...", "ct": "...", "tag": "...", "key": "<64 hex>", "bind": "...", "ttl": 600}}
```

- `iv/ct/tag`：AES-256-GCM 加密的功能数据
- `key`：解密密钥，由 `HMAC-SHA256(服务端私钥签名, "feature-data-v1|device|licenseSig")` 派生
- `ttl`：建议刷新周期

`action=data` 的额外校验：license 必须由本服务端签发、设备必须已绑定、
卡密状态不能是停用或过期。这样停用一张卡可以立即断掉它的数据供给。

### 客户端要求

- 授权成立 = license 验签通过 **且** 功能数据解密成功
- 任一条不满足即视为未授权（`FeatureData.load(ctx) == null` 让 `isAuthorized()` 返回 false）

### 实测

| 场景 | 结果 |
|---|---|
| 联网激活 | 成功，拿到 114 字节已解密数据 |
| 断网启动 | 「无法连接服务器」，拒绝且不崩溃 |
| 已激活后断网 | 拿不到 data，判定未授权 |
| 伪造 license | 验签拒绝 |
| 自造功能数据 | 无服务端派生的 key，客户端不采用 |

### 边界

`key` 随数据一起下发，所以**抓包者本人能解自己那一份**。
它防的是「本地伪造」和「离线绕过」，不防「把自己的数据拷给别人」——
后者由设备绑定（license 内嵌 device）和签名验签负责。

## 响应签名（v1.9.0 补上）

此前 `ecies_seal_response` 只有 `iv/ct/tag`，**没有签名**——文件头注释写了验签，代码里漏了。
渗透测试报告中这一点属实，已修复。

### 现状

```php
// 对 iv||ct||tag 的原始字节签名（不经过 base64，避免换行差异）
openssl_sign($iv . $ct . $tag, $sig, $sign_key, OPENSSL_ALGO_SHA256);
return ['iv'=>..., 'ct'=>..., 'tag'=>..., 's'=>b64u($sig)];
```

客户端 `openResponse()` 先验签再解密，三端一致（Android / Windows / 参考实现）。

### 实测

| 场景 | 结果 |
|---|---|
| 真实响应验签 | PASS |
| 篡改 ct 一个字节 | 拒绝 |
| 去掉 s 字段 | 拒绝 |

### 澄清攻击前提

报告称「假服务器用公开公钥完成 ECDH 得到相同 sessionKey」——**这一步不成立**。
客户端算的是 `ECDH(临时私钥, 服务端公钥)`，假服务器要复现必须有**服务端私钥**。
实测：客户端密钥 `2abf48b6...`，攻击者独立算出的 `72bdfa8e...`，不相同。

因此真实风险是「响应完整性缺失」（可被注入/篡改），
不是「攻击者能凭空构造可解密的响应」。加了签名后两者都不成立。

## 后台安全（v2.0.0）

针对「后台被攻击」的加固。客户端再牢，后台被打穿就等于直接发卡。

### 已实测的防护

| 攻击 | 结果 |
| --- | --- |
| 未登录直接 POST 发卡/停卡/解绑 | 302 跳登录，拦截 |
| 伪造 KAMISID 会话 | 302，拦截 |
| 登录 SQL 注入（`admin'--` / `' OR 1=1--`） | 拒绝 |
| 越权 ID 遍历（未登录改任意卡状态） | 302，拦截 |
| 连续错误密码 | 第 6 次起 429，锁 1 小时 |
| 无 CSRF 令牌提交 | 400 |
| HTTP 访问后台 | 301 强制跳 HTTPS |
| `lib/` `_data/` `.pem` `.json` `.log` | 403 |

### 强制 HTTPS 的注意点

只对 `admin.php` / `index.php` 做跳转，**不碰 `api.php`**。
因为客户端跟随 301 会把 POST 变成 GET 并丢弃请求体，那样所有客户端都会失效。
接口的机密性由 ECIES 自身保证，不依赖传输层跳转。

### 操作审计（`lib/audit.php`）

后台一旦被攻破，攻击者做的是「发卡、停卡、解绑」这类正常操作，单看数据分不出是谁干的。
所以记录每次操作的 action / target / IP / UA / 时间，写库而非文件（`open_basedir` 限制）。

入口：后台「操作审计」页，同时展示：

- 最近 200 条管理操作
- **异常活动**：同一 IP 10 分钟内 ≥30 次管理操作
- **数据自检**：
  - 24 小时内无备注的发卡数（>20 提示，可能是脚本直接写库）
  - 绑定设备数超过上限的卡密
  - 同一设备绑定多张有效卡的异常

### 运维建议

1. 发现异常活动或数据自检报警，立即改管理员密码
2. 定期看审计页，确认发卡数量与自己的操作一致
3. 数据库密码与主机密码当前相同（`20130401kyz`），建议改成各自独立的强密码
