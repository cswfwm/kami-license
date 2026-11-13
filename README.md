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

## 双层信封（v1.3.0 起）

请求与响应都必须套壳，服务器只接受加密请求。

### 请求（客户端 → 服务器）

```
内层明文 = { action, code, device, device_id, ts, nonce, pubkey, sig, ... }
  1. AES-256-CBC(key1) 后追加 HMAC-SHA256(mac1)
  2. gzip 压缩
  3. AES-256-CBC(key2)
  4. 包成 {"e": "<base64url>"}
```

### 响应（服务器 → 客户端）

```
业务 JSON
  1. AES-256-CBC(key1) + HMAC-SHA256(mac1)
  2. gzip
  3. AES-256-CBC(key2)
  4. 用服务端 ECDSA 私钥对 "e" 字符串签名
  → {"e": "<base64url>", "s": "<base64url 签名>"}
```

**客户端必须先验 `s` 再解密。** 这是判定「响应是否来自真实服务器」的唯一可靠手段：
伪装服务器即使拿到了全部对称密钥，也没有服务端私钥，签不出能通过的 `s`。

错误响应同样走加密信封，所以连「卡密不存在」这种信息也无法被中间人伪造或篡改。

### 已验证的攻击拦截

| 攻击 | 结果 |
|---|---|
| 伪造服务器用自己的密钥签名 | 拒绝（响应签名校验失败） |
| 篡改响应载荷但沿用原签名 | 拒绝 |
| 去掉签名 | 拒绝 |
| 发送明文请求 | HTTP 400 + 加密错误响应 |
| 重放旧时间戳的加密包 | `bad_timestamp` |
| 内层 action 与 URL 不一致 | `bad_action` |

### 坦诚说明

对称密钥（key1/mac1/key2）随 APK/EXE 分发，`strings` 即可提取，这是任何自带密钥方案的固有限制。
它的作用是挡住随手抓包、抓到的包不可直接阅读、批量脚本需要先实现协议；
**真正的真伪判定由 ECDSA 验签承担**，这一层是可靠的。

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
