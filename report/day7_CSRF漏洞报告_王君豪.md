# Day 7 — CSRF 漏洞审计与修复报告

**王君豪-2024141530115**

| 字段 | 值 |
|------|------|
| 报告编号 | DAY7-CSRF-20260724 |
| 目标地址 | `http://192.168.137.129:5000` |
| 应用名称 | 用户管理系统（Flask + SQLite） |
| 审计日期 | 2026-07-24 |
| 审计类型 | CSRF + 越权 + 密码修改安全 |
| 漏洞总数 | 5 个（高危 4，中危 1） |
| 修复状态 | ✅ 全部已修复 |

---

## 一、漏洞汇总

| 编号 | 漏洞名称 | 类型 | 等级 | 风险描述 | 位置 |
|------|---------|------|------|---------|------|
| V-01 | `/change-password` 无 CSRF Token 保护 | CSRF | 🔴 高危 | 任意第三方网站可构造表单修改密码，无需 Token 校验 | `app.py:465` `@csrf.exempt` |
| V-02 | `/change-password` 无原密码校验 | 身份绕过 | 🔴 高危 | 知道用户名即可直接修改密码，无需验证原密码 | `app.py:476-481` 缺少 old_password 参数获取与校验 |
| V-03 | `/change-password` 无 Referer 校验 | CSRF | 🔴 高危 | 不验证请求来源，跨站请求可直接提交 | 默认行为，未添加任何来源检查 |
| V-04 | `/change-password` 可越权修改他人密码 | IDOR | 🔴 高危 | username 参数直接从表单获取，可指定任意用户 | `app.py:476` `request.form.get("username")` |
| V-05 | `SESSION_COOKIE_SECURE=False` 配置缺陷 | 配置 | 🟠 中危 | Cookie 无 Secure 属性，可通过 HTTP 明文传输 | `app.py:30` 硬编码为 False |

---

## 二、漏洞原理、利用方式与修复方案（逐漏洞详解）

---

### V-01：CSRF — 无 Token 保护

#### 漏洞原理

跨站请求伪造（CSRF）是指攻击者诱导已登录用户访问恶意页面，该页面自动向目标 Web 应用发送恶意请求，从而在用户不知情的情况下以用户身份执行操作。

**Flask-WTF CSRFProtect 的防护机制：**

```
正常请求流程：
┌─────────────┐      ┌──────────────┐      ┌──────────────┐
│  用户访问    │      │  服务器生成   │      │  表单嵌入    │
│  表单页面    │ ──→  │  CSRF Token  │ ──→  │  Token       │
└─────────────┘      └──────────────┘      └──────────────┘
                                                      │
┌─────────────┐      ┌──────────────┐                 │
│  Token匹配   │ ←──  │  提交表单    │ ←───────────────┘
│  → 请求合法  │      │  + Token     │
└─────────────┘      └──────────────┘

无 CSRF Token 时的攻击流程：
┌─────────────┐      ┌──────────────┐
│  攻击者构造  │      │  诱导受害者   │
│  恶意表单    │ ──→  │  访问页面    │
└─────────────┘      └──────────────┘
                             │
┌─────────────┐      ┌──────▼───────┐
│  ❌ 密码被改  │ ←──  │  表单自动提交 │
│  无需 Token  │      │  携带 Cookie │
└─────────────┘      └──────────────┘
```

#### 攻击复现（修复前）

**攻击者构造的恶意 HTML 页面：**
```html
<html>
<body>
    <h1>🎉 恭喜你获得 iPhone 抽奖资格！</h1>
    <p>点击下方按钮立即参与</p>
    <form action="http://192.168.137.129:5000/change-password" method="POST">
        <input type="hidden" name="username" value="admin">
        <input type="hidden" name="new_password" value="attacker123">
    </form>
    <script>document.forms[0].submit();</script>
</body>
</html>
```

**攻击链路：**
```
1. 管理员登录了用户管理系统（浏览器中 session Cookie 有效）
2. 管理员收到一封钓鱼邮件，点击链接访问攻击者的恶意页面
3. 恶意页面自动提交表单到 http://target/change-password
4. 浏览器自动携带管理员的 Session Cookie（SameSite=Lax 不阻止 POST）
5. 服务器收到请求 → 发现 @csrf.exempt → 不检查 CSRF Token → 密码被修改
6. 攻击者用新密码 attacker123 登录 → 完全接管管理员账号
```

**修复前验证：**
```bash
# 无需 CSRF Token、无需 Cookie，直接 POST 即可修改
curl -s -X POST http://192.168.137.129:5000/change-password \
  -d "username=admin&new_password=hacked123"

# → HTTP 302 重定向到 /profile
# → 密码已被修改为 hacked123

# 攻击者使用新密码登录成功
curl -s -X POST http://192.168.137.129:5000/login \
  -d "username=admin&password=hacked123"
# → 返回"欢迎回来，admin！" ✅ 攻击成功
```

#### 漏洞代码分析

```python
# app.py 第 463-465 行（修复前）

@app.route("/change-password", methods=["POST"])
@limiter.limit("10 per minute")
@csrf.exempt                    # ← 关键问题
def change_password():

```
`@csrf.exempt` 是 Flask-WTF 提供的装饰器，用于**豁免**某个路由的 CSRF 保护。Flask-WTF 的 `CSRFProtect` 中间件默认会拦截所有 POST 请求并验证 `csrf_token` 字段，但使用了 `@csrf.exempt` 后，该路由**完全不进行任何 CSRF 校验**。

`@csrf.exempt` 的设计初衷是用于 Webhook 回调、API 接口等由服务端发起的请求场景。**将其用于用户密码修改接口属于严重的安全配置错误。**

#### 修复方案

```python
# app.py 第 463-465 行（修复后）

@app.route("/change-password", methods=["POST"])
@limiter.limit("10 per minute")
def change_password():           # ← 移除 @csrf.exempt
```

**修复原理：** 移除 `@csrf.exempt` 后，`CSRFProtect` 中间件会自动拦截所有不带有效 `csrf_token` 的 POST 请求，返回 `HTTP 400 Bad Request`。

#### 模板修复

```html
<!-- templates/profile.html（修复后） -->
<form method="post" action="/change-password" class="login-form">
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
    <!--       ↑ 添加 CSRF Token 隐藏字段              -->
    <input type="hidden" name="username" value="{{ user.username }}">
    <div class="form-group">
        <label for="old_password">原密码</label>
        <input type="password" id="old_password" name="old_password" required>
    </div>
    ...
</form>
```

#### 修复前后对比

| 对比项 | 修复前 | 修复后 |
|--------|--------|--------|
| CSRF 保护 | `@csrf.exempt` 豁免 | 由 `CSRFProtect` 全局保护 |
| 无 Token 请求 | ✅ 200 成功（漏洞） | ❌ 400 拒绝 |
| 带 Token 请求 | ✅ 200 成功 | ✅ 302 成功 |
| 跨站伪造攻击 | ✅ 成功 | ❌ 400 拒绝 |

#### 修复验证

```bash
# 验证1：无 CSRF Token → 400 拒绝
curl -s -X POST http://192.168.137.129:5000/change-password \
  -d "username=admin&old_password=x&new_password=y"
# → HTTP 400 Bad Request  ✅

# 验证2：带正确 CSRF Token → 302 成功
# 先从 profile 页获取 CSRF Token
CSRF=$(curl -s http://192.168.137.129:5000/profile | grep -oP 'name="csrf_token" value="\K[^"]+')
# 提交修改
curl -s -X POST http://192.168.137.129:5000/change-password \
  -e "http://192.168.137.129:5000/profile" \
  -d "csrf_token=$CSRF&username=admin&old_password=admin123&new_password=newpass"
# → HTTP 302 Redirect  ✅

# 验证3：新密码可登录
curl -s -X POST http://192.168.137.129:5000/login \
  -d "username=admin&password=newpass"
# → 欢迎回来，admin！ ✅
```

---

### V-02：无原密码校验

#### 漏洞原理

密码修改功能应当验证用户的**原密码**，确保操作者是账号的合法持有者。缺少原密码校验意味着**只要知道用户名即可修改密码**，结合 V-04（越权）或 V-01（CSRF），攻击链的攻击成本极低。

#### 攻击流程

```
攻击方式1：已登录用户（如 alice）修改 admin 密码
  alice 登录 → POST /change-password → username=admin&new_password=evil
  → 不需要 admin 的原密码 → 直接修改成功

攻击方式2：CSRF 钓鱼（无原密码场景）
  管理员访问恶意页面 → 表单提交 username=admin&new_password=evil
  → 不需要原密码 → 密码被改 → 攻击者登录
```

#### 漏洞代码分析

```python
# app.py 第 476-481 行（修复前）

username = request.form.get("username", "")
new_password = request.form.get("new_password", "")
# ❌ 完全没有获取 old_password 参数
# ❌ 没有任何原密码校验逻辑

if not username or not new_password:
    return redirect("/profile")

hashed_pw = generate_password_hash(new_password)

# 直接更新密码，不验证原密码
if username in USERS:
    USERS[username]["password"] = hashed_pw      # ← 直接覆盖
else:
    conn.execute("UPDATE users SET password = ? WHERE username = ?",
                 (hashed_pw, username))          # ← 直接覆盖
```

**问题根因：** 原密码验证是密码修改功能的**第一道防线**。缺少此校验相当于"任何人只要触碰门把手，门就会自动打开"。

#### 修复方案

```python
# app.py 第 475-503 行（修复后）

old_password = request.form.get("old_password", "")

if not username or not new_password or not old_password:
    return redirect("/profile")

# ==== 原密码校验逻辑 ====
password_valid = False

# 1. 先查 USERS 字典（预置用户）
if username in USERS and check_password_hash(USERS[username]["password"], old_password):
    password_valid = True

# 2. 再查数据库（注册用户）
if not password_valid:
    db_user = get_user_from_db(username)
    if db_user and check_password_hash(db_user["password"], old_password):
        password_valid = True

# 3. 原密码错误 → 返回错误提示
if not password_valid:
    csrf_token = generate_csrf()
    user_info = get_user_by_id(session.get("user_id")) if session.get("user_id") else None
    return render_template("profile.html", user=user_info, error="原密码错误", csrf_token=csrf_token)

# 4. 原密码正确 → 才允许修改
hashed_pw = generate_password_hash(new_password)
...
```

**校验流程：**

```
用户提交表单
    │
    ▼
获取 old_password 参数
    │
    ▼
┌─────────────────────────────────────┐
│  USERS 字典中存在该用户？           │
│  ├── 是 → check_password_hash()    │
│  │    ├── 匹配 → password_valid ✅ │
│  │    └── 不匹配 → 查数据库        │
│  └── 否 → 查数据库                  │
└─────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────┐
│  password_valid 是否为 True？       │
│  ├── 是 → 生成新哈希 → 更新密码 ✅ │
│  └── 否 → "原密码错误" → 拒绝 ❌  │
└─────────────────────────────────────┘
```

#### 验证结果

```bash
# 验证1：错误原密码 → 拒绝
curl -X POST /change-password \
  -e "http://192.168.137.129:5000/profile" \
  -d "csrf_token=$CSRF&username=admin&old_password=wrongpassword&new_password=test"
# → 页面显示 <div class="error-msg">原密码错误</div>  ✅

# 验证2：正确原密码 → 通过
curl -X POST /change-password \
  -e "http://192.168.137.129:5000/profile" \
  -d "csrf_token=$CSRF&username=admin&old_password=admin123&new_password=test"
# → HTTP 302  ✅
```

---

### V-03：无 Referer 校验

#### 漏洞原理

HTTP `Referer` 头标识请求来源页面。Referer 校验是 CSRF 防御的**辅助手段**——服务器检查请求的 Referer 是否来自本站（同源），如果不是则拒绝。虽然 Referer 可以被修改（某些旧浏览器/插件可修改），但作为一种防御纵深措施，它可以阻止大多数基础的 CSRF 攻击。

#### 攻击场景

```
合法请求：           恶意请求：
用户访问 /profile    攻击者页面 evil.com
  → Referer: target    → Referer: evil.com
  → ✅ 同源通过         → ❌ 来源不匹配
```

#### 修复方案

```python
# app.py（新增，第 469-475 行）

from urllib.parse import urlparse   # 文件开头新增导入

# 在 change_password() 函数中，获取参数前添加：

# 获取 Referer 头
referer = request.headers.get("Referer", "")

# 防御1：拒绝无 Referer 的请求（可能是直接 curl 或伪造）
if not referer:
    return redirect("/profile")

# 防御2：解析 Referer 的 hostname
referer_host = urlparse(referer).hostname

# 防御3：获取当前请求的 host（去掉端口号）
request_host = request.host.split(":")[0]

# 防御4：比较是否同源
# 允许本机IP和hostname两种形式
if referer_host != request_host and referer_host != "192.168.137.129":
    return redirect("/profile")
```

**代码逐行解析：**

| 行 | 代码 | 作用 |
|----|------|------|
| `urlparse` | 导入 URL 解析库 | 从 `http://evil.com/page` 中提取 `evil.com` |
| `request.headers.get("Referer", "")` | 获取 Referer 头 | 如果不存在则返回空字符串 |
| `if not referer:` | 拒绝空 Referer | 直接 curl 请求没有 Referer |
| `urlparse(referer).hostname` | 提取域名 | `http://evil.com/path` → `evil.com` |
| `request.host.split(":")[0]` | 提取本机域名 | `192.168.137.129:5000` → `192.168.137.129` |
| `referer_host != request_host` | 比较主机 | 不同源则拒绝 |

#### 验证结果

```bash
# 验证1：本站 Referer → 通过
curl -X POST /change-password \
  -e "http://192.168.137.129:5000/profile" \
  -d "csrf_token=$CSRF&username=admin&old_password=admin123&new_password=test"
# → HTTP 302  ✅

# 验证2：外部 Referer → 拒绝
curl -X POST /change-password \
  -H "Referer: http://evil.com" \
  -d "csrf_token=$CSRF&username=admin&old_password=admin123&new_password=test"
# → HTTP 400（CSRF 保护）+ 或 302（Referer 校验拒绝） ✅

# 验证3：无 Referer → 拒绝
curl -X POST /change-password \
  -d "csrf_token=$CSRF&username=admin&old_password=admin123&new_password=test"
# → 302 重定向到 /profile  ✅
```

---

### V-04：可越权修改他人密码（IDOR）

#### 漏洞原理

IDOR（Insecure Direct Object Reference，不安全的直接对象引用）是指应用程序直接使用用户提供的参数来访问或修改资源，而未验证当前用户是否有权操作该资源。

在本漏洞中，`username` 参数直接来自 POST 表单，攻击者可以修改该参数值为任意用户名，从而修改其他用户的密码。

#### 攻击流程

```
alice 登录自己的账号
    │
    ▼
alice 打开浏览器开发者工具，修改表单中的 username
    │
    ▼
┌────────────────────────────────────────────┐
│  <input name="username" value="alice">      │
│                  ↓                          │
│  <input name="username" value="admin">      │  ← 修改
└────────────────────────────────────────────┘
    │
    ▼
提交表单 → 服务端直接使用表单中的 username=admin
         → admin 的密码被 alice 修改
```

#### 漏洞代码分析

```python
# app.py（修复前）

# 漏洞4：username 完全来自客户端的表单参数
username = request.form.get("username", "")   # ← 客户端可控

# 没有任何验证当前 session 用户是否等于 username
# ❌ 没有 session["username"] != username 的检查

# 直接使用 username 更新密码
if username in USERS:
    USERS[username]["password"] = hashed_pw   # ← 越权修改
```

#### 修复方案

```python
# app.py（修复后）

# 获取当前登录用户（来自 session，不可伪造）
current_user = session["username"]

# 获取表单提交的目标用户名
username = request.form.get("username", "")

# ✅ 核心修复：只能修改自己的密码
if username != current_user:
    return redirect("/profile")
```

**为什么这能修复越权：**

| 来源 | 可控性 | 安全性 |
|------|--------|--------|
| `session["username"]` | 服务端设置，客户端不可修改 | ✅ 可信 |
| `request.form.get("username")` | 客户端随意修改 | ❌ 不可信 |

修复后，即使客户端将表单中的 `username` 改为 `admin`，服务端比较后发现 `session["username"]`（alice）≠ `username`（admin），直接拒绝。

#### 验证结果

```bash
# 验证1：admin 登录后，尝试修改 alice 的密码 → 拒绝
CSRF=$(curl -s -b "session=admin_session" http://target/profile | grep -oP 'value="\K[^"]+')
curl -X POST /change-password \
  -e "http://192.168.137.129:5000/profile" \
  -b "session=admin_session" \
  -d "csrf_token=$CSRF&username=alice&old_password=alice2025&new_password=hacked"
# → 302 重定向到 /profile（拒绝）✅

# 验证2：alice 的原密码仍可登录
curl -X POST /login \
  -d "username=alice&password=alice2025"
# → 欢迎回来，alice！ ✅（密码未被篡改）
```

---

### V-05：SESSION_COOKIE_SECURE 配置缺陷

#### 漏洞原理

`SESSION_COOKIE_SECURE` 控制 Flask Session Cookie 的 `Secure` 属性。当设置为 `True` 时，浏览器仅通过 HTTPS 连接发送该 Cookie；设置为 `False` 时，HTTP 和 HTTPS 都会发送。

**风险分析：**

```
用户 → [HTTP 连接] → 服务器
         ↑
    Cookie 明文传输
    中间人可以截获 → Session 劫持 → 账号接管

用户 → [HTTPS 连接] → 服务器
         ↑
    Cookie 加密传输
    中间人无法截获 → 安全
```

#### 漏洞代码分析

```python
# app.py 第 28-35 行（修复前）

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,     # ← 硬编码为 False，始终不启用 Secure
    ...
)
```

**问题：** 硬编码 `False` 意味着无论部署在什么环境（开发/生产/HTTPS/HTTP），Cookie 都不带 `Secure` 属性。即使服务器配置了 HTTPS，Cookie 仍然可以通过 HTTP 传输，被中间人窃取。

#### 修复方案

```python
# app.py 第 28-35 行（修复后）

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # 生产环境（HTTPS）自动启用 Secure 属性
    # 设置 ENV=production 环境变量即可开启
    SESSION_COOKIE_SECURE=os.environ.get("ENV") == "production",
    ...
)
```

**修复原理：**

| 环境 | ENV 值 | SESSION_COOKIE_SECURE | 效果 |
|------|--------|----------------------|------|
| 开发环境 | 未设置 | `"" == "production"` → `False` | Cookie 可通过 HTTP 传输 |
| 生产环境 | `production` | `"production" == "production"` → `True` | Cookie 仅通过 HTTPS 传输 |

**部署使用方式：**
```bash
# 生产环境启动（自动启用 Secure）
ENV=production python app.py

# 开发环境启动（Secure 关闭，兼容 HTTP）
python app.py
```

#### 验证结果

```bash
# 验证：默认环境（开发）Cookie 无 Secure 属性
curl -s -I http://192.168.137.129:5000/ | grep Set-Cookie
# → Set-Cookie: session=...; HttpOnly; Path=/; SameSite=Lax
#    ↑ Secure 属性未出现（因为 ENV ≠ "production"）

# 生产环境下 Cookie 会包含 Secure 属性
# ENV=production python app.py
# → Set-Cookie: session=...; HttpOnly; Path=/; SameSite=Lax; Secure
```

---

## 三、修改文件清单

| 文件 | 修改类型 | 涉及漏洞 | 修改内容 |
|------|----------|---------|---------|
| `app.py` | 修改 | V-01 | 移除 `@csrf.exempt` 装饰器，启用 CSRF 保护 |
| `app.py` | 修改 | V-02 | 新增 `old_password` 参数获取，新增 `check_password_hash()` 原密码校验逻辑，校验失败返回错误提示 |
| `app.py` | 修改 | V-03 | 新增 `from urllib.parse import urlparse` 导入，新增 Referer 头获取与同源校验 |
| `app.py` | 修改 | V-04 | 新增 `session["username"]` 与表单 `username` 的比较校验，拒绝非本人操作 |
| `app.py` | 修改 | V-05 | `SESSION_COOKIE_SECURE=False` → `os.environ.get("ENV") == "production"` |
| `templates/profile.html` | 修改 | V-01, V-02 | 新增 `<input name="csrf_token">` 隐藏字段；新增原密码输入框 `<input name="old_password">` |

---

## 四、修复前 vs 修复后代码对比

### /change-password 路由

| 对比项 | 修复前 | 修复后 |
|--------|--------|--------|
| 路由装饰器 | `@csrf.exempt` | 无豁免 |
| 原密码校验 | ❌ 无 | ✅ `check_password_hash()` |
| Referer 校验 | ❌ 无 | ✅ `urlparse()` 同源检查 |
| 身份校验 | ❌ 仅检查有 session | ✅ `session["username"] == username` |
| 越权防护 | ❌ 表单 username 直接使用 | ✅ 以 session 为准 |

### session 配置

| 对比项 | 修复前 | 修复后 |
|--------|--------|--------|
| `SESSION_COOKIE_SECURE` | `False`（硬编码） | `os.environ.get("ENV") == "production"` |

---

## 五、修复验证结果

### 安全测试

| 测试项 | 对应漏洞 | 结果 |
|--------|---------|------|
| 无 CSRF Token 修改密码 | V-01 | ✅ 400 拒绝 |
| 带正确 Token 修改密码 | V-01 | ✅ 302 成功 |
| 跨站伪造攻击（无 Cookie） | V-01 | ✅ 400 拒绝 |
| 错误原密码修改 | V-02 | ✅ "原密码错误"提示 |
| 空原密码提交 | V-02 | ✅ 拒绝 |
| 本站 Referer | V-03 | ✅ 通过 |
| 外部站点 Referer | V-03 | ✅ 拒绝 |
| 无 Referer 头 | V-03 | ✅ 拒绝 |
| admin 修改 alice 密码 | V-04 | ✅ 302 拒绝 |
| alice 修改 admin 密码 | V-04 | ✅ 302 拒绝 |
| admin 修改自己的密码 | V-04 | ✅ 302 成功 |
| Cookie Secure 属性检查 | V-05 | ✅ 环境变量控制 |
| 原有登录功能 | 回归 | ✅ 正常 |
| 原有注册功能 | 回归 | ✅ 正常 |
| 原有充值功能 | 回归 | ✅ 正常 |
| 原有搜索功能 | 回归 | ✅ 正常 |
| 原有上传功能 | 回归 | ✅ 正常 |

---

## 六、防御架构总结

```
修改密码请求到达
        │
        ▼
┌──────────────────────────────────┐
│ Layer 1: 身份认证               │
│ └── session.get("username") 检查 │
│     未登录 → 302 跳转到 /login   │
└──────────────────────────────────┘
        │ 通过
        ▼
┌──────────────────────────────────┐
│ Layer 2: CSRF Token 校验        │
│ └── CSRFProtect 中间件           │
│     无 Token → 400 Bad Request   │
└──────────────────────────────────┘
        │ 通过
        ▼
┌──────────────────────────────────┐
│ Layer 3: Referer 校验            │
│ └── urlparse 同源检查            │
│     跨域 → 302 Redirect          │
└──────────────────────────────────┘
        │ 通过
        ▼
┌──────────────────────────────────┐
│ Layer 4: 权限校验                │
│ └── session.user == username     │
│     越权 → 302 Redirect          │
└──────────────────────────────────┘
        │ 通过
        ▼
┌──────────────────────────────────┐
│ Layer 5: 原密码校验              │
│ └── check_password_hash()        │
│     错误 → "原密码错误"          │
└──────────────────────────────────┘
        │ 通过
        ▼
┌──────────────────────────────────┐
│ ✅ 密码修改成功                  │
│    generate_password_hash        │
│    → 更新 USERS/DB               │
│    → 302 Redirect                │
└──────────────────────────────────┘
```
