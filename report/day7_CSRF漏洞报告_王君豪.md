# Day 7 — CSRF 漏洞审计与修复报告

**王君豪-2024141530115**

| 字段 | 值 |
|------|------|
| 报告编号 | DAY7-CSRF-20260723 |
| 目标地址 | `http://192.168.137.129:5000` |
| 应用名称 | 用户管理系统（Flask + SQLite） |
| 审计日期 | 2026-07-23 |
| 审计类型 | 跨站请求伪造（CSRF） |
| 发现数量 | 1 个 |
| 修复状态 | ✅ 已修复 |

---

## 一、漏洞详情

### CSRF-01：/change-password 路由无 CSRF 保护

| 属性 | 值 |
|------|-----|
| **漏洞编号** | CSRF-01 |
| **漏洞类型** | 跨站请求伪造（Cross-Site Request Forgery） |
| **严重等级** | 🔴 高危 |
| **影响端点** | `POST /change-password` |
| **代码位置** | `app.py` 第 465 行 |
| **问题代码** | `@csrf.exempt` |

#### 漏洞代码

```python
# app.py 第 463-465 行
@app.route("/change-password", methods=["POST"])
@limiter.limit("10 per minute")
@csrf.exempt                    # ← 显式豁免 CSRF 保护，禁用防跨站机制
def change_password():
```

#### 漏洞原理

CSRF（Cross-Site Request Forgery，跨站请求伪造）是一种攻击方式，攻击者诱导已登录用户访问恶意页面，该页面自动向目标网站发送恶意请求（如表单提交），从而在用户不知情的情况下执行操作。

Flask-WTF 的 `CSRFProtect` 中间件通过以下方式防御 CSRF：

1. 服务器生成一个随机的 CSRF Token，绑定到用户 Session
2. 每个需要保护的表单中嵌入该 Token 作为隐藏字段
3. 提交请求时服务器验证 Token 是否与 Session 中的一致
4. 攻击者的恶意页面无法获取用户的 CSRF Token，因此请求被拒绝

`@csrf.exempt` 装饰器**完全禁用了这一保护机制**，使得该端点可以接受任何来源的 POST 请求。

#### 攻击复现（修复前）

**恶意 HTML 页面（攻击者构造）：**
```html
<html>
  <body>
    <h1>🎉 恭喜中奖！点击领取奖品</h1>
    <form action="http://192.168.137.129:5000/change-password" method="POST">
      <input type="hidden" name="username" value="admin">
      <input type="hidden" name="new_password" value="hacked123">
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```

**攻击流程：**
```
1. 受害者登录了用户管理系统（session 有效）
2. 受害者被诱导访问攻击者的恶意页面
3. 页面自动提交表单到 /change-password
4. 浏览器自动携带用户 Cookie（SameSite=Lax 不阻止 POST）
5. 服务端无 CSRF Token 校验 → 密码被修改
6. 攻击者用新密码登录 → 完全接管账号
```

**修复前验证：**
```bash
# 无需 CSRF Token、无需 Cookie，直接 POST
curl -X POST http://target/change-password \
  -d "username=admin&new_password=hacked123"
# → HTTP 302 成功 ✅ 漏洞存在
```

#### 修复方案

**修复后代码：**

```python
# app.py 第 463-465 行（修复后）
@app.route("/change-password", methods=["POST"])
@limiter.limit("10 per minute")
def change_password():    # ← 移除 @csrf.exempt，启用 CSRF 保护
```

**模板修复（profile.html）：**
```html
<form method="post" action="/change-password" class="login-form">
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
    <!--   ↑ 添加 CSRF Token 隐藏字段 -->
    <input type="hidden" name="username" value="{{ user.username }}">
    ...
</form>
```

#### 修复原理

| 防护层 | 说明 |
|--------|------|
| **Flask-WTF CSRFProtect** | 全局中间件，自动校验所有 POST 请求的 `csrf_token` 字段 |
| **Session 绑定 Token** | 每个 Session 生成唯一 Token，攻击者无法获取 |
| **表单 Token 嵌入** | 模板中 `{{ csrf_token }}` 生成隐藏字段 |
| **Token 验证** | 提交时对比请求中的 Token 与 Session 中的 Token 是否一致 |

**修复后的请求流程：**
```
合法请求：                  恶意请求：
用户浏览 profile 页面       攻击者构造表单
  → 获取 CSRF Token          → 没有 CSRF Token
  → 提交表单 + Token          → 提交表单（无 Token）
  → Token 验证通过 ✅         → Token 验证失败 ❌
  → 密码修改成功              → HTTP 400 Bad Request
```

#### 修复验证

| 测试场景 | 测试方法 | 修复前 | 修复后 |
|---------|---------|--------|--------|
| 无 CSRF Token 修改密码 | `curl -X POST /change-password -d "username=admin&password=new"` | ✅ 成功（漏洞） | ❌ 400 拒绝 |
| 带正确 Token 修改密码 | 从 profile 获取 Token 后提交 | ✅ 成功 | ✅ 302 成功 |
| 跨站伪造攻击（无 Cookie） | 从外部页面直接 POST | ✅ 成功 | ❌ 400 拒绝 |

```bash
# 修复后验证
# 无 CSRF Token → 被拒绝
curl -X POST /change-password -d "username=admin&new_password=hacked"
# → HTTP 400 Bad Request  ✅ 已修复

# 带 CSRF Token → 可正常修改
CSRF=$(curl -s /profile | grep -oP 'value="\K[^"]+')
curl -X POST /change-password -d "csrf_token=$CSRF&username=admin&new_password=new"
# → HTTP 302 Redirect  ✅ 正常功能
```

---

## 二、CSRF 防护现状总览

| 端点 | CSRF 保护 | 状态 |
|------|----------|------|
| `POST /login` | `CSRFProtect` + SameSite=Lax | ✅ 安全 |
| `POST /register` | `CSRFProtect` + SameSite=Lax | ✅ 安全 |
| `POST /recharge` | `CSRFProtect` + SameSite=Lax | ✅ 安全 |
| `POST /upload` | `CSRFProtect` + SameSite=Lax | ✅ 安全 |
| `POST /change-password` | `CSRFProtect` + SameSite=Lax | ✅ **已修复** |

**当前 CSRF 防护措施：**

| 措施 | 配置 | 作用 |
|------|------|------|
| `CSRFProtect(app)` | 全局启用 | 自动校验所有 POST 请求的 csrf_token |
| `SESSION_COOKIE_SAMESITE="Lax"` | app.py:29 | 阻止跨站 GET 请求携带 Cookie |
| `SESSION_COOKIE_HTTPONLY=True` | app.py:28 | 阻止 JavaScript 读取 Cookie |
| 表单 `{{ csrf_token }}` | 模板中嵌入 | 每个表单生成唯一 Token |

---

## 三、修改文件清单

| 文件 | 修改内容 |
|------|---------|
| `app.py` | 移除 `@csrf.exempt` 装饰器，启用 CSRF 保护 |
| `templates/profile.html` | 修改密码表单添加 `<input type="hidden" name="csrf_token" value="{{ csrf_token }}">` |

---

## 四、修复验证结果

| 测试项 | 结果 |
|--------|------|
| 无 CSRF Token 修改密码 → 400 拒绝 | ✅ |
| 带正确 CSRF Token 修改密码 → 302 成功 | ✅ |
| 跨站伪造攻击（无 Cookie）→ 400 拒绝 | ✅ |
| 新密码登录验证 → 成功 | ✅ |
| 原有登录/注册/充值/上传/搜索功能 | ✅ 正常 |
