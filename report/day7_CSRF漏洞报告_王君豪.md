# Day 7 — CSRF 漏洞审计与修复报告

**王君豪-2024141530115**

| 字段 | 值 |
|------|------|
| 报告编号 | DAY7-CSRF-20260724 |
| 目标地址 | `http://192.168.137.129:5000` |
| 应用名称 | 用户管理系统（Flask + SQLite） |
| 审计日期 | 2026-07-24 |
| 审计类型 | CSRF + 越权 + 密码修改安全 |
| 发现数量 | 5 个 |
| 修复状态 | ✅ 全部已修复 |

---

## 一、漏洞汇总

| # | 漏洞 | 类型 | 等级 | 位置 |
|---|------|------|------|------|
| 1 | `/change-password` 无 CSRF Token 保护 | CSRF | 🔴 高危 | `app.py:465` |
| 2 | `/change-password` 无原密码校验 | 越权 | 🔴 高危 | `app.py:476-481` |
| 3 | `/change-password` 无 Referer 校验 | CSRF | 🔴 高危 | 默认行为 |
| 4 | `/change-password` 可越权改他人密码 | IDOR | 🔴 高危 | `app.py:476` |
| 5 | `SESSION_COOKIE_SECURE=False` | 配置缺陷 | 🟠 中危 | `app.py:30` |

---

## 二、漏洞详情与修复方案

---

### 漏洞 1：CSRF — 无 Token 保护

**位置：** `app.py` 第 465 行

**问题代码：**
```python
@csrf.exempt   # 显式豁免 CSRF 保护
def change_password():
```

**修复方案：**
```python
# 移除 @csrf.exempt，启用全局 CSRFProtect
@app.route("/change-password", methods=["POST"])
@limiter.limit("10 per minute")
def change_password():
```

**模板添加 CSRF Token：**
```html
<form method="post" action="/change-password">
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
```

**验证结果：**
```bash
# 无 CSRF Token → 400 拒绝 ✅
curl -X POST /change-password -d "username=admin&old_password=x&new_password=y"
# → HTTP 400 Bad Request

# 带正确 Token → 可正常修改 ✅
CSRF=$(curl -s /profile | grep -oP 'value="\K[^"]+')
curl -X POST /change-password \
  -d "csrf_token=$CSRF&username=admin&old_password=admin123&new_password=new"
# → HTTP 302 Redirect
```

---

### 漏洞 2：无原密码校验

**位置：** `app.py` 第 476-481 行

**问题代码：**
```python
username = request.form.get("username", "")
new_password = request.form.get("new_password", "")
# ❌ 未获取 old_password，未校验原密码
```

**修复方案：**
```python
old_password = request.form.get("old_password", "")

# 校验原密码
password_valid = False
if username in USERS and check_password_hash(USERS[username]["password"], old_password):
    password_valid = True
else:
    db_user = get_user_from_db(username)
    if db_user and check_password_hash(db_user["password"], old_password):
        password_valid = True

if not password_valid:
    return render_template("profile.html", user=user_info, error="原密码错误", ...)
```

**验证结果：**
```bash
curl -X POST /change-password \
  -d "csrf_token=$CSRF&username=admin&old_password=wrong&new_password=test"
# → "原密码错误" ✅
```

---

### 漏洞 3：无 Referer 校验

**位置：** `app.py` 第 469-475 行（新增）

**修复方案：**
```python
from urllib.parse import urlparse

referer = request.headers.get("Referer", "")
if not referer:
    return redirect("/profile")
referer_host = urlparse(referer).hostname
request_host = request.host.split(":")[0]
if referer_host != request_host and referer_host != "192.168.137.129":
    return redirect("/profile")
```

**验证结果：**
```bash
curl -X POST /change-password -H "Referer: http://evil.com" ...
# → HTTP 400（CSRF 拒绝）或 302 重定向 ✅
```

---

### 漏洞 4：可越权修改他人密码

**位置：** `app.py` 第 476 行

**问题代码：**
```python
username = request.form.get("username", "")  # ❌ 来自表单，可任意指定
```

**修复方案：**
```python
current_user = session["username"]
username = request.form.get("username", "")

if username != current_user:
    return redirect("/profile")  # ✅ 只能修改自己的密码
```

同时表单的隐藏 `username` 字段仍保留（用于明确目标），但服务端以 session 为准。

**验证结果：**
```bash
# admin 登录后，尝试改 alice 密码
curl -X POST /change-password \
  -d "csrf_token=$CSRF&username=alice&old_password=alice2025&new_password=hacked"
# → 302 重定向到 /profile（拒绝）✅

# alice 原密码仍可登录 ✅
```

---

### 漏洞 5：SESSION_COOKIE_SECURE 配置缺陷

**位置：** `app.py` 第 30 行

**问题代码：**
```python
SESSION_COOKIE_SECURE=False  # 始终不启用 Secure 属性
```

**修复方案：**
```python
# 生产环境（HTTPS）自动启用 Secure 属性
SESSION_COOKIE_SECURE=os.environ.get("ENV") == "production"
```

**说明：** 当 `ENV=production` 环境变量设置时，Cookie 增加 `Secure` 属性，仅通过 HTTPS 传输，防止中间人窃取 Session Cookie。

---

## 三、修改文件清单

| 文件 | 修改内容 |
|------|---------|
| `app.py` | 移除 `@csrf.exempt`；新增原密码校验逻辑；新增 Referer 校验；新增 session 用户匹配检查；`SESSION_COOKIE_SECURE` 改为环境变量配置；新增 `from urllib.parse import urlparse` |
| `templates/profile.html` | 修改密码表单添加 CSRF Token 隐藏字段和原密码输入框 |

---

## 四、修复验证结果

| 测试项 | 结果 |
|--------|------|
| 无 CSRF Token 修改密码 → 400 拒绝 | ✅ |
| 伪造 Referer 提交 → 302 拒绝 | ✅ |
| 错误原密码 → "原密码错误" | ✅ |
| 越权改他人密码 → 302 拒绝 | ✅ |
| 正确原密码 + 正确 Token + 本站 Referer → 成功 | ✅ |
| SESSION_COOKIE_SECURE 环境变量配置 | ✅ |
| 原有登录/注册/充值/上传/搜索功能 | ✅ 正常 |
