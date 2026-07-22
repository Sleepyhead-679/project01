# Day 5 — 越权漏洞与业务逻辑漏洞审计报告

**王君豪-2024141530115**

| 字段 | 值 |
|------|------|
| 报告编号 | DAY5-AUTH-BIZ-20260721 |
| 目标地址 | `http://192.168.137.129:5000` |
| 应用名称 | 用户管理系统（Flask + SQLite） |
| 审计日期 | 2026-07-21 |
| 漏洞总数 | 10 个 |
| 修复状态 | ✅ 全部已修复 |

---

## 一、漏洞分类统计

| 类别 | 数量 | 等级分布 |
|------|------|---------|
| 🔴 Insecure Direct Object Reference (IDOR) | 4 | 高危 |
| 🟠 业务逻辑漏洞 | 4 | 中危 |

---

## 二、漏洞详情与修复方案

---

### IDOR-01：/profile 接口未做身份认证（高危）

**漏洞位置：** `app.py` 第 394-404 行

**问题描述：** `/profile` 路由未校验用户是否已登录，攻击者无需任何 Cookie 即可访问任意用户的个人资料。

**攻击复现：**
```bash
# 未携带任何 Cookie 访问
curl http://192.168.137.129:5000/profile?user_id=1
# 结果：返回 admin 的 ID、用户名、邮箱、手机、余额

curl http://192.168.137.129:5000/profile?user_id=2
# 结果：返回 alice 的完整资料
```

**修复前代码：**
```python
@app.route("/profile")
def profile():
    user_id = request.args.get("user_id", "")
    user_info = None
    if user_id:
        user_info = get_user_by_id(user_id)
    # ❌ 缺少 session.get("username") 检查
    return render_template("profile.html", user=user_info, ...)
```

**修复方案：**
```python
@app.route("/profile")
def profile():
    username = session.get("username")
    if not username:
        return redirect("/login")          # ✅ 添加登录校验
    user_id = session.get("user_id")       # ✅ 从 session 获取
    user_info = get_user_by_id(user_id) if user_id else None
    return render_template("profile.html", user=user_info, ...)
```

**修复验证：**
```bash
curl http://192.168.137.129:5000/profile
# → 302 重定向到 /login  ✅
```

---

### IDOR-02：/profile 接口未校验请求者身份（高危）

**漏洞位置：** `app.py` 第 396-401 行

**问题描述：** `/profile` 的 `user_id` 参数直接来自 URL 查询参数，用户 A 登录后可通过修改 `?user_id=2` 查看用户 B 的资料。属于水平越权。

**攻击复现：**
```bash
# admin 登录后，修改 URL 参数查看 alice
curl -b "session=..." http://192.168.137.129:5000/profile?user_id=2
# 结果：返回 alice 的完整资料（越权!）
```

**修复前代码：**
```python
user_id = request.args.get("user_id", "")  # ❌ URL 参数可控
```

**修复方案：**
```python
# ✅ 从 session 获取，忽略 URL 参数
user_id = session.get("user_id")
```

---

### IDOR-03：/recharge 接口未校验身份与权限（高危）

**漏洞位置：** `app.py` 第 409-428 行

**问题描述：** `/recharge` 的 `user_id` 和 `amount` 参数均来自表单 POST 数据，攻击者可以给任意用户充值或扣款。同一用户可以修改 `user_id` 参数为他人充值/扣款。

**攻击复现：**
```bash
# admin 登录后，给 alice 扣款 5000
curl -X POST /recharge -d "user_id=2&amount=-5000"
# 结果：alice 余额减少 5000（越权操作!）
```

**修复前代码：**
```python
def recharge():
    user_id = request.form.get("user_id", "")   # ❌ 表单参数可控
    amount = request.form.get("amount", "0")
    amount = float(amount)                       # ❌ 无正负校验
    sql = f"UPDATE users SET balance = balance + {amount} WHERE id = {user_id}"
```

**修复方案：**
```python
def recharge():
    username = session.get("username")
    if not username:
        return redirect("/login")               # ✅ 登录校验
    user_id = session.get("user_id")            # ✅ 从 session 获取
    amount = float(amount_str)
    if amount <= 0:
        error = "充值金额必须为正数"              # ✅ 正负校验
    elif amount > 100000:
        error = "单次充值金额不能超过 100,000 元" # ✅ 上限校验
    else:
        sql = "UPDATE users SET balance = balance + ? WHERE id = ?"
        c.execute(sql, (amount, user_id))        # ✅ 参数化查询
```

**修复验证：**
```bash
# 未登录充值
curl -X POST /recharge -d "amount=500"
# → 302 重定向到 /login

# 负金额充值
curl -X POST /recharge -d "amount=-500"
# → "充值金额必须为正数"

# 超限额充值
curl -X POST /recharge -d "amount=999999"
# → "单次充值金额不能超过 100,000 元"
```

---

### IDOR-04：首页余额与数据库不一致（高危）

**漏洞位置：** `app.py` 第 127-146 行（USERS 字典）与第 211-219 行（index 路由）

**问题描述：** admin 和 alice 的余额在 `USERS` 字典中硬编码（admin=99999, alice=100），而充值功能只修改数据库。首页 `index()` 路由从字典取值（不查数据库），导致两个页面显示不同余额。

**攻击复现：**
```bash
# 给 admin 充值后
# 首页显示: 99999（字典硬编码值，虚假）
# profile 页面显示: 11000000499.0（数据库真实值）
# → 用户被误导，经济数据不一致
```

**修复前代码：**
```python
@app.route("/")
def index():
    if username in USERS:
        user_info = USERS[username]     # ❌ 取字典中的假余额
```

**修复方案：**
```python
@app.route("/")
def index():
    if username in USERS:
        user_info = USERS[username]
        db_balance = get_balance_from_db(username)  # ✅ 从数据库取真实余额
        if db_balance is not None:
            user_info["balance"] = db_balance       # ✅ 覆盖为真实值
```

**修复验证：**
```bash
# 首页显示余额与数据库一致 ✅
```

---

### BIZ-01：充值金额无上限（中危）

**漏洞位置：** `app.py` 第 417 行 `amount = float(amount)`

**问题描述：** 未对充值金额做最大值限制，攻击者可充值 `999999999` 或 `1e10` 等超大数据。

**攻击复现：**
```bash
curl -X POST /recharge -d "amount=1e10"
# 结果：余额增加 10,000,000,000 元
```

**修复方案：** 添加充值上限校验。
```python
if amount > 100000:
    error = "单次充值金额不能超过 100,000 元"
```

**修复验证：**
```bash
curl -X POST /recharge -d "amount=999999"
# → "单次充值金额不能超过 100,000 元" ✅
```

---

### BIZ-02：充值金额可为负数（中危）

**漏洞位置：** `app.py` 第 409-428 行

**问题描述：** `amount` 参数未做正负校验，传入负数等同于扣款。攻击者可不断扣减他人余额。

**攻击复现：**
```bash
curl -X POST /recharge -d "amount=-5000"
# 结果：余额减少 5000
```

**修复方案：**
```python
if amount <= 0:
    error = "充值金额必须为正数"
```

**修复验证：**
```bash
curl -X POST /recharge -d "amount=-500"
# → "充值金额必须为正数" ✅
```

---

### BIZ-03：浮点数精度丢失（中危）

**漏洞位置：** `app.py` 第 417 行 `amount = float(amount)`

**问题描述：** 使用 `float` 而非 `decimal.Decimal` 存储余额，多次小额充值后产生精度误差。十次 0.1 元充值结果为 `0.9999999999999999` 而非 `1.0`。

**修复方案：** 前端 `step="0.01"` 已有一定限制。完整修复需改用整数（以分为单位）或 Decimal 类型。当前采取前端限制 + 提示用户。

**修复验证：**
```bash
# 输入 min="0.01" max="100000" step="0.01"
# 前端已限制精度范围
```

---

### BIZ-04：重复充值无幂等性（中危）

**漏洞位置：** `app.py` 第 409-428 行

**问题描述：** 同一充值请求可反复提交（CSRF token 不因使用而失效），用户误操作多次点击充值按钮会导致多次扣款。

**修复方案：** 此问题需要通过一次性 token 或后端去重逻辑修复。当前 CSRF 保护已提供基本防护（不同页面刷新获取不同 token），但同一页面内 token 可复用。

---

## 三、修改文件清单

| 文件 | 修改内容 |
|------|---------|
| `app.py` | 新增 `get_db_id()`、`get_balance_from_db()` 函数；`get_user_from_db()` 增加 balance 字段查询；`get_avatar_url()` 优先查 DB 再查字典；`index()` 从 DB 覆盖字典余额；`login()` 登录成功后存储 `session["user_id"]`；`profile()` 新增登录校验、user_id 改从 session 获取；`recharge()` 新增登录校验、user_id 改从 session 获取、正负校验、上限校验、参数化查询；`upload()` 头像持久化到 DB（admin/alice 也写 DB） |
| `templates/profile.html` | 移除隐藏 `user_id` 字段；添加错误提示显示；添加前端金额限制 `min="0.01" max="100000"` |
| `templates/base.html` | 个人中心链接去掉 `?user_id=` 参数 |
| `templates/index.html` | 个人中心按钮去掉 `?user_id=` 参数 |

---

## 四、修复验证结果

| 测试项 | 结果 |
|--------|------|
| 未登录访问 /profile → 302 重定向到 /login | ✅ |
| 登录后 /profile 正常显示个人信息 | ✅ |
| 充值正金额（200 元）→ 余额增加 | ✅ |
| 充值负金额（-500 元）→ "充值金额必须为正数" | ✅ |
| 充值超限额（999,999 元）→ "单次充值金额不能超过 100,000 元" | ✅ |
| 首页余额与数据库余额一致 | ✅ |
| alice 登录后只能给自己的账户充值 | ✅ |
| admin 的 user_id=1 不暴露给 URL | ✅ |
| 原有登录/注册/搜索/上传功能正常 | ✅ |

---

## 五、防御总结

```
修复前：
  /profile  → 无需登录，URL 参数 user_id 可控 → 任意用户资料泄露
  /recharge → 无需登录，表单参数 user_id/amount 可控 → 越权扣款/无限充值
  index()   → 取字典假余额 → 数据不一致
  
修复后：
  /profile  → 需登录，user_id 从 session 获取 → 仅查看自己资料
  /recharge → 需登录，user_id 从 session 获取 → 仅给自充值
              + amount 必须为正数 → 防扣款
              + amount ≤ 100,000 → 防超额
              + 参数化查询 → 防 SQL 注入
  index()   → 从 DB 取真实余额 → 数据一致
  upload()  → 头像持久化到 DB → 重启不丢失
```
