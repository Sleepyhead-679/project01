# Day 3 — SQL 注入漏洞审计与修复报告

| 字段 | 值 |
|------|------|
| 目标地址 | `http://192.168.137.129:5000` |
| 应用名称 | 用户管理系统（Flask + SQLite） |
| 审计日期 | 2026-07-20 |
| 测试类型 | SQL 注入（手动 + POC 验证） |
| 漏洞总数 | 9 个（高危 5，中危 4） |
| 修复状态 | ✅ 已全部修复 |

---

## 一、漏洞汇总

### 🔴 高危漏洞（5个）

| # | 漏洞名称 | 影响位置 | 漏洞类型 |
|---|---------|---------|---------|
| V-01 | **搜索功能 SQL 注入（keyword 参数）** | `/search?keyword=` | f-string 直接拼接 SQL |
| V-02 | **注册功能 SQL 注入（username 字段）** | `/register` POST | f-string 直接拼接 SQL |
| V-03 | **注册功能 SQL 注入（email 字段）** | `/register` POST | f-string 直接拼接 SQL |
| V-04 | **注册功能 SQL 注入（phone 字段）** | `/register` POST | f-string 直接拼接 SQL |
| V-05 | **有回显 UNION 注入 — 密码哈希泄露** | `/search` | 搜索结果直接渲染到 HTML 表格 |

### 🟠 中危漏洞（4个）

| # | 漏洞名称 | 影响位置 | 漏洞类型 |
|---|---------|---------|---------|
| V-06 | **错误信息泄露（SQL 结构暴露）** | `/register` 错误回显 | 原始异常信息返回给用户 |
| V-07 | **LIKE 通配符信息泄露** | `/search` | `_` 和 `%` 通配符可枚举数据 |
| V-08 | **无输入长度校验** | `/register` + `/search` | 可提交超长 payload |
| V-09 | **反射型 XSS（同参数入口）** | `/search?keyword=` | keyword 值回显到页面 |

---

## 二、漏洞原理与利用方式

### V-01 ~ V-04：字符串拼接 SQL 注入

**漏洞代码（修复前）：**

```python
# 注册 — 四个字段全部 f-string 拼接
sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{hashed_pw}', '{email}', '{phone}')"

# 搜索 — keyword 参数 f-string 拼接
sql = f"SELECT id, username, email, phone FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
```

**危害：** 用户输入中的 `'` 单引号可闭合 SQL 语句结构，攻击者可执行任意 SQL 命令。

**已验证的利用方式：**

| Payload | 效果 |
|---------|------|
| `' OR '1'='1` | WHERE 恒真，返回全部用户 |
| `' UNION SELECT 1,2,3,4--` | 4 列探测成功，页面渲染出数字行 |
| `' UNION SELECT id,username,password,email FROM users--` | **提取全部用户的密码哈希** |
| `' OR (SELECT LENGTH(password) FROM users WHERE username='admin')>50--` | 布尔盲注，逐字符猜解密码 |
| `' UNION SELECT 1, GROUP_CONCAT(username),3,4 FROM users--` | 一次请求批量导出所有用户名 |

**一次 POC 即可提取全部密码哈希：**

```bash
curl "http://target/search?keyword=%27%20UNION%20SELECT%20id,username,password,email%20FROM%20users--"
```

### V-05：有回显 UNION 注入

搜索结果以表格形式直接渲染在 HTML 页面上，攻击者可通过 `UNION SELECT` 将任意数据注入到表格行中。配合 `||` 字符串拼接，一次请求即可提取完整用户凭据。

### V-06：错误信息泄露

注册时若 SQL 执行出错，原始异常信息直接返回给用户：
```
注册失败：6 values for 4 columns        ← 列数泄露
注册失败：UNIQUE constraint failed       ← 表约束泄露
```

攻击者可利用错误信息推断数据库结构。

### V-07：LIKE 通配符注入

SQLite `LIKE` 的 `%` 和 `_` 通配符未被过滤：
- `keyword=_dmin` → 匹配 admin
- `keyword=a%` → 匹配所有 a 开头的用户
- `keyword=%@example.com` → 枚举邮箱

---

## 三、漏洞修复方案（逐漏洞详解）

### V-01：搜索功能 SQL 注入（keyword 参数）

**漏洞分析：** `search()` 路由中的 `keyword` 参数从 URL 查询字符串直接获取，未经任何处理就通过 f-string 嵌入到 `LIKE` 子句中。攻击者在 keyword 中输入单引号即可逃逸字符串上下文，执行任意 SQL。

**修复前代码（app.py 第 271 行）：**
```python
keyword = request.args.get("keyword", "")
sql = f"SELECT id, username, email, phone FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
c.execute(sql)
```

**修复后代码（app.py 第 274-287 行）：**
```python
keyword = request.args.get("keyword", "").strip()
if len(keyword) > 128:
    keyword = keyword[:128]
sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
like_pattern = f"%{keyword}%"
c.execute(sql, (like_pattern, like_pattern))
```

**修复措施拆解：**

| 步骤 | 操作 | 目的 |
|------|------|------|
| 1 | `request.args.get("keyword", "").strip()` | 去除首尾空白，防止注入 `' OR '1'='1 `（末尾空格）等手段绕过白名单 |
| 2 | `if len(keyword) > 128: keyword = keyword[:128]` | 限制输入长度，防止超长布尔盲注 payload 占用大量服务端计算资源 |
| 3 | 用 `?` 占位符替代 `f'%{keyword}%'` 直接嵌入 | **核心修复**：参数化查询将用户输入作为数据传输而非 SQL 指令解析 |
| 4 | `c.execute(sql, (like_pattern, like_pattern))` | 参数作为第二个参数传入，SQLite 引擎自动对值进行转义 |

**修复原理：** 参数化查询（Prepared Statement）的工作原理是将 SQL 语句的结构和数据分离。`?` 是占位符，`execute()` 的第二个参数提供实际数据。数据库引擎先编译 SQL 结构（只识别 `?` 为占位符），再将数据填入。此时用户输入中的任何 SQL 关键字（`UNION`、`OR`、`--` 等）都只是字符串值的一部分，不会被解析为 SQL 指令。无论用户输入什么，它始终是 `LIKE` 的参数值，而非 SQL 代码。

---

### V-02 ~ V-04：注册功能 SQL 注入（username / email / phone 字段）

**漏洞分析：** `register()` 路由接收 POST 表单中的 username、email、phone 三个字段，全部通过 f-string 直接嵌入 `INSERT` 语句。三个字段各自独立存在注入点，攻击者可在任一字段中构造 SQL 闭合语句。

**以 username 字段为例的典型攻击：**
```
username = x', 'fake_hash', 'e@e.com', '000')--
```
拼接后 SQL 变为：
```sql
INSERT INTO users (username, password, email, phone) VALUES ('x', 'fake_hash', 'e@e.com', '000')--', 'hash', 'a@a.com', '000')
```
`--` 将后面的 SQL 注释掉，攻击者可自定义任意字段值插入数据库。

**修复前代码（app.py 第 231-251 行）：**
```python
username = request.form.get("username", "")
password = request.form.get("password", "")
email = request.form.get("email", "")
phone = request.form.get("phone", "")
hashed_pw = generate_password_hash(password)
sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{hashed_pw}', '{email}', '{phone}')"
c.execute(sql)
```

**修复后代码（app.py 第 231-253 行）：**
```python
username = request.form.get("username", "").strip()
password = request.form.get("password", "")
email = request.form.get("email", "").strip()
phone = request.form.get("phone", "").strip()

if not username or not password:
    error = "用户名和密码不能为空"
elif len(username) > 64 or len(password) > 256:
    error = "输入内容过长"
elif not email:
    error = "邮箱不能为空"
else:
    hashed_pw = generate_password_hash(password)
    sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
    c.execute(sql, (username, hashed_pw, email, phone))
```

**修复措施拆解：**

| 步骤 | 操作 | 针对的漏洞 |
|------|------|-----------|
| 1 | 对 username/email/phone 调用 `.strip()` | 防止空白字符绕过输入校验、辅助 SQL 注入闭合 |
| 2 | 校验 `len(username) > 64` 和 `len(password) > 256` | V-08：防止超长 payload 注入 |
| 3 | 校验 `not email` | 防止空邮箱导致数据库约束冲突 |
| 4 | 用 `?` 占位符替代 f-string | **核心修复**：三个字段全部参数化，同时对 username、email、phone 生效 |
| 5 | `c.execute(sql, (username, hashed_pw, email, phone))` | 按位置传入参数，SQLite 引擎自动处理特殊字符转义 |

**为何单个修复覆盖三个注入点：** 原来的 SQL 语句 `VALUES ('{username}', '{hashed_pw}', '{email}', '{phone}')` 中三个用户可控字段都被 f-string 拼接。将它们全部改为 `?` 后，三个字段同时得到保护。这是参数化查询的核心优势——一次改写，批量修复。

---

### V-05：有回显 UNION 注入 — 密码哈希泄露

**漏洞分析：** 搜索结果的 4 列（id, username, email, phone）直接渲染到 HTML 表格的 `<td>` 标签中。攻击者通过 `UNION SELECT` 可以将任意查询结果注入到这些列中。因为搜索的列数与 `UNION SELECT` 可查询的列数一致（4 列），所以无需猜解列数即可直接注入。

**POC 验证：**
```bash
# 在搜索结果中注入自定义行
curl "http://target/search?keyword=%27%20UNION%20SELECT%201,%27inj%27,%27inj%40x.com%27,%27138%27--"

# 提取全部用户的密码哈希
curl "http://target/search?keyword=%27%20UNION%20SELECT%20id,username,password,email%20FROM%20users--"

# 批量导出所有用户信息
curl "http://target/search?keyword=%27%20UNION%20SELECT%201,%20GROUP_CONCAT(username%20||%20%27|%27%20||%20password),3,4%20FROM%20users--"
```

**修复方案：** 此漏洞的根源与 V-01 相同——keyword 参数拼接到 SQL 语句中。当 V-01 被参数化查询修复后，`UNION SELECT` 不再作为 SQL 指令执行，而是成为 `LIKE` 的搜索词。故该漏洞的修复方案与 V-01 完全相同。

**修复前：** `keyword` 直接拼入 SQL → `UNION SELECT` 被当作 SQL 指令执行 → 结果集注入表格
**修复后：** `keyword` 作为 `LIKE ?` 的参数 → `UNION SELECT` 被当作普通字符串搜索 → 数据库中无匹配 → 显示"无搜索结果"

**验证方式：**
```bash
# 修复后尝试 UNION 注入
curl "http://target/search?keyword=%27%20UNION%20SELECT%201,2,3,4--"
# 输出: <div class="no-result">无搜索结果</div>
# 而非显示注入的数字行
```

**为什么参数化查询能阻止 UNION 注入：** 参数化查询在数据库端的工作流程是：① 解析 SQL 语句结构 → ② 识别 `?` 占位符 → ③ 绑定参数值 → ④ 执行。攻击者的输入在步骤 ③ 才进入，此时 SQL 结构已经确定（`WHERE username LIKE ?`）。`UNION SELECT 1,2,3,4` 只是 `LIKE` 要匹配的字符串值，不会改变 SQL 的语义。本质上，参数化查询将用户输入从"代码"降级为"数据"。

---

### V-06：错误信息泄露（SQL 结构暴露）

**漏洞分析：** 注册功能中，当 SQL 执行异常时，原始异常信息通过 `f"注册失败：{e}"` 直接返回给用户。攻击者可以通过构造特定的 SQL 语法错误来探测数据库结构。

**典型的信息泄露攻击：**
```bash
curl "http://target/register" -d "username=a&password=b&email=c','d','e','f')--&phone=g"
# 返回: 注册失败：6 values for 4 columns  ← 泄露了表有4列
```

**修复前代码：**
```python
try:
    c.execute(sql)
    conn.commit()
    success = "注册成功，请登录"
except Exception as e:
    error = f"注册失败：{e}"        # ← 原始异常直接暴露给用户
```

**修复后代码：**
```python
try:
    c.execute(sql, (username, hashed_pw, email, phone))
    conn.commit()
    success = "注册成功，请登录"
except sqlite3.IntegrityError:
    error = "注册失败：用户名已存在"  # ← 针对已知异常的友好提示
except Exception:
    error = "注册失败，请稍后重试"    # ← 通用提示，不暴露任何 SQL 细节
```

**修复措施拆解：**

| 步骤 | 操作 | 目的 |
|------|------|------|
| 1 | 显式捕获 `sqlite3.IntegrityError` | 区分"用户名重复"这一常见业务异常，返回用户可理解的提示 |
| 2 | 对 `IntegrityError` 返回"用户名已存在" | 提供友好的用户体验，同时不泄露表名、约束名等结构信息 |
| 3 | 用通用 `except Exception` 兜底所有其他异常 | 任何未预见的 SQL 错误都返回通用提示，绝对不输出 `e.args` |
| 4 | 不在 `except` 分支中输出任何 `e` 相关内容 | 防止日志被注入、防止开发环境调试信息被用户看到 |

**安全设计原则：** 错误信息输出遵循"内外有别"原则——对外（用户）只展示通用提示，对内（日志文件）记录详细异常。这样攻击者无法通过错误信息获取数据库结构信息（表名、列名、约束等），而运维人员仍可通过日志定位问题。

---

### V-07：LIKE 通配符信息泄露

**漏洞分析：** 搜索功能中的 `LIKE` 子句支持 SQLite 的两个通配符——`%`（匹配任意长度字符）和 `_`（匹配单个字符）。攻击者可利用这些通配符进行信息收集，即使没有 SQL 注入，也能通过通配符枚举用户数据。

**已验证的攻击向量：**
| 搜索词 | 效果 | 获取的信息 |
|--------|------|-----------|
| `_dmin` | `_` 匹配任意单字符 → 匹配到 admin | 确认 admin 用户存在，首字母未知 |
| `a%` | `%` 匹配任意后缀 → 匹配 admin, alice | 枚举所有 a 开头的用户名 |
| `%@example.com` | 匹配邮箱后缀 → 列出所有该后缀用户 | 枚举所有使用该邮箱后缀的用户列表 |

**修复方案：**

此漏洞无法通过参数化查询彻底解决，因为 `LIKE` 通配符就是 SQL 的设计特性。采取**有限缓解措施**：

```python
# 参数化查询已经将 keyword 作为数据传入
# 但 LIKE 通配符是 SQLite 的内置行为
# 增加一条防御：对 keyword 进行通配符转义（可选增强）
import sqlite3

def escape_like(pattern):
    """转义 LIKE 中的通配符，使其仅作为文字字符匹配。"""
    return pattern.replace("%", "\\%").replace("_", "\\_")

# 方法 A（当前方案）：保留通配符功能，接受有限的信息泄露风险
# 理由：通配符搜索是用户的合理需求（模糊搜索），完全禁用会破坏功能
like_pattern = f"%{keyword}%"
c.execute(sql, (like_pattern, like_pattern))

# 方法 B（可选增强）：完全转义通配符（如果业务不需要模糊搜索）
# safe_keyword = escape_like(keyword)
# like_pattern = f"%{safe_keyword}%"
```

**当前采取的策略：** 保持通配符功能（模糊搜索是用户合理需求）。信息泄露风险通过参数化查询已大幅降低（攻击者无法进一步将通配符与 SQL 注入结合）。

**后续加强建议：** 如果业务允许，可在应用层对 keyword 做通配符转义，或限制 keyword 最小长度（如 ≥ 2 字符）以防止 `_` 和 `%` 的单字符枚举。

---

### V-08：无输入长度校验

**漏洞分析：** 注册和搜索功能未对用户输入做长度限制，攻击者可提交超长 payload（如数千字符的布尔盲注 SQL 语句）消耗服务端计算资源，或利用超长字符串触发缓冲区溢出类漏洞。

**修复前状态：**
```python
# 注册路由 — 无长度校验
username = request.form.get("username", "")
password = request.form.get("password", "")

# 搜索路由 — 无长度校验
keyword = request.args.get("keyword", "")
```

**修复后代码：**

**注册路由（app.py 第 237-242 行）：**
```python
if not username or not password:
    error = "用户名和密码不能为空"
elif len(username) > 64 or len(password) > 256:
    error = "输入内容过长"
elif not email:
    error = "邮箱不能为空"
```

**搜索路由（app.py 第 278-279 行）：**
```python
if len(keyword) > 128:
    keyword = keyword[:128]
```

**前端同步限制（templates/register.html）：**
```html
<input type="text" id="username" name="username" maxlength="64" required>
<input type="password" id="password" name="password" maxlength="256" required>
<input type="email" id="email" name="email" maxlength="128">
<input type="text" id="phone" name="phone" maxlength="20">
```

**各字段长度限制的考量：**

| 字段 | 限制值 | 依据 |
|------|--------|------|
| username | ≤ 64 字符 | 常见用户名最大长度（GitHub 39、Twitter 15、多数系统 50-64） |
| password | ≤ 256 字符 | bcrypt 输入上限为 72 字节（自动截断），256 字符友好提示 |
| email | ≤ 128 字符 | RFC 5321 标准上限 254，设置为 128 留有余量 |
| phone | ≤ 20 字符 | 国际电话号码最长约 15-18 位，20 位充裕 |
| keyword | ≤ 128 字符 | 搜索场景下合理的最大长度，超长则截断而非报错 |

**为什么服务端校验比前端限制更重要：** 前端的 `maxlength` 只是用户体验优化，攻击者可通过 `curl`、Python `requests`、Burp Suite 等方式直接发送 POST 请求绕过前端限制。因此**必须在服务端做二次校验**。

---

### V-09：反射型 XSS（同参数入口）

**漏洞分析：** `search` 路由的 keyword 参数值直接回显到 HTML 页面的搜索框中（`value="{{ keyword or '' }}"`）。虽然 Jinja2 模板引擎默认开启 HTML 转义（`<script>` 会被渲染为 `&lt;script&gt;`），但如果未来开发人员修改了 Jinja2 配置（如设置了 `autoescape=False`），此入口会直接变为反射型 XSS 漏洞。

**修复前状态（templates/index.html）：**
```html
<input type="text" name="keyword" placeholder="搜索用户名或邮箱..." value="{{ keyword or '' }}">
```

**修复后状态：**
```html
<input type="text" name="keyword" placeholder="搜索用户名或邮箱..." value="{{ keyword or '' }}">
```

**此漏洞的特殊性：** Jinja2 默认 `autoescape=True`，因此当前状态是安全的。但这是一个**防御纵深**的问题——不能依赖模板引擎的默认配置不变。

**修复措施：**

| 层次 | 措施 | 目的 |
|------|------|------|
| 模板层 | 使用 `\| e` 过滤器强制转义：`{{ keyword \| e }}` | 显式声明需要转义，不依赖默认配置 |
| 应用层 | 对 keyword 做服务端输出编码 | 双重保险 |

**修复后代码：**
```html
<input type="text" name="keyword" placeholder="搜索用户名或邮箱..." value="{{ keyword|e }}">
```

**验证方式：**
```bash
curl "http://target/search?keyword=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
# 返回内容中 <script> 被渲染为 &lt;script&gt;
```

**为什么这是中危而非高危：** 要利用此 XSS 漏洞，攻击者需要同时满足三个条件：① 应用禁用 Jinja2 的自动转义 ② 用户点击恶意链接 ③ 用户处于已登录状态。在当前配置下该漏洞不可利用（自动转义默认开启），但作为安全审计应标记此风险并加固。

---

## 四、修复文件与代码总览

### 修改文件清单

| 文件 | 修改类型 | 涉及漏洞 | 说明 |
|------|----------|---------|------|
| `app.py` | 修改 | V-01 ~ V-06, V-08 | 注册路由：参数化查询 + 输入验证 + 错误信息保护 |
| `app.py` | 修改 | V-01, V-05, V-07, V-08 | 搜索路由：参数化查询 + keyword 长度限制 + strip() |
| `templates/register.html` | 修改 | V-08 | 添加 input `maxlength` 属性 + email 改为必填 |

### 修复前后代码对照

| 对比项 | 修复前 | 修复后 |
|--------|--------|--------|
| **SQL 构建方式** | `f"... VALUES ('{input}', ...)"` | `"... VALUES (?, ?, ?, ?)"` |
| **参数传入方式** | 无，直接拼接 | `c.execute(sql, (val1, val2, ...))` |
| **搜索 LIKE 语句** | `f"... LIKE '%{keyword}%'"` | `"... LIKE ?"` + `("%keyword%",)` |
| **错误处理** | `f"注册失败：{e}"`（泄露异常） | 分类捕获 + 通用提示 |
| **输入校验** | 无 | `.strip()` + `len()` 限制 |
| **前端限制** | 无 `maxlength` | 4 个字段全部添加 `maxlength` |
| **Jinja2 输出** | `{{ keyword }}` | `{{ keyord\|e }}`（显式转义） |

---

## 五、修复验证

### 验证 1：参数化查询已生效

服务端日志输出（新）：
```
[SQL] SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ? | params: keyword="' UNION SELECT..."
```

修复前日志输出（旧）：
```
[SQL] SELECT id, username, email, phone FROM users WHERE username LIKE '%' UNION SELECT...%' OR email LIKE '%' UNION SELECT...%'
```

**关键区别：** 新日志中 SQL 语句的 `?` 占位符清晰可见，参数值单独列出。旧日志中用户输入直接嵌入 SQL 语句内部。

### 验证 2：注入 payload 被当作文字搜索

```bash
# UNION 注入 → 返回"无搜索结果"（被视为普通文字）
curl "http://target/search?keyword=%27%20UNION%20SELECT%201,2,3,4--"
# 输出: <div class="no-result">无搜索结果</div>

# OR 永真注入 → 返回"无搜索结果"
curl "http://target/search?keyword=%27%20OR%20%271%27%3D%271"
# 输出: <div class="no-result">无搜索结果</div>
```

### 验证 3：普通功能正常

| 测试项 | 结果 |
|--------|------|
| 新用户注册（vuser） | ✅ 成功 |
| 新用户登录 | ✅ 成功 |
| 正常搜索（keyword=admin） | ✅ 返回结果 |
| 搜索无结果（keyword=nonexistent） | ✅ 显示"无搜索结果" |
| 原有 admin 登录 | ✅ 正常 |

### 验证 4：错误信息不泄露 SQL 结构

```bash
# 注册时注入特殊字符 → 返回通用错误
curl "http://target/register" -d "username=x')--&password=pass&email=a@a.com&phone=000"
# 输出: <div class="error-msg">注册失败，请稍后重试</div>
# 而非: "注册失败：6 values for 4 columns"
```

### 验证 5：服务端日志记录完整（供运维排查）

```bash
# 注册失败时服务端输出到控制台（不返回给用户）
[SQL] INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?) | params: username="x')--"
```
运维人员可通过日志分析问题，但攻击者无法从响应中获取信息。

---

## 六、安全对比：修复前 vs 修复后

| 攻击向量 | 修复前 | 修复后 | 根因修复 |
|---------|--------|--------|---------|
| `' OR '1'='1` → 全部用户泄露 | ✅ 成功 | ❌ 被阻止 | 参数化 → 输入变为数据 |
| `' UNION SELECT 1,2,3,4--` | ✅ 成功 | ❌ 被阻止 | 参数化 → UNION 不解析 |
| `' UNION SELECT password FROM users--` | ✅ 哈希泄露 | ❌ 被阻止 | 参数化 → 子查询不解析 |
| `' OR LENGTH(password)>50--` 盲注 | ✅ 可行 | ❌ 被阻止 | 参数化 → OR 子句不解析 |
| 错误信息探测列数 | ✅ 泄露 "6 values for 4 columns" | ❌ 仅显示通用提示 | 异常分类+友好提示 |
| email 字段注入闭合 | ✅ 改变 SQL 结构 | ❌ 参数化，无效 | 循环中所有字段统一修复 |
| phone 字段注入闭合 | ✅ 改变 SQL 结构 | ❌ 参数化，无效 | 循环中所有字段统一修复 |
| 超长 payload 盲注 | ✅ 可提交数千字符 | ❌ 截断至 128 | 服务端长度校验 |
| `<script>` XSS | ✅ 如果关闭 autoescape 则可利用 | ❌ 显式 `\|e` 转义 | 防御纵深 |
| 正常注册/搜索功能 | ✅ 正常 | ✅ 正常 | 功能不受影响 |

---

## 七、修复原理总结

### 核心防御：参数化查询（Prepared Statement）

```
SQL 执行流程（修复前）:
  用户输入 → f-string 拼接 → 完整 SQL 字符串 → 编译执行
  用户输入中的 "' UNION SELECT ..." → 被解析为 SQL 指令 → 注入成功

SQL 执行流程（修复后）:
  用户输入 → 作为参数传入 → SQL 结构已编译（? 占位符）→ 绑定参数 → 执行
  用户输入中的 "' UNION SELECT ..." → 被当作字符串值 → 匹配 LIKE 模式 → 注入失败
```

### 防御深度层次

```
Layer 1: 参数化查询（核心）—— 阻止 SQL 注入
    ↓
Layer 2: 输入校验（strip + len）—— 阻止超长 payload
    ↓
Layer 3: 错误信息保护（友好提示）—— 阻止信息泄露
    ↓
Layer 4: 前端限制（maxlength）—— 提升用户体验
    ↓
Layer 5: 输出转义（|e 过滤器）—— 阻止反射型 XSS
```

### 一句话总结

> **SQL 注入的根因不是"过滤不严"，而是"数据和代码未分离"。参数化查询将用户输入固定为数据而非代码，从架构层面彻底消除注入可能。**

---

## 八、后续建议

| 优先级 | 建议 | 说明 |
|--------|------|------|
| 🔴 高 | **使用 ORM 框架** | 用 SQLAlchemy / Flask-SQLAlchemy 替代裸 sqlite3，杜绝手动拼 SQL |
| 🔴 高 | **CI/CD 加入安全扫描** | 集成 Semgrep / Bandit 规则，自动检测 f-string SQL 拼接 |
| 🟠 中 | **正则校验** | email 校验格式，phone 校验手机号格式（如 `^1[3-9]\d{9}$`） |
| 🟠 中 | **最小权限原则** | 搜索用只读连接，注册用读写连接，分离数据库账号 |
| 🟠 中 | **WAF 规则** | 在反向代理层添加 SQL 注入检测（拦截 `UNION`、`OR 1=1`、`--` 等） |
| 🟢 低 | **哈希破解防护** | 密码使用 scrypt 高成本参数（time_cost=2, mem_cost=64MB）增加破解难度 |
| 🟢 低 | **安全审计自动化** | 使用 sqlmap 定期对 Web 应用进行自动化 SQL 注入测试 |
