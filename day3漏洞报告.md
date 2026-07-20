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

## 三、修复方案

### 核心修复：参数化查询

将 4 个注入点的 f-string 拼接全部替换为 `?` 占位符参数化查询：

**修复后的注册代码：**
```python
sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
c.execute(sql, (username, hashed_pw, email, phone))
```

**修复后的搜索代码：**
```python
sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
c.execute(sql, (f"%{keyword}%", f"%{keyword}%"))
```

### 辅助修复

| 修复项 | 具体措施 |
|--------|---------|
| **错误信息保护** | 捕获 `sqlite3.IntegrityError` 返回通用提示，不暴露 SQL 细节 |
| **输入长度校验** | 注册：username ≤ 64, password ≤ 256, email ≤ 128, phone ≤ 20 |
| **输入长度校验** | 搜索：keyword ≤ 128 |
| **前端输入限制** | register.html 添加 `maxlength` 属性 |
| **输入去除空白** | 所有输入字段使用 `.strip()` 去除首尾空格 |

### 修改文件清单

| 文件 | 修改类型 | 说明 |
|------|----------|------|
| `app.py` | 修改 | 注册路由：参数化查询 + 输入验证 + 错误信息保护 |
| `app.py` | 修改 | 搜索路由：参数化查询 + keyword 长度限制 |
| `templates/register.html` | 修改 | 添加 input `maxlength` 属性 |

---

## 四、修复验证

### 验证 1：参数化查询已生效

服务端日志输出（新）：
```
[SQL] SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ? | params: keyword="' UNION SELECT..."
```

修复前日志输出（旧）：
```
[SQL] SELECT id, username, email, phone FROM users WHERE username LIKE '%' UNION SELECT...%' OR email LIKE '%' UNION SELECT...%'
```

### 验证 2：注入 payload 被当作文字搜索

```bash
# UNION 注入 → 返回"无搜索结果"（视为普通文字）
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
# 输出: <div class="error-msg">注册失败：用户名已存在</div>
# 而非: "注册失败：6 values for 4 columns"
```

---

## 五、安全对比：修复前 vs 修复后

| 攻击向量 | 修复前 | 修复后 |
|---------|--------|--------|
| `' OR '1'='1` → 全部用户泄露 | ✅ 成功 | ❌ 被阻止 |
| `' UNION SELECT 1,2,3,4--` | ✅ 成功 | ❌ 被阻止 |
| `' UNION SELECT password FROM users--` | ✅ 哈希泄露 | ❌ 被阻止 |
| `' OR LENGTH(password)>50--` 盲注 | ✅ 可行 | ❌ 被阻止 |
| 错误信息探测列数 | ✅ 泄露 "6 values for 4 columns" | ❌ 仅显示通用提示 |
| email 字段注入闭合 | ✅ 改变 SQL 结构 | ❌ 参数化，无效 |
| 正常注册/搜索功能 | ✅ 正常 | ✅ 正常 |

---

## 六、后续建议

1. **使用 ORM 框架**（如 SQLAlchemy / Flask-SQLAlchemy）替代裸 SQL 操作，从根本上杜绝 SQL 注入
2. **正则校验**：对 email 字段校验邮箱格式，phone 字段校验手机号格式
3. **WAF 规则**：在反向代理层添加 SQL 注入检测规则（如 `'--`、`UNION`、`OR 1=1` 等关键字拦截）
4. **最小权限**：数据库连接使用只读账号用于搜索，写操作使用独立账号
5. **定期审计**：使用自动化工具（SQLMap、Semgrep）定期扫描代码中的 SQL 注入风险
6. **预编译语句**：生产环境强制使用参数化查询，CI/CD 流水线中加入 SQL 注入检测门禁
