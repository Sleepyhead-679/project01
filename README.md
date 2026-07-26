# 简易用户信息管理平台

一个基于 Python Flask 的简易用户信息管理 Web 应用，提供登录/登出、用户注册、用户信息展示、搜索与头像上传功能。

## 项目结构

```
project01/
├── app.py                  # Flask 主应用 — 路由、SQLite 数据库、启动入口
├── data/
│   └── users.db            # SQLite 用户数据库（自动生成）
├── templates/
│   ├── base.html           # 基础模板 — 导航栏布局（含头像显示）
│   ├── login.html          # 登录页面 — 用户名/密码表单
│   ├── register.html       # 注册页面 — 新用户注册表单
│   ├── upload.html         # 上传页面 — 头像上传表单 + 预览
│   └── index.html          # 首页 — 用户信息展示 + 搜索面板
├── static/
│   ├── css/
│   │   └── style.css       # 全局样式 — 渐变导航栏、卡片布局、搜索表格、头像
│   └── uploads/            # 头像上传存储目录
├── README.md               # 本文件
├── .env.example            # 环境变量配置参考
├── report/                 # 安全审计报告目录
│   ├── day2密码漏洞报告.md  # 密码安全修复报告
│   ├── day3漏洞报告.md      # SQL 注入审计与修复报告
│   ├── day6_文件包含漏洞报告_王君豪.md  # 文件包含漏洞审计与修复报告
│   ├── day4_文件上传漏洞报告_王君豪.md  # 文件上传漏洞审计与修复报告
│   ├── day5_越权业务逻辑漏洞报告_王君豪.md  # 越权与业务逻辑漏洞审计与修复报告
│   ├── day7_CSRF漏洞报告_王君豪.md  # CSRF漏洞审计与修复报告
│   ├── day8_SSTI漏洞报告_王君豪.md  # SSTI漏洞审计与修复报告
│   └── day9_命令执行漏洞报告_王君豪.md  # 命令注入漏洞审计与修复报告
```

## 环境要求

- Python 3.8+
- Flask 3.x

## 快速开始

### 1. 安装依赖

```bash
pip install flask flask-wtf flask-limiter
```

### 2. 启动服务

```bash
cd /opt/project01
python app.py
```

服务默认监听在 **http://0.0.0.0:5000**, 首次启动自动创建 SQLite 数据库和预置用户。

### 3. 访问界面

打开浏览器访问 `http://localhost:5000`。

## 预置账号

> ⚠️ 以下为演示账号，密码已使用 bcrypt/scrypt 哈希存储，**不推荐直接在生产环境使用**。
> 上线前请务必修改默认密码并启用强密码策略。

| 用户名 | 角色 | 邮箱 | 手机 | 余额 |
|--------|------|------|------|------|
| admin | admin | admin@example.com | 13800138000 | 99999 |
| alice | user | alice@example.com | 13900139001 | 100 |

> 首次登录后建议立即修改默认密码。

## 功能说明

### 用户注册
- 新用户可通过 `/register` 页面注册，提供用户名、密码、邮箱、手机号
- 注册成功后自动跳转至登录页并提示"注册成功，请登录"

### 用户登录
- 输入用户名和密码进行身份验证，支持预置用户（admin/alice）和注册用户
- 验证通过后跳转至首页显示完整用户信息
- 错误密码会显示友好的错误提示

### 用户搜索
- 登录后可在首页搜索框按用户名或邮箱搜索用户
- 搜索结果以表格形式展示（ID、用户名、邮箱、手机）
- 无结果时显示"无搜索结果"

### 退出登录
- 清除会话状态并返回首页，同时清除客户端 Cookie

### 头像上传
- 登录后可在导航栏点击"上传头像"进入上传页面
- 支持 PNG/JPG/GIF/WEBP/BMP 格式图片
- 上传成功后导航栏显示圆形头像缩略图
- 点击导航栏头像可重新上传替换
- 头像文件保存在 `static/uploads/` 目录
- 文件大小限制：16MB

### 个人中心
- 登录后可在导航栏点击"个人中心"查看个人资料
- 显示用户 ID、用户名、邮箱、手机号、余额
- 资料来自数据库，数据一致性有保障

### 充值
- 在个人中心页面可进行账户充值
- 充值金额必须在 0.01 ~ 100,000 元之间
- 充值成功后余额实时更新
- 仅限给自己的账户充值

### 动态页面
- 通过 `/page?name=help` 可访问帮助中心
- 页面内容从 `pages/` 目录加载
- 仅允许加载白名单中的页面

### 修改密码
- 在个人中心页面可修改密码
- 需要输入原密码验证身份
- 仅限修改自己的密码
- 需要 CSRF Token 与 Referer 双重校验

### 欢迎页
- 通过 `/welcome?name=张三` 可访问个性化欢迎页
- 不填 name 参数时默认显示"亲爱的用户"

### 反馈
- 通过 `/feedback` 可提交意见反馈
- 支持姓名和留言内容
- 提交后显示反馈结果页面

### Ping 网络诊断
- 通过 `/ping` 可进行网络连通性测试（需登录）
- 支持 IP 地址和域名输入
- 以控制台风格显示 Ping 输出结果
- 支持 IP 白名单校验，仅允许合法 IP 和域名

## 安全措施（已启用）

| 类别 | 措施 | 说明 |
|------|------|------|
| 🛡️ **SQL 注入防护** | 参数化查询 | 所有数据库操作使用 `?` 占位符 |
| 🔐 **密码安全** | scrypt 哈希 | 使用 `werkzeug.security` 哈希存储 |
| 🚫 **CSRF 保护** | Flask-WTF CSRFProtect 全局保护 | 所有 POST 端点防跨站 |
| ⏱️ **速率限制** | Flask-Limiter | 登录 10 次/分钟/IP |
| 📋 **安全响应头** | CSP/X-Frame-Options 等 | XSS 与点击劫持防护 |
| 🔒 **会话安全** | HttpOnly + SameSite + 8h + Secure(生产环境) | 防 Session 劫持 |
| 🕵️ **版本隐藏** | WSGI 中间件 | 隐藏 Server 版本信息 |
| ✂️ **输入过滤** | 长度校验 + strip() + 自动转义 | 防 XSS 与超长输入 |
| 📝 **错误保护** | 通用错误提示 | 不泄露 SQL 结构 |
| 🖼️ **文件上传防护** | 扩展名白名单 + 魔术字节校验 + 路径遍历防护 | 只允许 PNG/JPG/GIF/WEBP/BMP |
| 🆔 **身份认证** | 所有敏感接口强制登录校验 | 防未授权访问 |
| 🔐 **权限校验** | user_id 从 session 获取，拒绝 URL/表单参数 | 防水平越权 |
| 💰 **充值安全** | 正数校验 + 上限 100,000 + 参数化查询 | 防负金额/超额/SQL注入 |
| 📄 **文件包含防护** | 白名单校验 + 路径分隔符剥离 + `os.path.realpath()` 边界检查 | 防任意文件读取 |
| 🔐 **密码修改安全** | 原密码校验 + Referer 校验 + CSRF Token + Session 绑定 | 防越权改密 |
| 🧩 **SSTI 防护** | 模板变量替代 f-string 拼接 + Jinja2 自动转义 | 防服务端模板注入 |
| 🖥️ **命令注入防护** | IP 白名单正则校验 + 列表传参替代 shell=True | 防命令注入与RCE |

---

## 安全审计与漏洞修复记录

本项目作为教学用途，**故意引入并逐步修复了以下安全漏洞**。每轮修复均有详细的审计报告。

### Day 2 — 密码安全修复

| 漏洞 | 类型 | 等级 | 修复方式 |
|------|------|------|---------|
| 硬编码 Secret Key | 密码安全 | 🔴 高危 | 替换为环境变量 + 随机生成 |
| 明文密码存储 | 密码安全 | 🔴 高危 | bcrypt/scrypt 哈希存储 |
| 密码回显到页面 | 信息泄露 | 🟠 中危 | 删除模板中的密码输出 |
| Flask Debug 模式 | 配置缺陷 | 🟠 中危 | 关闭 debug 模式 |
| 缺少安全响应头 | 配置缺陷 | 🟠 中危 | 添加 CSP/X-Frame-Options 等 |
| CSRF 保护缺失 | CSRF | 🟠 中危 | 启用 Flask-WTF CSRFProtect |
| 缺少速率限制 | 暴力破解 | 🔴 高危 | 添加 Flask-Limiter 10次/分钟 |
| 缺少 Session 安全配置 | 会话安全 | 🟠 中危 | 添加 HttpOnly/SameSite/8h |

详细报告：[`report/day2密码漏洞报告.md`](report/day2密码漏洞报告.md)

---

### Day 3 — SQL 注入修复

SQL 注入漏洞是由于使用 f-string 将用户输入直接拼接到 SQL 语句中导致的。攻击者可通过构造特殊字符（如单引号 `'`）改变 SQL 语句结构，执行任意 SQL 命令。

| 注入点 | 位置 | 修复方式 |
|--------|------|---------|
| **username 字段** | `/register` POST | 参数化查询 `?` 占位符 |
| **email 字段** | `/register` POST | 参数化查询 `?` 占位符 |
| **phone 字段** | `/register` POST | 参数化查询 `?` 占位符 |
| **keyword 参数** | `/search?keyword=` | 参数化查询 `?` 占位符 |

**修复前漏洞代码示例：**
```python
# ❌ f-string 直接拼接（漏洞）
sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{hashed_pw}', '{email}', '{phone}')"
c.execute(sql)

# ❌ 搜索功能同样存在
sql = f"SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
```

**修复后安全代码：**
```python
# ✅ 参数化查询（安全）
sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
c.execute(sql, (username, hashed_pw, email, phone))

sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
c.execute(sql, (f"%{keyword}%", f"%{keyword}%"))
```

详细报告：[`report/day3漏洞报告.md`](report/day3漏洞报告.md)

---

### Day 4 — 文件上传漏洞修复

头像上传功能存在 12 个安全漏洞（已修复 8 个，按业务需求保留 4 个）。

| 漏洞 | 类型 | 等级 | 修复方式 |
|------|------|------|---------|
| 任意文件上传 | 文件上传 | 🔴 高危 | 扩展名白名单 PNG/JPG/GIF/WEBP/BMP |
| SVG XSS | XSS | 🔴 高危 | 白名单拦截 `.svg` |
| .htaccess 上传 | 配置篡改 | 🔴 高危 | 隐藏文件检测 |
| PHP WebShell | RCE | 🔴 高危 | 危险扩展名黑名单（15种） |
| 文件覆盖 | 业务逻辑 | 🟠 中危 | `os.path.exists()` 检查 |
| Content-Type 篡改 | 绕过 | 🟠 中危 | MIME 白名单校验 |
| 无扩展名文件 | 文件上传 | 🟠 中危 | 必须包含扩展名 |
| 双扩展名绕过 | 文件上传 | 🟠 中危 | 分段检查危险扩展名 |
| 存储型 XSS（HTML） | XSS | 🔴 高危 | ⚠️ 保留（白名单已缓解） |
| JS + CSP 绕过 | XSS | 🔴 高危 | ⚠️ 保留（白名单已缓解） |
| 中文文件名 | 兼容性 | 🟢 低危 | ⚠️ 保留（业务需求） |
| 目录枚举 | 信息泄露 | 🟢 低危 | ⚠️ 保留（业务需求） |

**5 层文件上传防御架构：**
```
Layer 1: 扩展名白名单 + 黑名单分段检查
Layer 2: Content-Type MIME 白名单校验
Layer 3: 魔术字节签名校验（文件头 16 字节）
Layer 4: 文件覆盖保护（os.path.exists）
Layer 5: 路径遍历防护（secure_filename_original + realpath）
```

详细报告：[`report/day4_文件上传漏洞报告_王君豪.md`](report/day4_文件上传漏洞报告_王君豪.md)

---

### Day 5 — 越权与业务逻辑漏洞修复

| 漏洞 | 类型 | 等级 | 修复方式 |
|------|------|------|---------|
| `/profile` 无登录校验 | IDOR | 🔴 高危 | 添加 session 登录检查 |
| `/profile` 可查看任意用户 | IDOR | 🔴 高危 | user_id 改从 session 获取 |
| `/recharge` 越权操作 | IDOR | 🔴 高危 | user_id 从 session 获取 + 登录校验 |
| 首页余额不一致 | 业务逻辑 | 🔴 高危 | 从 DB 取真实余额覆盖字典值 |
| 充值金额可为负数 | 业务逻辑 | 🔴 高危 | 添加 `amount <= 0` 校验 |
| 充值金额无上限 | 业务逻辑 | 🟠 中危 | 上限 100,000 元 |
| 头像上传重启丢失 | 持久化 | 🟠 中危 | admin/alice 头像写入 DB |
| SQL 注入 profile/recharge | SQL 注入 | 🔴 高危 | 改为参数化查询 |

详细报告：[`report/day5_越权业务逻辑漏洞报告_王君豪.md`](report/day5_越权业务逻辑漏洞报告_王君豪.md)

---

### Day 6 — 文件包含漏洞修复（LFI）

动态页面 `/page?name=` 路由存在本地文件包含漏洞，攻击者可通过 `../` 路径遍历读取服务器任意文件。

| 漏洞 | 类型 | 等级 | 修复方式 |
|------|------|------|---------|
| 基础路径遍历 `../app.py` | LFI | 🔴 高危 | 白名单 + 路径分隔符剥离 + realpath 边界检查 |
| 绝对路径读取 `/etc/passwd` | LFI | 🔴 高危 | 白名单校验阻止 |
| URL 编码绕过 `%2e%2e%2f` | LFI | 🔴 高危 | 白名单前置校验 |
| SSH 私钥/Git/环境变量泄露 | LFI | 🔴 高危 | 路径遍历被阻断 |
| `\| safe` + 路径遍历 = HTML注入 | XSS | 🟠 中危 | 白名单确保仅可信内容渲染 |

**修复前（漏洞可读取任意文件）：**
```bash
curl "http://target/page?name=../app.py"           # ✅ 读取源代码
curl "http://target/page?name=../../../etc/passwd" # ✅ 读取系统文件
curl "http://target/page?name=../../../root/.ssh/id_ed25519" # ✅ SSH私钥
```

**修复后（三层防御）：**
```python
# Layer 1: 剥离路径分隔符
safe_name = name.replace("/", "").replace("\\", "").replace("..", "")
# Layer 2: 白名单校验
if name not in ALLOWED_PAGES:  # 仅允许 help/about/faq
    page_content = "页面不存在"
# Layer 3: realpath 目录边界检查
real_path = os.path.realpath(page_path)
if not real_path.startswith(os.path.realpath(PAGES_DIR)):
    page_content = "页面不存在"
```

详细报告：[`report/day6_文件包含漏洞报告_王君豪.md`](report/day6_文件包含漏洞报告_王君豪.md)

---

### Day 7 — CSRF 漏洞修复

`/change-password` 路由存在 5 个故意设计的安全漏洞（全部已修复）。

| 漏洞 | 类型 | 等级 | 修复方式 |
|------|------|------|---------|
| 无 CSRF Token (`@csrf.exempt`) | CSRF | 🔴 高危 | 移除 `@csrf.exempt`，启用 CSRFProtect |
| 无原密码校验 | 身份绕过 | 🔴 高危 | 添加 `check_password_hash()` 验证 |
| 无 Referer 校验 | CSRF | 🔴 高危 | 新增 `urlparse` 同源检查 |
| 越权修改他人密码 | IDOR | 🔴 高危 | `session["username"] != username` 检查 |
| `SESSION_COOKIE_SECURE=False` | 配置 | 🟠 中危 | 改为环境变量控制 |

**修复后的 6 层防御架构：**
```
Layer 1: 身份认证 — session 登录检查
Layer 2: CSRF Token — Flask-WTF CSRFProtect
Layer 3: Referer 校验 — urlparse 同源检查
Layer 4: 权限校验 — session.user == username
Layer 5: 原密码校验 — check_password_hash()
Layer 6: 密码哈希 — generate_password_hash()
```

详细报告：[`report/day7_CSRF漏洞报告_王君豪.md`](report/day7_CSRF漏洞报告_王君豪.md)

---

### Day 8 — SSTI 漏洞修复

`/welcome` 和 `/feedback` 路由使用 `render_template_string` 并通过 f-string 拼接用户输入，导致服务端模板注入漏洞。

| 漏洞 | 位置 | 等级 | 修复方式 |
|------|------|------|---------|
| `/welcome?name=` 参数 SSTI | `app.py:739-745` | 🔴 高危 | 模板变量 `{{ name }}` 替代 f-string 拼接 |
| `/feedback` name 字段 SSTI | `app.py:775,790` | 🔴 高危 | 模板变量 `{{ name }}` 传入 |
| `/feedback` message 字段 SSTI | `app.py:776,791` | 🔴 高危 | 模板变量 `{{ message }}` 传入 |

**修复前（SSTI 可 RCE）：**
```bash
curl "http://target/welcome?name={{7*7}}"                              # → 49
curl "http://target/welcome?name={{config.SECRET_KEY}}"                # → 密钥泄露
curl "http://target/welcome?name={{os.popen('id').read()}}"           # → uid=0(root)
```

**修复后：**
```python
# ❌ 漏洞代码
name = request.args.get("name", "")
render_template_string(f"<h1>欢迎你，{name}！</h1>")  # f-string 拼接

# ✅ 安全代码
name = request.args.get("name", "")
render_template_string("<h1>欢迎你，{{ name }}！</h1>", name=name)  # 模板变量
```

详细报告：[`report/day8_SSTI漏洞报告_王君豪.md`](report/day8_SSTI漏洞报告_王君豪.md)

---

### Day 9 — 命令注入漏洞修复

`/ping` 路由使用 `f"ping -c 3 {ip}"` + `shell=True` 执行系统命令，攻击者可通过 `;`、`|`、`` ` `` 注入任意命令。

| 漏洞 | 类型 | 等级 | 修复方式 |
|------|------|------|---------|
| 分号注入 `;id` | 命令注入 | 🔴 高危 | IP 正则校验 + `shell=True` → `shell=False` |
| 管道注入 `\|whoami` | 命令注入 | 🔴 高危 | 列表传参替代字符串拼接 |
| 反引号注入 `` `id` `` | 命令注入 | 🔴 高危 | 不经过 shell 解析 |
| 敏感文件读取 | 命令注入 | 🔴 高危 | 输入白名单校验 |

**修复前（3 种注入均成功）：**
```bash
curl -X POST /ping --data-urlencode "ip=127.0.0.1;id"       # → uid=0(root)
curl -X POST /ping --data-urlencode "ip=127.0.0.1|whoami"   # → root
curl -X POST /ping --data-urlencode "ip=127.0.0.1`hostname`" # → kali
```

**修复后：**
```python
# ❌ 漏洞代码
command = f"ping -c 3 {ip}"
output = subprocess.check_output(command, shell=True, ...)

# ✅ 安全代码（双层防御）
# 防御1: IP 正则 + 0-255 范围校验
is_valid = re.match(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$', ip)
# 防御2: 列表传参，不经过 shell
command = ["ping", "-c", "3", ip]
output = subprocess.check_output(command, timeout=30, stderr=subprocess.STDOUT)
```

详细报告：[`report/day9_命令执行漏洞报告_王君豪.md`](report/day9_命令执行漏洞报告_王君豪.md)

---

### 漏洞修复统计

| 安全审计轮次 | 修复数量 | 高危 | 中危 | 低危 |
|-------------|---------|------|------|------|
| Day 2 — 密码安全 | 8 | 3 | 5 | 0 |
| Day 3 — SQL 注入 | 4 | 4 | 0 | 0 |
| Day 4 — 文件上传 | 8 | 5 | 4 | 3 |
| Day 5 — 越权与业务逻辑 | 10 | 6 | 4 | 0 |
| Day 6 — 文件包含 LFI | 5 | 4 | 1 | 0 |
| Day 7 — CSRF | 5 | 4 | 1 | 0 |
| Day 8 — SSTI | 3 | 3 | 0 | 0 |
| Day 9 — 命令注入 | 1 | 1 | 0 | 0 |
| **合计** | **44** | **30** | **15** | **3** |

## 技术要点

- 基于 Flask 框架，使用 Session 管理用户登录状态
- 数据库使用 SQLite（`data/users.db`），支持用户持久化
- 使用 Jinja2 模板引擎实现页面继承与渲染
- Jinja2 自动 HTML 转义防止 XSS 攻击
- 使用 Flask-Limiter 实现 API 速率限制
- 导航栏采用蓝色渐变背景（#667eea → #764ba2）
- 页面采用卡片式布局设计

## 注意事项

> ⚠️ 本项目为教学演示用途，**请勿直接用于生产环境**。
>
> 生产环境应使用：
> - PostgreSQL/MySQL 替代 SQLite
> - 使用 ORM（如 SQLAlchemy）替代裸 SQL
> - HTTPS 加密传输
> - 强随机 `SECRET_KEY`（通过环境变量设置）
> - 更高强度的密码策略
>
> 生成 SECRET_KEY: `python3 -c "import secrets; print(secrets.token_hex(32))"`

## 许可

MIT
