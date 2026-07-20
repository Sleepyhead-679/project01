# 简易用户信息管理平台

一个基于 Python Flask 的简易用户信息管理 Web 应用，提供登录/登出、用户注册、用户信息展示与搜索功能。

## 项目结构

```
project01/
├── app.py                  # Flask 主应用 — 路由、SQLite 数据库、启动入口
├── data/
│   └── users.db            # SQLite 用户数据库（自动生成）
├── templates/
│   ├── base.html           # 基础模板 — 导航栏布局
│   ├── login.html          # 登录页面 — 用户名/密码表单
│   ├── register.html       # 注册页面 — 新用户注册表单
│   └── index.html          # 首页 — 用户信息展示 + 搜索面板
├── static/
│   └── css/
│       └── style.css       # 全局样式 — 渐变导航栏、卡片布局、搜索表格
├── README.md               # 本文件
├── .env.example            # 环境变量配置参考
├── security-remediation-report.md  # 密码安全修复报告
└── day3漏洞报告.md          # SQL 注入审计与修复报告
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

## 安全措施（已启用）

| 措施 | 说明 |
|------|------|
| 🛡️ **参数化 SQL 查询** | 所有数据库操作使用 `?` 占位符，防止 SQL 注入 |
| 🔐 **密码哈希存储** | 使用 `werkzeug.security` scrypt 哈希，非明文存储 |
| 🚫 **CSRF 保护** | Flask-WTF CSRFProtect 全局保护 POST 请求 |
| ⏱️ **登录速率限制** | 10 次/分钟/IP，防暴力破解 |
| 📋 **安全响应头** | CSP、X-Frame-Options、X-Content-Type-Options 等 |
| 🔒 **会话安全** | HttpOnly、SameSite=Lax、8 小时有效期 |
| 🕵️ **版本隐藏** | WSGI 中间件隐藏 Server 版本信息 |
| ✂️ **输入过滤** | 长度校验、strip() 去除首尾空白、HTML 自动转义 |
| 📝 **错误信息保护** | 数据库错误返回通用提示，不泄露 SQL 细节 |

## SQL 注入修复记录

该应用曾存在 4 个 SQL 注入点（全部已修复）：

| 注入点 | 位置 | 修复方式 |
|--------|------|---------|
| username 字段 | `/register` POST | 参数化查询 |
| email 字段 | `/register` POST | 参数化查询 |
| phone 字段 | `/register` POST | 参数化查询 |
| keyword 参数 | `/search?keyword=` | 参数化查询 |

详细审计报告见 [`day3漏洞报告.md`](day3漏洞报告.md)。

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
