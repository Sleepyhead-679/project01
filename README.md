# 简易用户信息管理平台

一个基于 Python Flask 的简易用户信息管理 Web 应用，提供基础的登录/登出与用户信息展示功能。

## 项目结构

```
project01/
├── app.py                  # Flask 主应用 — 路由、用户数据库、启动入口
├── templates/
│   ├── base.html           # 基础模板 — 导航栏布局
│   ├── login.html          # 登录页面 — 用户名/密码表单
│   └── index.html          # 首页 — 用户信息展示面板
├── static/
│   └── css/
│       └── style.css       # 全局样式 — 渐变导航栏、卡片布局
└── README.md               # 本文件
```

## 环境要求

- Python 3.8+
- Flask 3.x

## 快速开始

### 1. 安装 Flask

```bash
pip install flask
```

### 2. 启动服务

```bash
cd /opt/project01
python app.py
```

服务默认监听在 **http://0.0.0.0:5000**。

### 3. 访问界面

打开浏览器访问 `http://localhost:5000`。

## 预置账号

> ⚠️ 以下为演示账号，密码已使用 bcrypt 哈希存储，**不推荐直接在生产环境使用**。
> 上线前请务必修改默认密码并启用强密码策略。

| 用户名 | 角色 | 邮箱 | 手机 | 余额 |
|--------|------|------|------|------|
| admin | admin | admin@example.com | 13800138000 | 99999 |
| alice | user | alice@example.com | 13900139001 | 100 |

> 首次登录后建议立即修改默认密码。默认密码仅保存在密码哈希中，无法直接获取。

## 功能说明

- **登录** — 输入用户名和密码进行身份验证，验证通过后跳转至首页并显示完整用户信息
- **用户信息展示** — 登录成功后以列表形式展示当前用户的全部信息（用户名、密码、邮箱、手机、角色、余额）
- **退出登录** — 清除会话状态并返回首页
- **错误提示** — 登录失败时显示友好的错误信息

## 技术要点

- 基于 Flask 框架，使用 Session 管理用户登录状态
- 用户数据以字典形式硬编码在代码中（演示用途）
- 使用 Jinja2 模板引擎实现页面继承与渲染
- 🛡️ **安全措施已启用**：
  - 密码使用 `werkzeug.security.generate_password_hash()` bcrypt/ scrypt 哈希存储
  - Flask-WTF CSRF 保护防止跨站请求伪造
  - Flask-Limiter 登录速率限制防暴力破解
  - 安全响应头（CSP, X-Frame-Options, X-Content-Type-Options 等）
  - 会话安全配置（HttpOnly, SameSite, 有效期限制）
  - 服务器版本信息隐藏
- 导航栏采用蓝色渐变背景（#667eea → #764ba2）
- 页面采用卡片式布局设计

## 注意事项

> ⚠️ 本项目为教学演示用途，用户数据硬编码在源代码中，**请勿直接用于生产环境**。
> 生产环境应使用数据库存储用户信息、HTTPS 加密传输，并配置强随机 SECRET_KEY。
> 可使用环境变量 `SECRET_KEY` 设置自定义密钥。
> 生成方式: `python3 -c "import secrets; print(secrets.token_hex(32))"`

## 许可

MIT
