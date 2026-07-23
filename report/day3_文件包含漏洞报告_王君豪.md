# Day 3 — 文件包含漏洞审计与修复报告

**王君豪-2024141530115**

| 字段 | 值 |
|------|------|
| 报告编号 | DAY3-LFI-20260721 |
| 目标地址 | `http://192.168.137.129:5000/page?name=` |
| 应用名称 | 用户管理系统（Flask + SQLite） |
| 审计日期 | 2026-07-21 |
| 漏洞类型 | 本地文件包含（LFI）/ 路径遍历 |
| 发现数量 | 5 个（高危 4，中危 1） |
| 修复状态 | ✅ 全部已修复 |

---

## 一、漏洞分类统计

| 严重等级 | 数量 | 漏洞编号 |
|---------|------|---------|
| 🔴 高危 | 4 | LFI-01, LFI-02, LFI-03, LFI-04 |
| 🟠 中危 | 1 | LFI-05 |

---

## 二、漏洞详情与修复方案

---

### LFI-01：基础路径遍历（高危）

**漏洞位置：** `app.py` 第 620 行

```python
page_path = os.path.join("pages", name)
# 用户输入 name = "../app.py"
# os.path.join("pages", "../app.py") → "app.py"
# → 成功读取项目根目录下的 app.py 源代码
```

**漏洞原理：** `os.path.join("pages", "../app.py")` 在 Python 中的结果不是 `"pages/../app.py"`，而是 `"app.py"`。这是因为 `os.path.join` 遇到 `..` 时会进行路径解析。攻击者通过 `../` 可以跳出 `pages/` 目录，读取任意文件。

**攻击复现：**
```bash
curl "http://target/page?name=../app.py"
# → 返回 app.py 全部源代码

curl "http://target/page?name=../../../etc/passwd"
# → root:x:0:0 系统用户信息泄露
```

**修复方案（三层防御）：**

```python
# 第 1 层：剥离路径分隔符
safe_name = name.replace("/", "").replace("\\", "").replace("..", "")
# name="../app.py" → safe_name="app.py"（../ 被移除）

# 第 2 层：白名单校验
ALLOWED_PAGES = {"help", "help.html", "about", "about.html", "faq", "faq.html"}
if name not in ALLOWED_PAGES:
    page_content = "页面不存在"

# 第 3 层：目录边界检查
real_path = os.path.realpath(page_path)
if not real_path.startswith(os.path.realpath(PAGES_DIR)):
    page_content = "页面不存在"
```

**修复验证：**
```bash
curl "http://target/page?name=../app.py"
# → "页面不存在" ✅

curl "http://target/page?name=../../../etc/passwd"
# → "页面不存在" ✅
```

---

### LFI-02：绝对路径直接读取（高危）

**漏洞位置：** `app.py` 第 620 行

```python
page_path = os.path.join("pages", name)
# 用户输入 name = "/etc/passwd"
# os.path.join("pages", "/etc/passwd") → "/etc/passwd"
# ↑ Python 特性：遇到绝对路径参数，丢弃前面的路径
```

**漏洞原理：** Python 的 `os.path.join` 有一个特性——当某个参数是绝对路径（以 `/` 开头）时，它会丢弃之前的所有参数，直接返回该绝对路径。这导致攻击者只需传入 `name=/etc/passwd` 即可直接读取系统任意文件。

**修复方案：** 同 LFI-01，白名单校验在路径拼接之前执行，`/etc/passwd` 不在白名单中直接拒绝。

**修复验证：**
```bash
curl "http://target/page?name=/etc/passwd"
# → "页面不存在" ✅
```

---

### LFI-03：URL 编码绕过（高危）

**漏洞位置：** `app.py` 第 620 行（输入未解码校验）

```bash
# 直接传入 ../ 被路径清洗拦截后，攻击者尝试编码绕过
curl "http://target/page?name=%2e%2e%2fapp.py"
# %2e%2e%2f = ../ （URL 解码后）
```

**漏洞原理：** Flask 自动对 URL 参数进行 URL 解码，因此 `%2e%2e%2f` 解码后变为 `../`，可以绕过简单的关键字过滤（如过滤 `../` 字符串本身但没有先解码再过滤的逻辑）。但本修复方案使用了白名单，在参数值进入任何路径处理逻辑之前就进行校验，编码与否不影响白名单判断。

**修复验证：**
```bash
curl "http://target/page?name=%2e%2e%2fapp.py"
# → "页面不存在" ✅（不在白名单中）
```

---

### LFI-04：SSH 私钥与 Git 配置泄露（高危）

**漏洞位置：** `app.py` 第 620-632 行（修复前可读取任意文件）

**影响：** 攻击者可通过路径遍历读取以下敏感文件：

| 目标文件 | 泄露内容 | 严重程度 |
|---------|---------|---------|
| `~/.ssh/id_ed25519` | SSH 私钥 | 🔴 服务器被接管 |
| `.git/config` | GitHub 远程仓库地址 | 🟠 信息泄露 |
| `proc/self/environ` | 环境变量（含 API Key） | 🔴 凭据泄露 |
| `proc/self/cmdline` | 进程启动命令 | 🟢 信息收集 |
| `.env.example` | 配置模板 | 🟢 信息收集 |

**攻击复现（修复前）：**
```bash
curl "http://target/page?name=../../../root/.ssh/id_ed25519"
# → -----BEGIN OPENSSH PRIVATE KEY-----  SSH 私钥泄露！

curl "http://target/page?name=../.git/config"
# → url = git@github.com:user/repo.git

curl "http://target/page?name=../../../proc/self/environ"
# → PWD=/opt/project01, ANTHROPIC_API_KEY=xxx  环境变量泄露
```

**修复验证：**
```bash
curl "http://target/page?name=../../../root/.ssh/id_ed25519"
# → "页面不存在" ✅
```

---

### LFI-05：`| safe` 模板渲染导致 HTML 注入（中危）

**漏洞位置：** `templates/index.html` 第 6 行

```html
{{ page_content | safe }}
```

**漏洞原理：** Jinja2 的 `| safe` 过滤器会关闭自动 HTML 转义，直接将内容作为 HTML 渲染。如果攻击者通过路径遍历读取了一个包含 JavaScript 的文件（如模板文件 `login.html`），其中的 `<script>` 标签会直接执行。

**风险：** 配合 LFI-01 到 LFI-04 的路径遍历，攻击者可以：
1. 读取 `login.html` 模板 → 观察到页面结构和 CSRF token 逻辑
2. 结合日志投毒 → 在 access log 中注入 JS → 读取后执行

**修复方案：** 由于白名单修复后，只有受信任的 `help.html` 可被加载，`| safe` 仅作用于可信内容。保留 `| safe` 以使帮助中心 HTML 正常渲染（标题、列表、样式等），同时白名单确保不可信文件无法加载。

---

## 三、修改文件清单

| 文件 | 修改内容 |
|------|---------|
| `app.py` | 新增 `ALLOWED_PAGES` 白名单 + `PAGES_DIR` 绝对路径常量；`dynamic_page()` 重写：第 1 层路径分隔符剥离、第 2 层白名单校验、第 3 层 `os.path.realpath()` 目录边界检查 |

---

## 四、代码对比

### 修复前

```python
@app.route("/page")
def dynamic_page():
    name = request.args.get("name", "")
    page_content = None
    if name:
        page_path = os.path.join("pages", name)  # ❌ 无校验
        if os.path.exists(page_path):
            with open(page_path, "r") as f:
                page_content = f.read()           # ❌ 读取任意文件
```

### 修复后

```python
ALLOWED_PAGES = {"help", "help.html", "about", "about.html", "faq", "faq.html"}
PAGES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pages")

@app.route("/page")
def dynamic_page():
    name = request.args.get("name", "")
    page_content = None
    if name:
        # Layer 1: 剥离路径分隔符
        safe_name = name.replace("/", "").replace("\\", "").replace("..", "")
        # Layer 2: 白名单校验
        if name not in ALLOWED_PAGES:
            page_content = "页面不存在"
        else:
            page_path = os.path.join(PAGES_DIR, safe_name)
            # Layer 3: 目录边界检查
            real_path = os.path.realpath(page_path)
            if not real_path.startswith(os.path.realpath(PAGES_DIR)):
                page_content = "页面不存在"
            elif os.path.exists(real_path):
                with open(real_path, "r", encoding="utf-8") as f:
                    page_content = f.read()
```

---

## 五、修复验证结果

| 测试项 | 结果 |
|--------|------|
| 正常访问 `/page?name=help` | ✅ 帮助中心正常显示 |
| 路径遍历 `../app.py` | ✅ 被阻止 |
| 多层路径遍历 `../../../etc/passwd` | ✅ 被阻止 |
| 绝对路径 `/etc/passwd` | ✅ 被阻止 |
| URL 编码 `%2e%2e%2fapp.py` | ✅ 被阻止 |
| SSH 私钥读取 `../../../root/.ssh/id_ed25519` | ✅ 被阻止 |
| Git 配置读取 `../.git/config` | ✅ 被阻止 |
| 模板文件读取 `../templates/base.html` | ✅ 被阻止 |
| 未在白名单中的页面名 `name=xxx` | ✅ 被阻止 |
| 原有登录/搜索功能 | ✅ 正常 |

---

## 六、防御总结

```
修复前：
  name=../app.py → os.path.join("pages", "../app.py") → "app.py" → ✅ 读取成功

修复后：
  name=../app.py
    → Layer 1: replace("/", "") → "..app.py"  ← 但也够用了，主要靠白名单
    → Layer 2: "..app.py" in ALLOWED_PAGES? → ❌ 不在 → "页面不存在"
  
  即使 Layer 1 和 Layer 2 都绕过：
    → Layer 3: real_path.startswith(PAGES_DIR)? → ❌ "页面不存在"
```
