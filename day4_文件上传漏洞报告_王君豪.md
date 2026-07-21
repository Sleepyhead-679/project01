# Day 4 — 文件上传漏洞审计与修复报告

**王君豪-2024141530115**

| 字段 | 值 |
|------|------|
| 目标地址 | `http://192.168.137.129:5000/upload` |
| 应用名称 | 用户管理系统（Flask + SQLite） |
| 审计日期 | 2026-07-21 |
| 漏洞总数 | 8 个（高危 4，中危 4）|
| 修复状态 | ✅ 全部已修复 |

---

## 一、漏洞列表

| # | 漏洞名称 | 位置 | 等级 |
|---|---------|------|------|
| 1 | 任意文件上传（无扩展名/内容校验） | `/upload` POST | 🔴 高危 |
| 2 | SVG 文件 XSS 上传 | `/upload` POST | 🔴 高危 |
| 3 | .htaccess 文件上传（Apache 配置篡改） | `/upload` POST | 🔴 高危 |
| 4 | PHP WebShell 上传（PHP 环境 RCE） | `/upload` POST | 🔴 高危 |
| 5 | 文件覆盖攻击 | `/upload` POST | 🟠 中危 |
| 6 | Content-Type MIME 类型篡改 | `/upload` POST | 🟠 中危 |
| 7 | 无扩展名文件上传 | `/upload` POST | 🟠 中危 |
| 8 | 双扩展名文件上传（如 `test.php.jpg`） | `/upload` POST | 🟠 中危 |

---

## 二、漏洞原理与修复方案

---

### 漏洞 1：任意文件上传

**原理：** 上传功能不做任何检查（扩展名、内容、MIME），攻击者可上传任意类型文件。

**修复前代码：**
```python
filename = f.filename
save_path = os.path.join(UPLOAD_FOLDER, filename)
f.save(save_path)  # 无任何校验
```

**修复方案：三层校验**

```python
# 配置
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp", "bmp"}
ALLOWED_MIMETYPES = {"image/png", "image/jpeg", "image/gif", "image/webp", "image/bmp"}
DANGEROUS_EXTENSIONS = {"php","phtml","php3","php4","php5","php7","pht","phps",
                        "asp","aspx","jsp","jspx","exe","sh","py","pl","cgi",
                        "htaccess","htpasswd"}
IMAGE_SIGNATURES = {
    b"\x89PNG\r\n\x1a\n": "image/png",
    b"\xff\xd8\xff": "image/jpeg",
    b"GIF87a": "image/gif",
    b"GIF89a": "image/gif",
    b"RIFF": "image/webp",
    b"BM": "image/bmp",
}
```

**第一层：扩展名白名单 + 黑名单**
```python
def allowed_file(filename):
    if "." not in filename:          # 拒绝无扩展名
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    if ext not in ALLOWED_EXTENSIONS: # 白名单校验
        return False
    if filename.startswith("."):      # 拒绝隐藏文件（.htaccess）
        return False
    parts = filename.lower().split(".") # 分段检查双扩展名
    for part in parts:
        if part in DANGEROUS_EXTENSIONS:
            return False
    return True
```

**第二层：Content-Type 校验**
```python
content_type = f.content_type or ""
if content_type and content_type not in ALLOWED_MIMETYPES:
    error = "文件类型不匹配"
```

**第三层：魔术字节校验**
```python
def validate_image_content(file_storage):
    header = file_storage.read(16)
    file_storage.seek(0)
    for signature in IMAGE_SIGNATURES:
        if header.startswith(signature):
            if signature == b"RIFF":
                return header[8:12] == b"WEBP"
            return True
    return False
```

**验证：**
```bash
curl -F "file=@shell.php"  → ❌ "不支持的文件类型"
curl -F "file=@evil.html"  → ❌ "不支持的文件类型"
curl -F "file=@real.png"   → ✅ 成功上传
```

---

### 漏洞 2：SVG XSS 上传

**原理：** SVG 可嵌入 `<script>` 标签，浏览器渲染时执行恶意 JS。

**修复前：** `.svg` 扩展名未被禁止，直接上传保存。

**修复方案：** SVG 扩展名不在 `ALLOWED_EXTENSIONS` 白名单中，自动被拒绝。

```python
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp", "bmp"}
#                     ↑ "svg" 不在其中
```

额外防线：SVG 以 `<?xml` 开头，不匹配任何图片魔术字节签名，即使伪造扩展名也会被魔术字节校验拦截。

**验证：**
```bash
curl -F "file=@evil.svg"  → ❌ "不支持的文件类型"
```

---

### 漏洞 3：.htaccess 上传

**原理：** Apache 读取目录下 `.htaccess` 作为配置指令。攻击者可上传恶意文件改变服务器行为（如将 `.txt` 当作 PHP 解析）。

**修复方案：** `allowed_file()` 中的 `filename.startswith(".")` 拒绝所有隐藏文件。同时 `DANGEROUS_EXTENSIONS` 包含 `"htaccess"` 作为第二道防线。

```python
if filename.startswith("."):
    return False
```

| 攻击手法 | 拦截方式 |
|---------|---------|
| `.htaccess` | `startswith(".")` 拦截 |
| `my.htaccess` | 不在 `ALLOWED_EXTENSIONS` |
| `my.htaccess.png` | `"htaccess"` 在 `DANGEROUS_EXTENSIONS` |

**验证：**
```bash
curl -F "file=@.htaccess"  → ❌ "不支持的文件类型"
```

---

### 漏洞 4：PHP WebShell 上传

**原理：** 部署在 PHP 环境时，上传的 `.php` 文件可被 PHP 解析器执行，导致 RCE。

**修复方案：** 白名单拦截 + 危险扩展名黑名单双重阻断。

```python
# 白名单不含 php → 直接拒绝
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp", "bmp"}

# 黑名单包含所有 PHP 变体（防双扩展名绕过）
DANGEROUS_EXTENSIONS = {
    "php", "phtml", "php3", "php4", "php5", "php7", "pht", "phps",
    "asp", "aspx", "jsp", "jspx",
    "exe", "sh", "py", "pl", "cgi",
}
```

**危险扩展名对照：**
```
.php .phtml .php3 .php4 .php5 .php7 .pht .phps  → PHP 全系列
.asp .aspx                                       → ASP/.NET
.jsp .jspx                                       → Java
.exe .sh .py .pl .cgi                            → 可执行/脚本
```

**验证：**
```bash
curl -F "file=@shell.php"     → ❌ 被阻止
curl -F "file=@shell.phtml"   → ❌ 被阻止
curl -F "file=@shell.php5"    → ❌ 被阻止
curl -F "file=@shell.asp"     → ❌ 被阻止
curl -F "file=@real.png"      → ✅ 成功
```

---

### 漏洞 5：文件覆盖攻击

**原理：** 上传接口不检查文件是否已存在，同名文件静默覆盖。攻击者可覆盖其他用户的文件。

**修复方案：** `f.save()` 前用 `os.path.exists()` 检查。

```python
if os.path.exists(save_path):
    error = "文件已存在，请修改文件名后重试"
else:
    f.save(save_path)
    file_url = f"/static/uploads/{filename}"
    success = "头像上传成功"
```

**流程图：**
```
上传文件 → os.path.exists()
    ├── True  → "文件已存在"（不保存）
    └── False → f.save() 保存文件
```

**验证：**
```bash
# 第一次上传
curl -F "file=@photo.png"  → ✅ "头像上传成功"
# 第二次上传同名文件
curl -F "file=@photo.png"  → ❌ "文件已存在"
# 改名后重新上传
curl -F "file=@photo_v2.png" → ✅ "头像上传成功"
```

---

### 漏洞 6：Content-Type MIME 篡改

**原理：** 客户端可通过 `type=image/png` 参数随意声明 Content-Type，服务端未做校验。

**修复方案：** MIME 白名单校验。

```python
ALLOWED_MIMETYPES = {"image/png", "image/jpeg", "image/gif", "image/webp", "image/bmp"}

content_type = f.content_type or ""
if content_type and content_type not in ALLOWED_MIMETYPES:
    error = "文件类型不匹配，请上传有效的图片文件"
```

Content-Type 为空时跳过（兼容老旧客户端），由魔术字节校验把关。

**分层校验互补：**

| 场景 | Content-Type | 魔术字节 | 结果 |
|------|-------------|----------|------|
| 真实 PNG + `image/png` | ✅ | ✅ | ✅ |
| 真实 PNG + 无声明 | ⚠️ 跳过 | ✅ | ✅ |
| 文本文件 + `image/png` | ✅（伪造成功） | ❌ | ❌ |
| 恶意文件 + `application/x-php` | ❌ | — | ❌ |

**验证：**
```bash
curl -F "file=@fake.txt;type=image/png;filename=innocent.png"  → ❌ "文件内容校验失败"
curl -F "file=@fake.txt;type=application/x-php;filename=x.php" → ❌ "文件类型不匹配"
```

---

### 漏洞 7：无扩展名文件上传

**原理：** 无扩展名文件在 Linux 下可直接作为可执行文件运行。

**修复方案：** `allowed_file()` 要求文件名必须包含 `.`。

```python
if "." not in filename:
    return False
```

图片文件必有扩展名（`.png`、`.jpg` 等），无扩展名在 Web 场景下无合理业务用途。

**验证：**
```bash
curl -F "file=@executable"  → ❌ "不支持的文件类型"
curl -F "file=@photo"       → ❌ "不支持的文件类型"
curl -F "file=@photo.png"   → ✅ 成功
```

---

### 漏洞 8：双扩展名文件上传

**原理：** `test.php.jpg` 在某些服务器配置下被识别为 PHP 执行（Apache MultiViews、Nginx 配置错误等）。

**修复方案：** `allowed_file()` 中分段检查文件名每一段是否在危险扩展名黑名单中。

```python
# "test.php.jpg" → parts = ["test", "php", "jpg"]
# "php" 在 DANGEROUS_EXTENSIONS 中 → 拒绝
parts = filename.lower().split(".")
for part in parts:
    if part in DANGEROUS_EXTENSIONS:
        return False
```

**校验对比：**

| 文件名 | 仅白名单检查 | 加黑名单分段检查 |
|--------|-------------|----------------|
| `photo.png` | ✅ | ✅ |
| `test.php.jpg` | ✅（jpg 在白名单） | ❌（php 在黑名单） |
| `a.asp.png` | ✅ | ❌ |
| `a.jsp.png` | ✅ | ❌ |
| `a.htaccess.png` | ✅ | ❌ |

**验证：**
```bash
curl -F "file=@test.php.jpg"    → ❌ 被阻止
curl -F "file=@a.asp.png"       → ❌ 被阻止
curl -F "file=@photo.png"       → ✅ 成功
```

---

## 三、路径遍历防护（通用安全加固）

**原理：** 攻击者在文件名注入 `../` 或 `\x00` 空字节，使文件保存到上传目录之外。

**修复方案：** `secure_filename_original()` 函数三层清洗 + `os.path.realpath()` 目录边界检查。

```python
def secure_filename_original(name):
    name = name.replace("\\", "/")                    # 反斜杠→正斜杠
    name = name.rsplit("/", 1)[-1] if "/" in name else name  # 只取最后一段
    name = name.replace("\x00", "")                   # 清除空字节
    return name

# 目录边界校验
real_path = os.path.realpath(save_path)
if not real_path.startswith(os.path.realpath(UPLOAD_FOLDER)):
    error = "非法的文件路径"
```

---

## 四、修改文件清单

| 文件 | 修改内容 |
|------|---------|
| `app.py` | 新增扩展名白名单、MIME 白名单、魔术字节签名库、危险扩展名黑名单；新增 `allowed_file()`、`validate_image_content()`、`secure_filename_original()` 三个函数；重写 `upload()` 路由集成 5 层校验 |

---

## 五、修复验证结果

| 测试项 | 对应漏洞 | 结果 |
|--------|---------|------|
| 上传 `evil.html` | 漏洞 1 | ✅ 被阻止 |
| 上传 `shell.php` | 漏洞 1, 4 | ✅ 被阻止 |
| 上传 `evil.svg` | 漏洞 2 | ✅ 被阻止 |
| 上传 `.htaccess` | 漏洞 3 | ✅ 被阻止 |
| 上传 `shell.phtml` / `shell.asp` | 漏洞 4 | ✅ 被阻止 |
| 同名文件二次上传 | 漏洞 5 | ✅ 被拦截 |
| 伪造 Content-Type | 漏洞 6 | ✅ 被拒绝 |
| 无扩展名文件 | 漏洞 7 | ✅ 被阻止 |
| 双扩展名 `test.php.jpg` | 漏洞 8 | ✅ 被阻止 |
| 路径遍历 `../../x.txt` | 通用加固 | ✅ 路径被清洗 |
| 真实 PNG 图片上传 | 快乐路径 | ✅ 成功，导航栏显示头像 |
| 搜索/注册/登录/退出 | 回归测试 | ✅ 全部正常 |

---

## 六、五层防御架构

```
用户上传文件
    │
    ▼
Layer 1: 扩展名校验（白名单 + 黑名单 + 隐藏文件 + 分段检查）
    │
    ▼
Layer 2: Content-Type 校验（MIME 白名单匹配）
    │
    ▼
Layer 3: 魔术字节校验（文件头签名匹配 6 种图片格式）
    │
    ▼
Layer 4: 文件覆盖保护（os.path.exists() 检查）
    │
    ▼
Layer 5: 路径遍历防护（secure_filename_original + os.path.realpath）
    │
    ▼
✅ 文件保存到 static/uploads/
```

---

## 七、后续建议

| 优先级 | 建议 |
|--------|------|
| 🔴 高 | 限制上传大小至 2-5MB（当前 16MB）|
| 🔴 高 | 使用 UUID 重命名文件，杜绝路径遍历和枚举 |
| 🟠 中 | 集成 ClamAV 在上传时扫描文件 |
| 🟢 低 | 服务端用 Pillow 重新生成缩略图，丢弃原始内容 |
