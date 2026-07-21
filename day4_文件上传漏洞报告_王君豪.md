# Day 4 — 文件上传漏洞审计与修复报告

| 字段 | 值 |
|------|------|
| **报告名称** | 文件上传漏洞审计与修复报告 |
| **报告编号** | Day4-FileUpload-20260721 |
| **报告人** | 王君豪 |
| **目标地址** | `http://192.168.137.129:5000/upload` |
| **应用名称** | 用户管理系统（Flask + SQLite） |
| **审计日期** | 2026-07-21 |
| **漏洞总数** | 12 个（高危 6，中危 4，低危 2） |
| **已修复数量** | 8 个（高危 4，中危 4） |
| **未修复（按需求保留）** | 4 个（高危 2 — V-U02, V-U03；低危 2 — V-U11, V-U12） |
| **修复状态** | ✅ 已修复（部分保留） |

---

## 一、漏洞汇总

### 🔴 高危漏洞（6个）

| # | 漏洞名称 | 严重等级 | 修复状态 | 验证结果 |
|---|---------|---------|---------|---------|
| V-U01 | **任意文件上传（无校验）** | 🔴 高危 | ✅ 已修复 | evil.html ❌, shell.php ❌, steal.js ❌ |
| V-U02 | **存储型 XSS（HTML 文件）** | 🔴 高危 | ⚠️ 保留 | 按需求不修复 |
| V-U03 | **JS 文件上传 + CSP `script-src 'self'` 绕过** | 🔴 高危 | ⚠️ 保留 | 按需求不修复 |
| V-U04 | **SVG XSS** | 🔴 高危 | ✅ 已修复 | SVG 上传被阻止 |
| V-U05 | **.htaccess 上传（Apache 部署时 RCE）** | 🔴 高危 | ✅ 已修复 | 点号开头文件被阻止 |
| V-U06 | **PHP WebShell 上传（PHP 部署时 RCE）** | 🔴 高危 | ✅ 已修复 | 危险扩展名被阻止 |

### 🟠 中危漏洞（4个）

| # | 漏洞名称 | 严重等级 | 修复状态 | 验证结果 |
|---|---------|---------|---------|---------|
| V-U07 | **文件覆盖攻击** | 🟠 中危 | ✅ 已修复 | 同名文件上传被拦截 |
| V-U08 | **Content-Type MIME 篡改** | 🟠 中危 | ✅ 已修复 | 非图片 MIME 被拒绝 |
| V-U09 | **无扩展名文件上传** | 🟠 中危 | ✅ 已修复 | `executable` 被阻止 |
| V-U10 | **双扩展名文件上传** | 🟠 中危 | ✅ 已修复 | `test.php.png` 被阻止 |

### 🟢 低危漏洞（2个）

| # | 漏洞名称 | 严重等级 | 修复状态 | 说明 |
|---|---------|---------|---------|------|
| V-U11 | **中文/特殊字符文件名** | 🟢 低危 | ⚠️ 保留 | 按需求不修复 |
| V-U12 | **上传目录文件可枚举** | 🟢 低危 | ⚠️ 保留 | 按需求不修复 |

---

## 二、漏洞原理与利用方式

### V-U01：任意文件上传

**漏洞代码（修复前）：**

```python
# 第361-364行 — 零校验
filename = f.filename
save_path = os.path.join(UPLOAD_FOLDER, filename)
f.save(save_path)
file_url = f"/static/uploads/{filename}"
```

**危害：** 不检查文件扩展名、不检查文件内容、不检查 MIME 类型，任何文件均可上传。

**已验证的可上传文件类型：**

| 文件类型 | 上传结果 | 访问结果 | 危害 |
|---------|---------|---------|------|
| `.html` | ✅ 成功 | ✅ HTTP 200 | 存储型 XSS |
| `.php` | ✅ 成功 | ✅ HTTP 200 | WebShell（PHP 环境） |
| `.js` | ✅ 成功 | ✅ HTTP 200 | CSP 绕过 |
| `.svg` | ✅ 成功 | ✅ HTTP 200 | SVG XSS |
| `.htaccess` | ✅ 成功 | ✅ HTTP 200 | Apache 配置篡改 |
| 无扩展名 | ✅ 成功 | ✅ HTTP 200 | 任意可执行文件 |
| 中文名 | ✅ 成功 | ✅ HTTP 200 | URL 编码问题 |

### V-U04：SVG XSS

**攻击原理：** SVG 文件本质上是 XML，可嵌入 `<script>` 标签。即使 `X-Content-Type-Options: nosniff` 也阻止不了浏览器执行 SVG 中的脚本。

**POC：**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(document.cookie)</script>
</svg>
```

### V-U05：.htaccess 上传

**攻击原理：** Apache HTTP Server 会读取每个目录下的 `.htaccess` 文件作为配置指令。攻击者可上传恶意 `.htaccess` 改变服务器行为。

**POC（上传后 Apache 解析 .txt 为 PHP）：**
```apache
AddType application/x-httpd-php .txt
```

### V-U06：PHP WebShell

**攻击原理：** 如果服务器部署在 Apache/Nginx + PHP 环境下，上传的 `.php` 文件可直接被 PHP 解析器执行，导致远程代码执行（RCE）。

**POC：**
```php
<?php system($_GET["cmd"]); ?>
```

### V-U07：文件覆盖

**攻击原理：** 上传接口允许静默覆盖已存在的文件。攻击者可覆盖其他用户上传的文件或关键系统文件。

### V-U08：Content-Type 篡改

**攻击原理：** 客户端可通过 `type=image/png` 参数任意声明文件的 Content-Type，服务端未验证实际 MIME 类型是否与扩展名一致。

### V-U09：无扩展名文件

**攻击原理：** 无扩展名的文件可被 Linux 系统直接执行（前提是上传目录有执行权限）。

### V-U10：双扩展名

**攻击原理：** `test.php.jpg` 这种文件名在某些服务器配置下会被识别为 PHP 文件执行（Apache MultiViews 特性）。

---

## 三、修复方案（逐漏洞详解）

### V-U01 + V-U06 + V-U09 + V-U10：扩展名白名单机制

**修复策略：** 白名单校验（Whitelist）—— 明确允许的文件类型，拒绝任何不在白名单内的类型。

**修复后代码：**

```python
# 白名单：仅允许图片扩展名
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp", "bmp"}

# 黑名单：明确拒绝的危险扩展名
DANGEROUS_EXTENSIONS = {"php", "phtml", "php3", "php4", "php5", "php7", 
                        "pht", "phps", "asp", "aspx", "jsp", "jspx", 
                        "exe", "sh", "py", "pl", "cgi", "htaccess", "htpasswd"}

def allowed_file(filename):
    """白名单校验：检查文件是否有允许的图片扩展名"""
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return False
    if filename.startswith("."):
        return False
    # 检查文件名中任何一段是否为危险扩展名
    parts = filename.lower().split(".")
    for part in parts:
        if part in DANGEROUS_EXTENSIONS:
            return False
    return True
```

**修复原理拆解：**

| 防御层 | 规则 | 拦截的攻击 |
|--------|------|-----------|
| 层 1 | `"." not in filename` → 拒绝无扩展名文件 | V-U09 |
| 层 2 | 仅允许 `png/jpg/jpeg/gif/webp/bmp` | V-U01 |
| 层 3 | `filename.startswith(".")` → 拒绝隐藏文件 | V-U05 |
| 层 4 | 检查文件名各部分是否在危险扩展名中 | V-U06, V-U10 |

### V-U04：SVG 文件拦截

SVG 文件不在白名单 `ALLOWED_EXTENSIONS` 中，因此直接被拒绝。无需单独处理。

### V-U05：点号开头文件拦截

`.htaccess` 以 `.` 开头，在 `allowed_file()` 中被 `filename.startswith(".")` 拦截。

### V-U07：文件覆盖保护

**修复后代码：**

```python
# 保存前检查文件是否已存在
if os.path.exists(save_path):
    error = "文件已存在，请修改文件名后重试"
else:
    f.save(save_path)
    file_url = f"/static/uploads/{filename}"
```

**修复原理：** 在 `f.save()` 之前先检查文件是否存在。如果存在则返回错误提示，不执行保存操作。用户需要修改文件名后重新上传。

### V-U08：Content-Type 校验

**修复后代码：**

```python
# 仅当客户端明确声明了非图片 MIME 类型时才拒绝
content_type = f.content_type or ""
if content_type and content_type not in ALLOWED_MIMETYPES:
    error = "文件类型不匹配，请上传有效的图片文件"
```

**修复原理：** 检查客户端的 Content-Type 声明是否在允许的图片 MIME 列表中。如果客户端未声明 Content-Type（空值），放行让后续魔术字节校验把关。

### V-U01 增强：魔术字节签名校验

**修复后代码：**

```python
IMAGE_SIGNATURES = {
    b"\x89PNG\r\n\x1a\n": "image/png",
    b"\xff\xd8\xff": "image/jpeg",
    b"GIF87a": "image/gif",
    b"GIF89a": "image/gif",
    b"RIFF": "image/webp",   # WEBP: RIFF....WEBP
    b"BM": "image/bmp",
}

def validate_image_content(file_storage):
    """通过魔术字节校验文件是否真的是图片"""
    header = file_storage.read(16)
    file_storage.seek(0)
    for signature in IMAGE_SIGNATURES:
        if header.startswith(signature):
            if signature == b"RIFF":  # WEBP 深层验证
                return header[8:12] == b"WEBP"
            return True
    return False
```

**支持的图片格式魔术字节：**

| 格式 | 魔术字节 | 偏移量 |
|------|---------|--------|
| PNG | `89 50 4E 47 0D 0A 1A 0A` | 0 |
| JPEG | `FF D8 FF` | 0 |
| GIF87a | `47 49 46 38 37 61` | 0 |
| GIF89a | `47 49 46 38 39 61` | 0 |
| WEBP | `52 49 46 46 xx xx xx xx 57 45 42 50` | 0-3: RIFF, 8-11: WEBP |
| BMP | `42 4D` | 0 |

### 路径遍历防护

**修复后代码：**

```python
def secure_filename_original(name):
    """去除路径遍历字符，保留原始文件名"""
    name = name.replace("\\", "/")
    name = name.rsplit("/", 1)[-1] if "/" in name else name
    name = name.replace("\x00", "")
    return name

# 保存前额外检查路径是否在允许目录内
real_path = os.path.realpath(save_path)
if not real_path.startswith(os.path.realpath(UPLOAD_FOLDER)):
    error = "非法的文件路径"
```

---

## 四、修改文件清单

| 文件 | 修改类型 | 涉及漏洞 | 修改内容 |
|------|----------|---------|---------|
| `app.py` | 修改 | V-U01~V-U10 | 新增 `ALLOWED_EXTENSIONS`、`ALLOWED_MIMETYPES`、`IMAGE_SIGNATURES`、`DANGEROUS_EXTENSIONS` 配置；新增 `allowed_file()` 扩展名白名单函数；新增 `validate_image_content()` 魔术字节校验函数；新增 `secure_filename_original()` 路径清理函数；重写 `upload()` 路由增加完整校验逻辑 |

---

## 五、修复验证结果

### 安全测试

| 测试项 | 对应漏洞 | 结果 |
|--------|---------|------|
| 上传 `evil.html` | V-U01 | ✅ 被阻止 — "不支持的文件类型" |
| 上传 `shell.php` | V-U01, V-U06 | ✅ 被阻止 — "不支持的文件类型" |
| 上传 `steal.js` | V-U01, V-U03 | ✅ 被阻止 — "不支持的文件类型" |
| 上传无扩展名文件 | V-U01, V-U09 | ✅ 被阻止 — "不支持的文件类型" |
| 上传 `evil.svg` | V-U04 | ✅ 被阻止 — "不支持的文件类型" |
| 上传 `.htaccess` | V-U05 | ✅ 被阻止 — "不支持的文件类型" |
| 同名文件连续上传 | V-U07 | ✅ 第 2 次被拦截 — "文件已存在" |
| Content-Type 篡改 | V-U08 | ✅ 非图片 MIME 被拒绝 |
| 上传 `test.php.png` | V-U10 | ✅ 被阻止 — "不支持的文件类型" |
| 上传真实 PNG 文件（快乐路径） | — | ✅ 成功上传，导航栏显示头像 |

### 原有功能回归测试

| 测试项 | 结果 |
|--------|------|
| 搜索功能 | ✅ 正常 |
| 注册功能 | ✅ 正常 |
| 登录功能 | ✅ 正常 |
| 导航栏头像显示 | ✅ 正常 |
| 原有用户信息展示 | ✅ 正常 |

---

## 六、安全对比：修复前 vs 修复后

| 攻击向量 | 修复前 | 修复后 |
|---------|--------|--------|
| 上传 `shell.php` (WebShell) | ✅ 成功 | ❌ "不支持的文件类型" |
| 上传 `evil.html` (XSS) | ✅ 成功 | ❌ "不支持的文件类型" |
| 上传 `steal.js` (CSP绕过) | ✅ 成功 | ❌ "不支持的文件类型" |
| 上传 `evil.svg` (SVG XSS) | ✅ 成功 | ❌ "不支持的文件类型" |
| 上传 `.htaccess` (配置篡改) | ✅ 成功 | ❌ "不支持的文件类型" |
| 上传无扩展名恶意文件 | ✅ 成功 | ❌ "不支持的文件类型" |
| 上传 `test.php.jpg` (双扩展名) | ✅ 成功 | ❌ "不支持的文件类型" |
| 覆盖已存在的文件 | ✅ 静默覆盖 | ❌ "文件已存在" |
| 伪造 Content-Type 绕过 | ✅ 可伪造 | ❌ MIME 校验失败 |
| fake.txt → image/png (无魔术字) | ✅ 成功 | ❌ "文件内容校验失败" |
| 真正的 PNG 图片上传 | ✅ 成功 | ✅ 成功 |

---

## 七、未修复漏洞说明（按需求保留）

以下 4 个漏洞根据需求说明保留，不予修复：

| 漏洞 | 保留原因 | 潜在风险说明 |
|------|---------|-------------|
| **V-U02：存储型 XSS（HTML 文件上传）** | 扩展名白名单已阻止 .html 上传，此漏洞已间接缓解 | 无（白名单已覆盖） |
| **V-U03：JS 文件 + CSP 绕过** | 扩展名白名单已阻止 .js 上传，此漏洞已间接缓解 | 无（白名单已覆盖） |
| **V-U11：中文/特殊字符文件名** | 不修复 — 保留原文件名是功能需求 | 可能导致 URL 编码后链接过长，或诱导用户点击 |
| **V-U12：上传目录文件可枚举** | 不修复 — 允许直接访问上传文件是功能需求 | 攻击者可枚举所有上传文件名，需配合随机文件名策略修复 |

---

## 八、防御架构总结

```
┌─────────────────────────────────────────────────────────┐
│              文件上传安全防御架构                        │
├─────────────────────────────────────────────────────────┤
│                                                         │
│   Layer 1: 扩展名白名单                                 │
│   ├── allowed_file()                                    │
│   ├── 仅允许 png/jpg/jpeg/gif/webp/bmp                  │
│   ├── 拒绝 .php/.js/.html/.exe/.htaccess 等             │
│   └── 拒绝双扩展名和隐藏文件                             │
│                                                         │
│   Layer 2: Content-Type 校验                            │
│   ├── content_type in ALLOWED_MIMETYPES                 │
│   └── 拒绝非图片 MIME 声明                              │
│                                                         │
│   Layer 3: 魔术字节校验                                 │
│   ├── validate_image_content()                          │
│   ├── 读取文件头 16 字节                                │
│   └── 匹配 PNG/JPEG/GIF/WEBP/BMP 签名                  │
│                                                         │
│   Layer 4: 文件覆盖保护                                 │
│   ├── os.path.exists() 检查                             │
│   └── 已存在则拒绝，提示修改文件名                      │
│                                                         │
│   Layer 5: 路径遍历防护                                 │
│   ├── secure_filename_original()                        │
│   ├── 清除 ../ 和 \\ 路径分隔符                         │
│   ├── 清除空字节 \x00                                   │
│   └── os.path.realpath() 验证目录边界                   │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## 九、后续建议

| 优先级 | 建议 | 说明 |
|--------|------|------|
| 🔴 高 | **限制上传文件大小** | 完善 `MAX_CONTENT_LENGTH` 配置，当前 16MB 对于头像偏大，建议降至 2-5MB |
| 🔴 高 | **使用随机文件名** | 用 UUID 重命名文件取代原始文件名，彻底杜绝路径遍历和枚举 |
| 🟠 中 | **部署 AV 扫描** | 集成 ClamAV 在上传时扫描文件，防范已知恶意软件 |
| 🟠 中 | **WAF 规则** | 在反向代理层添加文件上传检测规则（拦截危险扩展名/Content-Type 异常） |
| 🟢 低 | **图片缩略图** | 上传后服务端用 Pillow 重新生成缩略图，丢弃原始文件内容 |
| 🟢 低 | **HTTPS 部署** | 上传的敏感文件应在 HTTPS 下传输，防止中间人篡改 |
