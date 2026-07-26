# Day 9 — 命令注入漏洞审计与修复报告

**王君豪-2024141530115**

| 字段 | 值 |
|------|------|
| 报告编号 | DAY9-CMDI-20260724 |
| 目标地址 | `http://192.168.137.129:5000/ping` |
| 应用名称 | 用户管理系统（Flask + SQLite） |
| 审计日期 | 2026-07-24 |
| 审计类型 | 命令注入（Command Injection） |
| 漏洞总数 | 1 个 |
| 修复状态 | ✅ 已修复 |

---

## 一、漏洞汇总

| 编号 | 漏洞名称 | 类型 | 等级 | 位置 | 风险描述 |
|------|---------|------|------|------|---------|
| V-01 | `/ping` POST `ip` 参数命令注入 | 命令注入 | 🔴 高危 | `app.py:894-897` | 用户输入直接拼入系统命令，通过 `shell=True` 执行，可注入任意命令实现 RCE |

---

## 二、漏洞原理

### 2.1 什么是命令注入？

命令注入（Command Injection）是指攻击者通过向应用程序提交恶意构造的输入，使得该输入作为系统命令的一部分被执行。与 SQL 注入类似，命令注入的根因是**用户输入与命令代码未分离**。

### 2.2 命令注入的三种利用方式

```bash
# 原始命令
ping -c 3 127.0.0.1

# 方式1: 分号 ; — 顺序执行多条命令
ping -c 3 127.0.0.1; id           → 先 ping，再执行 id

# 方式2: 管道 | — 前命令输出作为后命令输入
ping -c 3 127.0.0.1| whoami       → whoami 的输出代替 ping 的输出

# 方式3: 反引号 `` — 命令替换
ping -c 3 127.0.0.1`hostname`     → 先执行 hostname，结果拼入 ping 参数
```

### 2.3 shell=True 的危险性

```python
# ❌ 危险模式：shell=True 将所有输入传给系统 shell 解析
command = f"ping -c 3 {ip}"                            # 字符串拼接
subprocess.check_output(command, shell=True, ...)       # shell 解析
# 最终 shell 执行的命令：
# ping -c 3 127.0.0.1; id
#           ↑ 分号被 shell 解析为命令分隔符


# ✅ 安全模式：列表传参，不经过 shell
command = ["ping", "-c", "3", ip]                      # 列表参数
subprocess.check_output(command, shell=False, ...)      # 不经过 shell
# 系统直接执行 ping 程序，参数 "127.0.0.1;id" 被视为一个整体参数
# ping: 127.0.0.1;id: Name or service not known
#           ↑ 分号不会被解析，因为它不是 shell
```

---

## 三、漏洞详情与利用方式

### 3.1 漏洞位置

| 字段 | 值 |
|------|-----|
| **路由** | `POST /ping` |
| **代码行** | `app.py` 第 894、897 行 |
| **注入参数** | `ip`（POST 表单参数）|
| **命令执行** | `subprocess.check_output(command, shell=True, ...)` |

### 3.2 漏洞代码逐行分析

```python
@app.route("/ping", methods=["GET", "POST"])
def ping():
    ...
    if request.method == "POST":
        ip = request.form.get("ip", "")               # ← 用户输入，无校验
        
        if ip:
            # 第894行: ❌ f-string 直接拼接
            command = f"ping -c 3 {ip}"
            #          ↑ 用户输入中的 ; | ` 等特殊字符被保留
            
            # 第897行: ❌ shell=True 通过系统 shell 执行
            output = subprocess.check_output(command, shell=True, ...)
            #          ↑ shell 解析 command 字符串
            #            遇到 ; 或 | 时执行额外命令
```

**为什么 f-string + shell=True 组合特别危险：**

```
f"ping -c 3 {ip}" 当 ip = "127.0.0.1;cat /etc/passwd"
        ↓
Python 展开为: "ping -c 3 127.0.0.1;cat /etc/passwd"
        ↓
传给 shell=True → 系统 shell (bash/zsh) 解析
        ↓
shell 看到分号 ; → 执行两条命令:
  1. ping -c 3 127.0.0.1
  2. cat /etc/passwd       ← 攻击者的恶意命令被执行
```

### 3.3 攻击演示（修复前）

**3.3.1 基础命令执行（; 分号注入）**

```bash
curl -X POST http://target/ping \
  --data-urlencode "ip=127.0.0.1;id"
# 执行: ping -c 3 127.0.0.1;id
# 输出中包含: uid=0(root) gid=0(root) groups=0(root)
```

**3.3.2 管道注入（| 管道符）**

```bash
curl -X POST http://target/ping \
  --data-urlencode "ip=127.0.0.1|whoami"
# 执行: ping -c 3 127.0.0.1|whoami
# 输出: root
```

**3.3.3 反引号注入**

```bash
curl -X POST http://target/ping \
  --data-urlencode "ip=127.0.0.1`hostname`"
# 执行: ping -c 3 127.0.0.1`hostname`
# → 等价于 ping -c 3 127.0.0.1kali
```

**3.3.4 敏感文件读取**

```bash
curl -X POST http://target/ping \
  --data-urlencode "ip=127.0.0.1;cat /etc/passwd | head -3"
#  输出: root:x:0:0:root:/root:/usr/bin/zsh
```

**3.3.5 SSH 私钥泄露**

```bash
curl -X POST http://target/ping \
  --data-urlencode "ip=127.0.0.1;cat ~/.ssh/id_ed25519"
#  输出: -----BEGIN OPENSSH PRIVATE KEY-----
```

### 3.4 攻击链

```
攻击者
  │
  ├──→ 探测:  ip=127.0.0.1                     → Ping正常      ✅ 功能可用
  │
  ├──→ 注入:  ip=127.0.0.1;id                  → uid=0(root)  🔴 RCE确认
  │
  ├──→ 读取:  ip=127.0.0.1;cat /etc/passwd     → root:x:0:0   🔴 文件泄露
  │
  ├──→ 密钥:  ip=127.0.0.1;cat ~/.ssh/id_ed25519 → SSH密钥泄露 🔴 服务器沦陷
  │
  └──→ 控制:  下载并执行恶意程序 → 创建反向Shell → 完全控制服务器
```

---

## 四、修复方案

### 4.1 核心修复：双层防御

```python
# ╔════════════════════════════════════════════════════╗
# ║  修复1: 输入校验 — 只允许合法 IP 和域名           ║
# ╚════════════════════════════════════════════════════╝

import re

ip = request.form.get("ip", "").strip()

# IPv4 格式校验
ipv4_pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
# 域名格式校验
domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?\.[a-zA-Z]{2,}$'

is_ipv4 = re.match(ipv4_pattern, ip)
is_domain = re.match(domain_pattern, ip)

if is_ipv4:
    # 验证每个字段 0-255
    octets = [int(x) for x in ip.split(".")]
    if all(0 <= o <= 255 for o in octets):
        is_valid = True
    else:
        error = "IP 地址格式错误，每个字段必须在 0-255 之间"
elif is_domain:
    is_valid = True
else:
    error = "请输入有效的 IP 地址或域名"


# ╔════════════════════════════════════════════════════╗
# ║  修复2: 列表传参 — 不使用 shell=True              ║
# ╚════════════════════════════════════════════════════╝

if is_valid:
    # ✅ 使用列表而非字符串，不经过 shell 解析
    command = ["ping", "-c", "3", ip]
    output = subprocess.check_output(command, timeout=30, stderr=subprocess.STDOUT)
    #                      ↑ 不传 shell=True，默认 shell=False
```

### 4.2 修复原理对比

| 对比项 | 修复前（漏洞） | 修复后（安全） |
|--------|---------------|---------------|
| **命令构建** | `f"ping -c 3 {ip}"`（字符串拼接） | `["ping", "-c", "3", ip]`（列表传参） |
| **执行方式** | `shell=True`（经过系统 shell） | `shell=False`（直接执行程序） |
| **输入验证** | ❌ 无验证 | ✅ IP 正则 + 字段范围 + 域名正则 |
| **`;id` 注入** | shell 解析为两条命令 ✅ 执行 | ping 收到参数 `"127.0.0.1;id"` → 非法主机名 ❌ 失败 |
| **`\|whoami` 注入** | shell 解析管道 ✅ 执行 | ping 收到参数 `"127.0.0.1\|whoami"` → 非法主机名 ❌ 失败 |

### 4.3 输入校验逻辑

```
用户输入 ip
    │
    ▼
┌────────────────────────────────────────────┐
│  IPv4 正则匹配?                             │
│  ├── 是 → 检查每段 0-255                   │
│  │    ├── 全通过 → is_valid = True         │
│  │    └── 有超出 → "字段必须在0-255之间"    │
│  └── 否 → 域名正则匹配?                     │
│       ├── 是 → is_valid = True              │
│       └── 否 → "请输入有效的IP地址或域名"    │
└────────────────────────────────────────────┘
    │
    ▼
┌────────────────────────────────────────────┐
│  is_valid?                                   │
│  ├── True → ["ping", "-c", "3", ip]       │
│  └── False → 返回错误提示                   │
└────────────────────────────────────────────┘
```

### 4.4 涉及文件

| 文件 | 修改内容 |
|------|---------|
| `app.py:894-897` | `f"ping -c 3 {ip}"` + `shell=True` → `["ping", "-c", "3", ip]` + `shell=False` |
| `app.py:890-904` | 新增 `import re`；新增 IP 正则校验 + 域名正则校验；新增字段范围检查（0-255）；新增用户友好错误提示 |

---

## 五、修复验证

### 5.1 安全测试

| 测试项 | Payload | 修复前 | 修复后 | 结果 |
|--------|---------|--------|--------|------|
| 正常 Ping | `127.0.0.1` | ✅ Ping 成功 | ✅ Ping 成功 | ✅ 功能正常 |
| 管道注入 | `127.0.0.1\|id` | ✅ `root` 执行成功 | ❌ "请输入有效的 IP 地址或域名" | ✅ 已修复 |
| 分号注入 | `127.0.0.1;id` | ✅ `uid=0(root)` | ❌ "请输入有效的 IP 地址或域名" | ✅ 已修复 |
| 反引号注入 | `` 127.0.0.1`id` `` | ✅ 反引号被执行 | ❌ "请输入有效的 IP 地址或域名" | ✅ 已修复 |
| 超范围 IP | `256.256.256.256` | ✅ 执行失败 | ❌ "每个字段必须在 0-255 之间" | ✅ 已修复 |
| 非法字符 | `abc;rm -rf /` | ✅ 命令执行 | ❌ "请输入有效的 IP 地址或域名" | ✅ 已修复 |
| 未登录访问 | — | ✅ 可访问 | ❌ 302 跳转登录 | ✅ 已修复 |

### 5.2 回归测试

| 测试项 | 结果 |
|--------|------|
| Ping 127.0.0.1 (localhost) | ✅ 成功 |
| 搜索功能 | ✅ 正常 |
| 登录功能 | ✅ 正常 |
| 个人中心 | ✅ 正常 |
| 修改密码 | ✅ 正常 |

---

## 六、安全修复原理总结

### subprocess 的两种调用方式对比

```python
# ╔══════════════════════════════════════════════════════╗
# ║  方式1: shell=True（危险）                          ║
# ╚══════════════════════════════════════════════════════╝
subprocess.check_output("ping -c 3 127.0.0.1;id", shell=True)

# 等价于在终端执行:
# $ ping -c 3 127.0.0.1;id
#           ↑ shell 会解析并执行分号后的命令


# ╔══════════════════════════════════════════════════════╗
# ║  方式2: 列表传参 shell=False（安全）                 ║
# ╚══════════════════════════════════════════════════════╝
subprocess.check_output(["ping", "-c", "3", "127.0.0.1;id"])

# 等价于直接执行 ping 程序:
# exec("ping", ["ping", "-c", "3", "127.0.0.1;id"])
#                           ↑ "127.0.0.1;id" 整体作为第3个参数传给 ping
#                           分号不会被解析，因为根本没有 shell
```

### 安全口诀

> **列表传参不生壳，用户输入先校验。**
> 
> 列表传参 → 不经过 shell，特殊字符不会被解析
> 不生壳 → `shell=False`（默认值），拒绝任何 shell 解析
> 先校验 → 正则白名单，只允许合法 IP 和域名

---

## 七、防御建议

| 优先级 | 措施 | 说明 |
|--------|------|------|
| 🔴 高 | **永远不使用 `shell=True`** | 使用列表传参 `["cmd", "arg1", "arg2"]` |
| 🔴 高 | **输入白名单校验** | 使用正则表达式限制输入格式 |
| 🟠 中 | **最小权限运行** | 不以 root 权限运行 Web 服务 |
| 🟠 中 | **命令执行替代方案** | 使用 Python 库替代系统命令（如 `pythonping`） |
| 🟢 低 | **沙箱/容器隔离** | 在 Docker 容器中运行，限制系统命令影响范围 |
