# singsub — 订阅转换器

支持 **Clash YAML / URI / sing-box JSON** 三种格式输入，输出 **sing-box 配置** 或 **URI 列表**。提供 HTTP 服务模式，支持 Python 脚本装配模板 + 懒加载订阅。

---

## 快速开始

```bash
# 1. 复制配置
cp config.example.json config.json
# 编辑 config.json：填写 token 和订阅链接

# 2. 命令行转换
./singsub.py convert "https://你的订阅链接"
./singsub.py convert "https://..." -f uri                                          # 转成 URI
./singsub.py convert "https://..." -o result.json                                  # 输出到文件

# 3. HTTP 服务
./singsub.py serve
# 访问 http://localhost:8080/<token>?name=自建
# 访问 http://localhost:8080/<token>?name=自建&format=uri
# 访问 http://localhost:8080/<token>?script=homeserver
# 访问 http://localhost:8080/<token>            ← 合并所有订阅
```

---

## 用法

### 命令行

这玩意是我一开始拿来验证转换是否正确的，后面感觉自己写太累了，让glm5.2接手成用http了，之后基本不会动了

```
./singsub.py convert <url> [-f singbox|uri] [-u <user-agent>] [-o <文件>]
```

| 参数 | 说明 |
|---|---|
| `url` | 订阅链接（http/https） |
| `-f` / `--format` | 输出格式：`singbox`（默认）或 `uri` |
| `-u` / `--user-agent` | 请求时的 User-Agent，默认 `Mihomo` |
| `-o` / `--output` | 输出到文件，默认打印到 stdout |

### HTTP 服务

```
./singsub.py serve [--config config.json] [--host 0.0.0.0] [--port 8080]
```

| 参数 | 说明 |
|---|---|
| `--config` | 配置文件路径，默认 `config.json` |
| `--host` | 监听地址，默认 `0.0.0.0` |
| `--port` | 监听端口，默认 `8080` |

#### URL 参数

```
http://host:port/<token>?name=<订阅名>&format=singbox|uri
http://host:port/<token>?script=<脚本名>&format=singbox|uri
http://host:port/<token>                                ← 合并所有订阅（注意，由于没有对多余参数做处理，如果script写成scripts也会变成这个）
```

| 参数 | 说明 |
|---|---|
| `name` | 订阅名，对应 `config.json` 中 `subs` 的键名 |
| `script` | 脚本名，对应 `config.json` 中 `scripts` 的键名（优先级高于 `name`） |
| `format` | `singbox`（默认）或 `uri` |
| `ua` | 自定义 User-Agent |

**token 安全**：URL 路径首段作为 token 验证，使用 `hmac.compare_digest` 防时序攻击。

> **注意**：URL 参数名是 `?script=…`（单数 `script`，不是 `scripts`）。常见拼写错误。

---

## 配置文件 `config.json`

```json
{
  "token": "your-secret-token",
  "subs": {
    "自建": "node/selfbuilt.json",
    "客户": "hnode/client.json",
    "rtx.al": "https://another.example.com/sub",
    "ikuuu": "https://agjtx.no-mad-world.club/link/…"
  },
  "scripts": {
    "desktop": "script/desktop.py",
    "homeserver": "script/homeserver.py"
  }
}
```

| 字段 | 说明 |
|---|---|
| `token` | URL 路径验证密码 |
| `subs` | 订阅名 → 订阅链接或本地文件路径 |
| `scripts` | 脚本名 → 装配脚本路径（可选） |

### 本地文件作为订阅

`subs` 的值可以是本地文件路径（相对 `config.json` 所在目录），也可以是 HTTP 链接：

```json
"自建": "node/selfbuilt.json"
```

支持的文件格式不限——引擎自动检测是 sing-box JSON、Clash YAML 还是 URI 列表。`node/selfbuilt.json` 即 sing-box JSON 格式（顶层 `outbounds` 数组），无需额外配置。

---

## 输入格式支持

引擎 `detect_and_parse` 自动识别三种格式：

| 输入格式 | 识别方式 | 处理 |
|---|---|---|
| **sing-box JSON** | 以 `{` 开头，含 `outbounds` 字段 | 直接提取 `outbounds` |
| **Clash YAML** | `yaml.safe_load` 含 `proxies` 字段 | `clash2singbox` 转换 |
| **URI 列表** | 以上都不匹配 |按行识别 `ss://` / `vmess://` / `vless://` / `trojan://` |

### 支持的单节点协议

| 协议 | 输入 | 输出 |
|---|---|---|
| Shadowsocks | `ss://` URI / clash `type: ss` | `type: shadowsocks` |
| VMess | `vmess://` URI / clash `type: vmess` | `type: vmess` |
| VLESS | `vless://` URI / clash `type: vless` | `type: vless` |
| Trojan | `trojan://` URI / clash `type: trojan` | `type: trojan` |

URI 格式支持完整选项（TLS、Reality、WebSocket、gRPC、HTTP 传输等）。Clash 格式支持 ss/vmess/vless/trojan 的全字段转换。

---

## 装配脚本

装配脚本是 singsub 的核心特性——用 Python 脚本把订阅节点装进 sing-box 模板，生成完整配置。

### 脚本契约

每个脚本只需定义一个函数：

```python
def assemble(context):
    # context["subs"]      懒加载：subs["自建"] 自动抓取+解析，返回节点 list
    # context["args"]      查询参数 dict（不含 script/format/ua/name）
    # context["config_dir"] 配置文件所在目录
    return config_dict     # 最终 sing-box 配置
```

脚本写好后在 `config.json` 中注册：

```json
"scripts": {
    "homeserver": "script/homeserver.py"
}
```

通过 URL 调用：`http://host:8080/<token>?script=homeserver`

### 脚本特点

- **懒加载**：`subs["自建"]` 用到时才去抓取并转换，结果缓存。
- **热重载**：脚本文件修改后自动重新加载（基于 mtime 检测），无需重启服务。
- **模板自主权**：脚本自行决定用哪个模板文件、是否过滤节点、如何填充分组。
- **查询参数透传**：URL 上的额外参数通过 `context["args"]` 传递给脚本。

---

## 项目结构

```
singsub/
├── singsub.py             # 主入口：CLI + HTTP 服务
├── assembler.py           # 脚本引擎：懒加载订阅 + 动态加载脚本
├── fetch.py               # 订阅获取：URL 或本地文件
├── clash.py               # Clash YAML → sing-box 节点
├── uri2sb.py              # URI → sing-box 节点
├── sb2uri.py              # sing-box → URI
├── common.py              # JSON 序列化、查询字符串解析
│
├── config.example.json    # 配置示例
│
├── script/                # 装配脚本
│
├── template/              # sing-box 配置模板
│
├── node/                  # 本地订阅文件
│
└── yaml/                  # 内嵌 PyYAML（无外部依赖）
    ├── __init__.py
    └── ...
```

---

## 依赖

- **Python ≥ 3.10**（使用 `match` 语法）
- `requests`（HTTP 订阅获取）
- 无其他外部依赖（`yaml/` 目录是内嵌的 PyYAML）

```bash
pip install requests
```

---

## 文件说明

### 核心模块

| 文件 | 作用 |
|---|---|
| `singsub.py` | 入口文件。`detect_and_parse` 自动识别订阅格式；`Handler` 处理 HTTP 请求；`cmd_serve` 启动服务；`cmd_convert` 命令行转换 |
| `assembler.py` | `LazySubs` 类：懒加载订阅（用到才拉取、解析、缓存）。`run_script`：加载 Python 脚本文件，传入 context 并调用 `assemble`。`_load_script`：带 mtime 缓存的动态加载 |
| `fetch.py` | `getsub(url, ua, base_dir)`：自动判断 URL / 本地文件，HTTP 用 requests 获取，本地文件从磁盘读取 |
| `clash.py` | `clash2singbox`：YAML 解析 → 遍历 `proxies` → 按类型（ss/vmess/vless/trojan）转换 → 返回 sing-box 节点列表 |
| `uri2sb.py` | 按行解析 ss / vmess / vless / trojan URI。支持 SIP002 和旧式 ss 格式，支持 TLS、Reality、WebSocket 等传输层配置 |
| `sb2uri.py` | 反向转换：sing-box 节点 → URI。支持从 dict、list、或含 `outbounds` 的完整配置中提取节点 |
| `common.py` | `dict2json`：JSON 序列化（保留中文 tag）。`parse_query`：URL 查询字符串解析 |

### 配置和模板

| 文件 | 说明 |
|---|---|
| `config.json` | 运行配置：token 验证密码、订阅列表、脚本注册 |
| `template/*.json` | sing-box 配置骨架：inbounds、route 规则、dns 等。脚本把节点填进 `outbounds` 完成装配 |

---

## 常见问题

**Q: 订阅解析失败，报 base64 解码错误？**
A: 通常是 Clash 订阅内容没有以 `proxies:` 开头，或 URL 参数写错了（比如 `?scripts=` 多写了 `s`）。检查 URL 参数名是否为 `?script=…`。如果问题持续，确认订阅链接返回的格式。

**Q: 如何调试脚本？**
A：脚本抛出的异常会被捕获、堆栈打印到 stderr，并返回 500。先看服务进程的输出日志。也可以单独测试：

```bash
python3 -c "
import sys; sys.path.insert(0, '.')
from assembler import run_script
import json
# 手动模拟调用
config = run_script('script/homeserver.py', {'自建': 'node/selfbuilt.json', 'ikuuu': 'https://...'})
print(json.dumps(config, indent=2, ensure_ascii=False))
"
```

**Q: 修改脚本后需要重启吗？**
A: 不需要。脚本基于 mtime 缓存，修改文件后下次请求自动加载新版本。修改 `config.json` 的 `subs` 则需要重启。

**Q: 如何在脚本中使用更多订阅？**
A: 脚本中通过 `context["subs"]["订阅名"]` 访问。订阅名必须在 `config.json` 的 `subs` 中有定义（否则抛 `KeyError`）。用 `subs.get("订阅名", [])` 可以安全地取不存在的订阅（返回空列表）。

**Q: 服务端口被占用？**
```bash
fuser -k 8080/tcp    # 释放端口
```