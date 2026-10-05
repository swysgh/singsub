# singsub — 订阅转换器（Go 版）

支持 **Clash YAML / URI / sing-box JSON** 三种格式输入，输出 **sing-box 配置** 或 **URI 列表**。提供 HTTP 服务模式，脚本引擎改用 **JavaScript（goja）**，兼容 Sub-Store 风格脚本（`$content` / `produceArtifact` / `fs` / 顶层 `await`）。

---

## 与 Python 版的区别

| 项 | Python 版 | Go 版 |
|---|---|---|
| 脚本引擎 | Python（`assemble(context)`） | JavaScript（goja） |
| 脚本风格 | Python 脚本 | Sub-Store 风格 JS 脚本 |
| 依赖 | `requests` + 内嵌 PyYAML | 无（goja / yaml.v3 编译进二进制） |
| 部署 | 需 Python 环境 | 单二进制文件 |

Go 版**兼容两种脚本契约**：

1. **Sub-Store 风格**（主路径）：`$content` + `produceArtifact` + `fs.readFileSync` + 顶层 `await`
2. **singsub assemble 契约**：`function assemble(context)` 返回配置 dict（兼容原 Python 契约的 JS 等价物）

---

## 快速开始

```bash
# 1. 编译
go build -o singsub .

# 2. 复制配置
cp config.example.json config.json
# 编辑 config.json：填写 token、订阅链接、脚本路径

# 3. 启动 HTTP 服务
./singsub --config config.json --host 0.0.0.0 --port 8080
# 访问 http://localhost:8080/<token>?name=自建
# 访问 http://localhost:8080/<token>?script=homeserver
# 访问 http://localhost:8080/<token>?script=9abb&format=uri
```

---

## 用法

### HTTP 服务

```
./singsub [--config config.json] [--host 0.0.0.0] [--port 8080]
```

| 参数 | 说明 |
|---|---|
| `--config` | 配置文件路径，默认 `config.json` |
| `--host` | 监听地址，默认 `0.0.0.0` |
| `--port` | 监听端口，默认 `8080` |
| `--log-level` | 日志级别 `DEBUG`/`INFO`/`WARNING`/`ERROR`，默认 `INFO` |

#### URL 参数

```
http://host:port/<token>?name=<订阅名>&format=singbox|uri
http://host:port/<token>?script=<脚本名>&format=singbox|uri
http://host:port/<token>                                ← 合并所有订阅
http://host:port/<share_key>                            ← 分享链接（免 token）
```

| 参数 | 说明 |
|---|---|
| `name` | 订阅名，对应 `config.json` 中 `subs` 的键名 |
| `script` | 脚本名，优先级高于 `name` |
| `format` | `singbox`（默认）或 `uri` |
| `ua` | 自定义 User-Agent |

**token 安全**：路径首段作为 token 验证，使用 `crypto/subtle.ConstantTimeCompare` 防时序攻击。

**分享链接**：路径首段匹配 `shares` 中的键时，跳过 token 验证，直接执行对应脚本。

---

## 配置文件 `config.json`

```json
{
  "token": "your-secret-token",
  "subs": {
    "自建": "node/selfbuilt.json",
    "客户": "https://sub.example.com/api/v1/client/subscribe?token=xxx",
    "rtx.al": "https://another.example.com/sub"
  },
  "scripts": {
    "desktop": "script/desktop.js",
    "homeserver": "script/homeserver.js"
  },
  "shares": {
    "share_abc123": "homeserver",
    "share_def456": "desktop"
  }
}
```

| 字段 | 说明 |
|---|---|
| `token` | URL 路径验证密码 |
| `subs` | 订阅名 → 订阅链接或本地文件路径 |
| `scripts` | 脚本名 → JS 脚本路径（可选） |
| `shares` | 分享键 → 脚本名（可选） |
| `script_timeout_ms` | JS 脚本执行超时毫秒数，默认 `5000`（可选） |
| `fetch_timeout_ms` | 拉取远程订阅的超时毫秒数，默认 `15000`（可选） |
| `max_body_bytes` | 单个订阅响应体的字节上限，默认 `33554432`（32 MiB）（可选） |

后三项都可省略，省略时用默认值，因此旧的 `config.json` 无需修改即可继续使用。

### 订阅按需拉取

脚本里访问哪个订阅，才拉取哪个订阅。`context.subs["名字"]` 和 `context.subs.get("名字")`
都是惰性的：只在真正被读取时才发起抓取，且**同一次请求内只抓一次**。

访问不存在的订阅名会返回空对 `{outbounds: [], endpoints: []}` 而不是抛错，
所以脚本无需自己判空。

### 脚本超时

脚本在 `script_timeout_ms`（默认 5 秒）内没跑完会被强制中断，返回 HTTP 500。
这能防止脚本里的死循环把 CPU 占满。

### 本地文件作为订阅

`subs` 的值可以是本地文件路径（相对 `config.json` 所在目录）或 HTTP 链接。引擎自动检测格式（sing-box JSON / Clash YAML / URI 列表）。

---

## 输入格式支持

引擎 `detectAndParse` 自动识别三种格式：

| 输入格式 | 识别方式 | 处理 |
|---|---|---|
| **sing-box JSON** | 以 `{` 开头，含 `outbounds` 或 `endpoints` 字段 | 分别提取 `outbounds` 和 `endpoints` |
| **Clash YAML** | 含 `proxies` 字段 | `clash2singbox` 转换，全部归入 `outbounds` |
| **URI 列表** | 以上都不匹配 | 按行识别 `ss://` / `vmess://` / `vless://` / `trojan://` / `wireguard://` |

### 支持的协议

| 协议 | URI | Clash | 输出 |
|---|---|---|---|
| Shadowsocks | `ss://` | `type: ss` | `shadowsocks` |
| VMess | `vmess://` | `type: vmess` | `vmess` |
| VLESS | `vless://` | `type: vless` | `vless` |
| Trojan | `trojan://` | `type: trojan` | `trojan` |
| WireGuard | `wireguard://` | `type: wireguard` | `wireguard` |

---

## 脚本

### Sub-Store 风格脚本（推荐）

兼容 [Sub-Store](https://github.com/sub-store-org/Sub-Store) 脚本规范，可直接复用现有 Sub-Store JS 脚本：

```javascript
const fs = require("fs");

// 1. 读模板
$content = fs.readFileSync('/path/to/template.json', "utf8");
let config = JSON.parse($content);

// 2. 获取订阅节点（异步，返回 sing-box 节点数组）
async function getProxies(name) {
    return await produceArtifact({
        type: 'subscription',
        name: name,
        platform: 'sing-box',
        produceType: 'internal'
    });
}

let proxies = await getProxies('自建');

// 3. 装配：插入节点、填充分组
config.outbounds.push(...proxies);
config.outbounds.forEach(o => {
    if (o.tag === 'select') {
        o.outbounds.push(...proxies.map(p => p.tag));
    }
});

// 4. 写回 $content 作为输出
$content = JSON.stringify(config, null, 2);
```

#### 支持的 Sub-Store API

| API | 说明 |
|---|---|
| `$content` | 全局变量，脚本读模板后赋值，结束时作为最终输出 |
| `$arguments` | 查询参数对象（URL 上除 script/format/ua/name 外的参数） |
| `produceArtifact({type, name, platform, produceType})` | 异步获取订阅节点，返回 sing-box 节点数组 |
| `require("fs")` / `fs.readFileSync(path, enc)` | 读本地文件 |
| `fs.writeFileSync(path, content)` | 写本地文件 |
| `fs.existsSync(path)` | 判断文件是否存在 |
| `console.log/info/warn/error(...)` | 日志输出 |
| `ProxyUtils.yaml.safeLoad/safeDump` | YAML 解析/序列化（简化实现） |
| `ProxyUtils.produce(proxies, platform)` | 简化实现，返回 JSON 字符串 |
| `b64e(s)` / `b64d(s)` | Base64 编解码 |
| 顶层 `await` | 支持 `await produceArtifact(...)` |

#### 路径解析

- `fs.readFileSync` 的相对路径相对**脚本所在目录**解析
- `subs` / `scripts` 配置中的相对路径相对 **`config.json` 所在目录**解析

### assemble(context) 契约（兼容）

也支持定义 `assemble(context)` 函数的脚本（兼容原 Python 契约的 JS 形式）：

```javascript
function assemble(context) {
    const subs = context.subs;
    // subs["自建"] 返回 {outbounds, endpoints}，取 .outbounds 得节点
    const proxies = subs["自建"].outbounds;

    const config = { outbounds: [{ type: "selector", tag: "select", outbounds: [] }] };
    config.outbounds.push(...proxies);
    config.outbounds.forEach(o => {
        if (o.tag === "select") o.outbounds.push(...proxies.map(p => p.tag));
    });
    return config;
}
```

`context` 包含：
- `context.subs`：订阅对象，`subs["名"]` 返回 `{outbounds, endpoints}`，`subs.get("名")` 安全取（未知名称返回两个空数组），`subs.keys()` 列出全部订阅名
- `context.args`：查询参数 dict
- `context.config_dir`：配置文件所在目录

---

## 项目结构

```
singsub/
├── main.go           # 入口：CLI + HTTP 服务
├── config.go         # 配置加载与校验
├── assembler.go      # JS 脚本引擎（goja + Sub-Store 兼容 API）
├── detect.go         # 格式识别 + 渲染
├── fetch.go          # 订阅获取（HTTP / 本地文件）
├── clash.go          # Clash YAML → sing-box
├── uri2sb.go         # URI → sing-box
├── sb2uri.go         # sing-box → URI
├── common.go         # JSON 序列化、日志、查询解析
├── helpers.go        # json / yaml / base64 辅助
├── yaml.go           # yaml 包装
├── config.example.json
└── go.mod
```

---

## 编译

```bash
go build -o singsub .
```

无 CGO 依赖,可交叉编译。goja 和 yaml.v3 编译进二进制,部署只需单个可执行文件。

---

## Docker 部署

### 直接构建运行

```bash
# 构建镜像
docker build -t singsub:latest .

# 运行(配置、节点文件、脚本均通过卷挂载提供)
docker run -d --name singsub \
  -p 127.0.0.1:8080:8080 \
  -v "$PWD/config.json:/app/config.json:ro" \
  -v "$PWD/node:/app/node:ro" \
  -v "$PWD/script:/app/script:ro" \
  singsub:latest
```

### docker compose

仓库自带 `docker-compose.yml`:

```bash
docker compose up -d
docker compose logs -f
```

### 镜像说明

- **多阶段构建**:`golang:1.25-alpine` 编译 → `alpine:3.23` 运行,最终镜像只含一个静态二进制
- **纯静态二进制**(`CGO_ENABLED=0`),不依赖 glibc/musl
- **非 root 运行**(uid/gid 1000),`HEALTHCHECK` 探测 `GET /`
- **配置不打进镜像**:`config.json` 含 token 与订阅凭据,通过 `.dockerignore` 排除,
  运行时以只读卷挂载;`node/`、`script/` 同理

> ⚠️ 注意 `config.json` 里 `subs` / `scripts` 的路径。容器内挂载点是 `/app/node` 和
> `/app/script`,所以配置里要写成容器内路径,例如
> `"/app/node/selfbuilt.json"`、`"/app/script/desktop.js"`(而不是宿主机上的
> `/zfspool/share/nas/config/singsub/...`)。或者挂载到与宿主机一致的绝对路径上,
> 这样原配置不用改。

---

## 常见问题

**Q: 脚本路径 `/nas/config/...` 找不到？**
A: Sub-Store 脚本里硬编码的 `/nas/...` 路径需对应实际部署环境。可通过软链接或修改脚本路径适配。

**Q: 如何调试脚本？**
A: 以 DEBUG 日志级别启动服务，脚本里 `console.log(...)` 的输出会打到日志（`[script]` 前缀）：
```bash
./singsub --log-level DEBUG --config config.json
```
然后请求对应 URL（如 `http://localhost:8080/<token>?script=homeserver`）即可在服务进程输出中查看脚本日志。

**Q: 修改脚本后需要重启吗？**
A: 不需要。脚本基于 mtime 缓存，修改文件后下次请求自动加载新版本。

**Q: produceArtifact 支持哪些 platform？**
A: 目前 `platform` 参数被忽略，总是返回 sing-box 节点数组（因为引擎本身就是 sing-box 格式）。这是与原 Sub-Store 的差异——Sub-Store 会按 platform 转换，这里直接给 sing-box 节点。

**Q: WireGuard 节点如何处理？**
A: sing-box JSON 输入的 `endpoints` 单独提取并原样透传（仅含 `endpoints` 而无 `outbounds` 的配置也能识别）；Clash/URI 输入的 wireguard 归入 `outbounds`。`format=uri` 输出时两种形状都支持转 `wireguard://` URI：outbound 用 `server`/`server_port`/`local_address`，endpoint 用 `peers[0].address`/`peers[0].port` 和 `address`。URI 反向解析统一产出 `outbounds` 形状。
