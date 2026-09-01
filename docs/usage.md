# fakeTunnel 使用文档

本文是安装、编译、配置、运行和维护的完整说明。协议与内部结构见 [architecture.md](architecture.md)。把家里的 Gitea 映射到公网见 [scenarios/gitea.md](scenarios/gitea.md)。仓库里的可运行模板见 [`configs/examples/`](../configs/examples/)。

## 1. 它做什么

fakeTunnel 把家里或内网的 TCP / HTTP / UDP 服务，通过一台公网 VPS 暴露出去，并在 Edge 上用 **IP allowlist（默认拒绝）** 控制谁能连。

| 进程 | 跑在哪 | 职责 |
|------|--------|------|
| **Edge** | 公网 VPS | 听隧道口（TLS，`listen`，默认 `:8443`，**可改**）和各业务端口；先做 allowlist，再经 yamux 交给 Agent |
| **Agent** | 能访问源站的机器（常与源站同机，也可在同一内网的另一台） | **只出站**连 Edge（NAT/防火墙友好），拨到配置的 `local` |
| **faketunnel CLI** | 运维机 | 生成配置；调 Admin API 改 allowlist / denylist、看状态（热更新，不必重启 Edge） |

同时只支持 **一条** Agent 会话：新的 Agent 连上后，旧会话会被踢掉。多台源站请各跑独立的 Edge。

```
访问者 --TCP/HTTP(S)/UDP--> Edge(VPS) --TLS+yamux--> Agent --TCP/UDP--> local（本机或内网）
                 allowlist 未命中 → TCP RST / HTTP 403 / UDP 丢弃
                 业务口 / 隧道口 / Admin 连续 5 次无效 → 临时封禁 6 小时；同一 IP 第二次封禁 → 永久
```

`local` 默认是 Agent 本机环回（`127.0.0.1:端口`）。Agent 与源站不在同一台时，把 `local` 写成内网 `IP:端口` 即可，见 [5.7](#57-agent-与源站不在同一台同一内网)。

## 2. 要求

- 构建：Go **1.22+**。系统没有 Go 时，可把官方工具链解压到仓库 `.tools/go`（已 gitignore）。
- 运行：三个二进制都是静态可执行文件，**无额外运行时依赖**。
- Edge：公网可达的 TCP（隧道口 + 业务口）；若用 UDP 隧道再开放对应 UDP。
- Agent：能访问 Edge 的隧道口即可，**不必**对公网开放入站端口。
- 时钟大致准确（TLS 证书校验）。

示例里的 `dev-token-change-me` / `admin-dev-token-change-me` 以及 `203.0.113.10` 都是**占位符**，部署前必须换成自己的 token 与真实地址。推荐用 `faketunnel init` 一次生成，避免手抄。

## 3. 构建与编译

在仓库根目录操作。产物默认写到 `bin/`（已 gitignore）。项目已提供标准 `Makefile` 自动化构建、测试与跨平台编译。

### 3.1 安装 Go

确认版本：

```bash
go version   # 需要 go1.22 或更高
```

系统没有 Go，或版本过旧时，从 [https://go.dev/dl/](https://go.dev/dl/) 下载对应平台的归档（不要用过旧的发行版包）。以 Linux 为例：

```bash
# 把下载的 go1.22.x.linux-<arch>.tar.gz 放到仓库外或 /tmp
mkdir -p .tools
rm -rf .tools/go
tar -C .tools -xzf /tmp/go1.22.*.linux-*.tar.gz   # 解压后得到 .tools/go
export PATH="$PWD/.tools/go/bin:$PATH"
export GOROOT="$PWD/.tools/go"
go version
```

Makefile 会自动优先检测并使用 `.tools/go/bin/go`，若不存在则回退至系统 `go`。

### 3.2 使用 Makefile 编译（推荐）

```bash
# 编译所有程序（bin/edge, bin/agent, bin/faketunnel）
make build

# 运行测试
make test          # 运行完整测试套件
make test-unit     # 仅运行轻量单元测试
make test-itest    # 运行端到端集成测试

# 代码检查与清理
make vet           # 静态代码检查
make fmt           # 格式化代码
make clean         # 清理 bin/ 目录
```

安装到系统目录（默认 `/usr/local/bin`）：

```bash
sudo make install
```

### 3.3 直接使用 Go 命令行编译

若环境不支持 `make`，可直接使用 `go` 命令：

```bash
go test ./...
CGO_ENABLED=0 go build -ldflags "-s -w" -o bin/edge ./cmd/edge
CGO_ENABLED=0 go build -ldflags "-s -w" -o bin/agent ./cmd/agent
CGO_ENABLED=0 go build -ldflags "-s -w" -o bin/faketunnel ./cmd/faketunnel
```

查看版本（构建时可通过 ldflags 注入版本号）：

```bash
./bin/edge -version
./bin/agent -version
./bin/faketunnel version
```

### 3.4 交叉编译

开发机与 VPS 架构不同时，通过交叉编译可直接生成目标架构的静态二进制，**不必**在 VPS 上安装 Go。

使用 Makefile 一键生成主流平台二进制：

```bash
make cross-all             # 生成所有主流平台二进制至 bin/<平台>/
make cross-linux-amd64     # 常见 x86_64 VPS
make cross-linux-arm64     # ARM64 VPS / 树莓派
make cross-darwin-arm64    # Apple Silicon macOS
make cross-windows-amd64   # Windows x86_64 (.exe)
```

或使用原生 Go 命令交叉编译：

```bash
# 在 ARM 开发机上为 x86_64 Linux VPS 编译：
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o bin/edge ./cmd/edge
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o bin/agent ./cmd/agent
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o bin/faketunnel ./cmd/faketunnel
```

把 `bin/edge`、`bin/faketunnel` 拷贝到公网 VPS，把 `bin/agent` 拷贝到内网源站机器即可。

### 3.5 启动参数与配置发现

| 程序 | 用法 |
|------|------|
| Edge | `edge [-config path/to/edge.yaml] [-version]` |
| Agent | `agent [-config path/to/agent.yaml] [-version]` |
| CLI | `faketunnel <init\|allowlist\|denylist\|status\|version> [flags]` |

未写 `-config` 时，按下面顺序查找（`edge` / `agent` 各自找自己的文件名）：

1. 环境变量 `FAKETUNNEL_CONFIG`（若设置，**直接使用该路径**，不再按角色名搜索）
2. `./edge.yaml` 或 `./edge.yml`（Agent 为 `agent.yaml` / `agent.yml`）
3. `./configs/edge.yaml`（或 `.yml`）
4. `/opt/faketunnel/configs/<role>.yaml`
5. `/etc/faketunnel/<role>.yaml`

YAML 里的相对路径（证书、token 文件、allowlist）都相对**配置文件所在目录**解析，不是相对当前工作目录。

1. 环境变量 `FAKETUNNEL_CONFIG`（若设置，**直接使用该路径**，不再按角色名搜索）
2. `./edge.yaml` 或 `./edge.yml`（Agent 为 `agent.yaml` / `agent.yml`）
3. `./configs/edge.yaml`（或 `.yml`）
4. `/opt/faketunnel/configs/<role>.yaml`
5. `/etc/faketunnel/<role>.yaml`

YAML 里的相对路径（证书、token 文件、allowlist）都相对**配置文件所在目录**解析，不是相对当前工作目录。

## 4. 本机回环快速试用

以下全部绑在 `127.0.0.1`，用于确认程序能跑通。生产请用第 5 节的 `faketunnel init` 和第 8 节。

也可以直接生成一对最小配置：

```bash
./bin/faketunnel init -dir ./configs -edge 127.0.0.1 -http 8080:3000 -tcp 2222:9000
```

### 4.1 准备源站（任选需要测的）

TCP echo（`127.0.0.1:9000`）：

```bash
python3 -c 'import socket,threading
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("127.0.0.1",9000)); s.listen()
while True:
    c,_=s.accept()
    threading.Thread(target=lambda c: (c.sendall(c.recv(65536)), c.close()), args=(c,), daemon=True).start()'
```

HTTP（`127.0.0.1:3000`）：

```bash
python3 -m http.server 3000 --bind 127.0.0.1
```

UDP echo（`127.0.0.1:9053`）：

```bash
python3 -c 'import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("127.0.0.1",9053))
while True:
    data,addr=s.recvfrom(65535); s.sendto(data,addr)'
```

`configs/examples/edge.yaml` 里的 `web-h2`（HTTPS passthrough）需要源站自己持证并听 `127.0.0.1:3443`；快速试用可跳过该隧道。

### 4.2 启动 Edge，再启动 Agent

```bash
./bin/edge -config configs/examples/edge.yaml
./bin/agent -config configs/examples/agent.yaml
```

首次启动会在**配置文件旁**生成自签证书：本示例即 `configs/examples/certs/edge.crt` 与 `edge.key`（已 gitignore）。Agent 日志出现 `connected to edge` 即隧道就绪。

### 4.3 访问公网侧（示例 allowlist 仅 `127.0.0.1` / `::1`）

```bash
python3 -c 'import socket; s=socket.create_connection(("127.0.0.1",2222),2); s.sendall(b"hello"); print(s.recv(64))'
curl -H 'Host: web.localhost' http://127.0.0.1:8080/
curl -k --resolve secure.localhost:8444:127.0.0.1 https://secure.localhost:8444/
curl http://127.0.0.1:8080/healthz
python3 -c 'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2); s.sendto(b"hello-udp",("127.0.0.1",5354)); print(s.recvfrom(64))'
```

未在 allowlist 中的源 IP：TCP 尽量 RST；明文 HTTP 回 **403**；TLS 端口直接断开；UDP 丢弃。业务口 ACL、隧道口 TLS/token、Admin 口令连续 5 次无效会临时封禁 6 小时（日志 `ip temp banned`），详见 [6.1](#61-无效请求与-ip-封禁)。

### 4.4 热更新 allowlist

```bash
export FAKETUNNEL_TOKEN=admin-dev-token-change-me
./bin/faketunnel allowlist list -admin http://127.0.0.1:9090
./bin/faketunnel allowlist add -admin http://127.0.0.1:9090 203.0.113.10/32
./bin/faketunnel status -admin http://127.0.0.1:9090
```

变更立即生效并写回 `allowlist.json`，**不必重启** Edge。若当前目录有 `admin.token`（`init` 会生成），可以省略 `-token`。

## 5. 配置参考

手写时只需填**真正因环境而异**的字段，其余由程序补默认值。

### 5.0 用 init 生成（推荐）

```bash
./bin/faketunnel init -dir /opt/faketunnel/configs -edge VPS_IP -listen :27443 -http 8080:3000 -tcp 2222
./bin/faketunnel init -dir ./configs -edge VPS_IP -listen :27443 -preset gitea
```

写出 `edge.yaml`、`agent.yaml`（含 token，拷到 Agent 机器即可）、`token`、`admin.token`、`allowlist.json`。已有文件需加 `-force`。

| 参数 | 默认 | 说明 |
|------|------|------|
| `-dir` | `.` | 输出目录 |
| `-edge` | `127.0.0.1` | 写入 `agent.yaml` 的 Edge 主机（IP 或域名）。只写主机时自动拼上隧道端口 |
| `-listen` | `:8443` | Edge 隧道监听地址，写入 `edge.yaml` 的 `listen`。公网建议改成不常见端口；`agent.yaml` 的 `edge` 端口必须一致 |
| `-http` | 无 | HTTP 映射，可重复。格式见下 |
| `-tcp` | 无 | TCP 映射，可重复 |
| `-udp` | 无 | UDP 映射，可重复 |
| `-preset` | 无 | `gitea`：在未指定映射时使用 HTTP `8080:3000` + TCP `2222:2222` |
| `-allow` | 环回 | allowlist CIDR，可重复 |
| `-force` | false | 覆盖已有文件 |

至少要有一条 `-http` / `-tcp` / `-udp`，或使用 `-preset gitea`。

映射字符串 `PUBLIC[:LOCAL]`：

| 写法 | `public` | `local` |
|------|----------|---------|
| `8080` | `:8080` | `127.0.0.1:8080` |
| `8080:3000` | `:8080` | `127.0.0.1:3000` |
| `0.0.0.0:8080` | `0.0.0.0:8080` | `127.0.0.1:8080` |
| `127.0.0.1:8080:3000` | `127.0.0.1:8080` | `127.0.0.1:3000` |
| `0.0.0.0:8080:192.168.1.50:3000` | `0.0.0.0:8080` | `192.168.1.50:3000`（源站在内网另一台） |

三节写法 `8080:192.168.1.50:3000` **不会**把 local 解析成内网 IP。跨机请用四节写法，或生成后再改 YAML 的 `local`。

### 5.1 最小手写示例

```yaml
# edge.yaml
listen: ":27443"    # Agent 来连的隧道口；省略则为 :8443。公网请改成不常见端口
token: "..."
tunnels:
  - type: http
    public: 8080    # 纯数字 = 听所有网卡的该端口
    local: 3000     # 纯数字 = 127.0.0.1:该端口
```

```yaml
# agent.yaml — 不必列 tunnels
edge: "VPS_IP:27443"   # 端口必须与 Edge 的 listen 一致（默认 8443；公网请改）
token: "..."
```

### 5.2 地址简写

| 字段 | 纯数字 | 完整写法 |
|------|--------|----------|
| `listen` / `tunnels[].public` / `admin.listen` | `8080` → `:8080`（所有网卡） | `127.0.0.1:8080`、`[::]:8080` |
| `edge`（Agent） | `8443` → `127.0.0.1:8443` | `VPS_IP:27443`（须与 Edge `listen` 端口一致） |
| `tunnels[].local` | `3000` → `127.0.0.1:3000` | `192.168.1.50:3000`、`[::1]:3000` |

`0.0.0.0` 只听 IPv4；IPv6 用 `[::]:端口`（Linux 上常双栈）。Agent 的 `edge` 只写主机名或 IP、不写端口时，会拼上默认隧道口 **8443**；若 Edge `listen` 不是 8443，必须写成 `主机:端口`。

### 5.3 隧道 name（可省略）

YAML **不必**写 `name`。省略时启动阶段自动生成，**不会写回配置文件**，所以在 Edge 文件里找不到该字段是正常的。

规则：`类型-公网端口`；若写了 `host`，再拼上规范化后的 host。重名时加 `-2`、`-3`。

| 配置片段 | 内部 `name` |
|----------|-------------|
| `type: http` + `public: 8080` | `http-8080` |
| `public: 2222`（无 type、无 host → TCP） | `tcp-2222` |
| `type: http` + `public: 8080` + `host: web.localhost` | `http-8080-web-localhost` |
| `type: udp` + `public: 5354` | `udp-5354` |

Edge 日志里可以看到实际名字：`tcp listen tunnel=tcp-2222`、`http listen ... tunnels=[http-8080]`。

只有 Agent 也手写 `tunnels`（作允许名单或覆盖 `local`）时，才需要与 Edge 的 name 一致。不想猜自动名字，就在 **Edge 和 Agent 两边都显式写 `name`**。更常见的做法是 **只改 Edge 的 `local`，Agent 不写 tunnels**，这样完全不用管 name。

### 5.4 共用字段

| 字段 | 默认 | 说明 |
|------|------|------|
| `token` | 无 | 隧道预共享口令。日志不打印明文。与 Admin token **分开** |
| `token_file` | 配置旁若存在名为 `token` 的文件则自动使用 | 从文件读隧道 token（会 trim 空白） |
| `tunnels` | Edge **必填**；Agent **可省略** | Edge 定义公网口与 `local`。Agent 省略时使用 Edge 经 OpenStream 下发的 `local` |
| `tunnels[].name` | 自动生成，见 5.3 | 省略即可 |
| `tunnels[].type` | 见右 | `tcp` / `http` / `udp`。有 `host` / `tls` / `http2` / `passthrough` 时推断为 `http`，否则 `tcp`。UDP **必须**显式写出 |
| `tunnels[].public` | Edge 必填 | `host:port` 或纯端口 |
| `tunnels[].local` | Edge 必填 | Agent 拨号目标：`host:port` 或纯端口（→ `127.0.0.1:该端口`） |
| `idle_timeout` | TCP **无限制**；UDP **60s** | 进程级。如 `5m`。Git 大仓库推送**不要**给 HTTP/TCP 设过短空闲超时 |
| `dial_timeout` | `10s` | Agent 拨 `local`、Edge 等首包的超时 |
| `max_sessions` | `1024` | 并发 TCP/HTTP 会话 + 已就绪 UDP assoc |
| `shutdown_timeout` | `10s` | SIGINT/SIGTERM 后排空等待 |
| `log_level` | `info` | `debug` / `info` / `warn` / `error` |
| `log_format` | `text` | `text` 或 `json`（systemd/journald 建议 json） |
| `proxy_protocol` | `false` | 公网口期望 PROXY v1（前面还有一层反代时） |

Agent 若列出 `tunnels`：按 `name` 作为**允许名单**（未列出的隧道会被拒绝），并且非空的 `local` 会覆盖 Edge 下发的目标。只覆盖其中一条时，仍须把其它要放行的隧道也列出来。缺 `local` 则回退到 Edge 下发的目标。`public` / `host` / `tls` / `passthrough` / `http2` 只在 Edge 生效。

### 5.5 Edge 专用

| 字段 | 默认 | 说明 |
|------|------|------|
| `listen` | `:8443` | Agent 来连的 TLS 隧道口，不是业务口。**可改**（如 `:27443`）；公网不要用 8443 等常被扫描的端口。改了之后 Agent 的 `edge` 必须带同一端口 |
| `tls.auto_self_signed` | 未配 cert/key 时为 true | 证书文件不存在时生成自签 |
| `tls.cert` / `tls.key` | `<配置目录>/certs/edge.crt` `.key` | 隧道证书；也作为 HTTPS **终止**模式的回退证书 |
| `allowlist_file` | `<配置目录>/allowlist.json` | **存在则以文件为准**，忽略 YAML 里的 `allowlist` |
| `allowlist` | 文件不存在时写入环回 | 仅当文件不存在时使用 |
| `denylist_file` | `<配置目录>/denylist.json` | 自动封禁记录（临时 / 永久）。缺省文件在首次封禁时创建 |
| `health_path` | 关闭 | 如 `/healthz`：allowlist 通过后，对 **HTTP/1.1** 该路径由 Edge 直回 `ok`，不经 Agent。HTTP/2 与 TLS passthrough 上看不到明文路径 |
| `admin.enable` | `true` | `false` 关闭管理口 |
| `admin.listen` | `127.0.0.1:9090` | 环回则明文 HTTP。绑非环回（如 `:9090`）时 **强制 HTTPS**（复用 Edge 隧道证书），且禁止示例 / 过短 / 与隧道相同的 Admin token |
| `admin.token` / `admin.token_file` | 自动写 `admin.token` | Admin Bearer；公网时至少 16 字符，且必须与隧道 token 不同 |
| `admin.metrics` | `true` | `/metrics`（同样需要 Bearer） |

启用 Admin 时必须能落到 `allowlist_file` 和 Admin token（均可由默认值补齐）。

公网把 `listen` 改成不常见端口后，防火墙放行该端口，并把 Agent 的 `edge` 改成 `VPS_IP:同一端口`。只改一边会导致 Agent 连不上。

文件不存在且 YAML 也未写 `allowlist` 时，会创建仅含 `127.0.0.1/32` 与 `::1/128` 的文件（本机可测、外网仍拒绝）。要拒绝包括本机在内的全部连接，写 `{"cidrs":[]}`。

### 5.6 Agent 专用

| 字段 | 默认 | 说明 |
|------|------|------|
| `edge` | 必填 | `host:port`，指向 Edge 的 **`listen` 隧道口**，不是 8080 等业务口 |
| `tls.ca` | 空 | 校验 Edge 证书的 CA（生产应配置） |
| `tls.server_name` | 无 CA 时 `localhost`；有 CA 且未写时用 `edge` 的主机名 | SNI / 证书主机名。自签 SAN 默认是 `localhost`，不要改成 VPS IP |
| `tls.insecure_skip_verify` | 无 `tls.ca` 时为 true | 生产必须 `false` 并配置 `ca`。启动时会打 warn |
| `agent_id` | `agent` | 可选，出现在 Edge 日志 |
| `local_private_only` | `true` | `local` 只能是环回 / RFC1918 / IPv6 ULA。需要拨公网地址时才设 `false` |

### 5.7 Agent 与源站不在同一台（同一内网）

`local` 是 **Agent 去拨的地址**，不是 Edge 本机地址。

1. 在 **Edge** 的 `tunnels[].local` 写成源站内网 `IP:端口`（推荐，Agent 仍可省略 tunnels）：

```yaml
tunnels:
  - type: http
    public: 8080
    local: "192.168.1.50:3000"
  - public: 2222
    local: "192.168.1.50:2222"
```

2. 源站必须对该内网地址监听（不能只绑 `127.0.0.1`），并在防火墙上放行来自 Agent 的端口。不要把源站直接暴露到公网。
3. RFC1918（`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`）与 IPv6 ULA 默认允许。`local target rejected` 表示目标不是私网。
4. 改 `local` 后需 **重启 Edge**（不走 Admin 热更新）。已连接的 Agent 对新流使用新目标。

若坚持不改 Edge、只在 Agent 覆盖，必须写出与 Edge 一致的 `name`，并列出所有要放行的隧道：

```yaml
# agent.yaml
edge: "VPS_IP:27443"   # 须与 Edge listen 端口一致
token: "..."
tunnels:
  - name: http-8080          # 与 Edge 自动名一致，或两边都显式写 name
    local: "192.168.1.50:3000"
  - name: tcp-2222
    local: "192.168.1.50:2222"
```

### 5.8 TCP 隧道（`type: tcp`）

适合 SSH、数据库、任意 TCP。`public` 在 Edge 上不可与另一条 TCP/HTTP 隧道重复（可与 UDP 同端口号共存）。

### 5.9 HTTP 隧道（`type: http`）

| 字段 | 说明 |
|------|------|
| `public` | 公网听 HTTP(S)。同一地址可挂多条，用 `host` 区分 |
| `host` | 匹配 HTTP Host / TLS SNI / HTTP/2 `:authority`。**省略 = 该端口 catch-all**（用 IP 访问时必须省略或另配 catch-all） |
| `tls` | `true` 时公网为 TLS |
| `passthrough` | 与 `tls` 联用：Edge **不解密**，按 SNI 把字节拼到源站（HTTP/2 / gRPC / mTLS）。源站自己持证 |
| `http2` | Edge **终止** TLS 时提供 ALPN `h2`，解密后把 h2c 拼到源站（源站须支持 h2c）。必须同时 `tls: true` |
| `cert` / `key` | 终止模式的证书；缺省回退 Edge `tls`（含自签） |

行为摘要：

- **HTTP/1.1**：按请求反代（keep-alive、WebSocket 可用）。会补 `X-Forwarded-Proto` / `X-Forwarded-Host`，并保留原 `Host`。
- **HTTP/2 / passthrough**：整连接透传。
- 访问者 Host 对不上且没有 catch-all → HTTP **502** `no tunnel for host`。

用 **IP** 打开页面时，浏览器 Host 是 `IP:端口`，不会匹配 `host: git.example.com`。对外按 IP 提供服务时请**不要写 `host`**。

### 5.10 UDP 隧道（`type: udp`）

必须显式 `type: udp`。每条隧道一条 yamux hub，按 `(clientIP, clientPort)` 建 assoc。同一 `public` 不能挂两条 UDP。客户端必须保持源端口。空闲时间取进程级 `idle_timeout`，未设时 UDP 默认 60s 回收。

### 5.11 环境变量

| 变量 | 谁读 | 说明 |
|------|------|------|
| `FAKETUNNEL_CONFIG` | Edge / Agent / CLI 发现 token 时 | 配置文件路径 |
| `FAKETUNNEL_TUNNEL_TOKEN` | Edge / Agent | 隧道 token；仅当 YAML 未写 `token` / `token_file` |
| `FAKETUNNEL_ADMIN_TOKEN` | Edge | Admin token；仅当 YAML 未写 `admin.token` / `token_file` |
| `FAKETUNNEL_ADMIN` | CLI | Admin API 根地址，默认 `http://127.0.0.1:9090` |
| `FAKETUNNEL_TOKEN` | CLI | Admin Bearer。还会依次读 `./admin.token`、`configs/admin.token`、`/opt/faketunnel/configs/admin.token`、`/etc/faketunnel/admin.token` |

### 5.12 带注释的完整 YAML

生产不需要把所有字段都写出来；下面仅作对照。相对路径相对该 YAML 所在目录。

```yaml
# edge.yaml
listen: ":27443"              # Agent 来连的隧道口；公网不要长期用 8443
token_file: token
log_level: info
log_format: json
dial_timeout: 10s
max_sessions: 1024
shutdown_timeout: 10s
# idle_timeout: 5m          # 不要给 git 长传设过短值
health_path: /healthz
admin:
  enable: true
  listen: "127.0.0.1:9090"
  token_file: admin.token
  metrics: true
tls:
  auto_self_signed: true
  cert: certs/edge.crt
  key: certs/edge.key
tunnels:
  - type: http
    public: 8080
    local: 3000                 # 或 "192.168.1.50:3000"
  - type: tcp
    public: 2222
    local: 2222
```

```yaml
# agent.yaml
edge: "VPS_IP:27443"          # 端口与 Edge listen 一致
token_file: token
# agent_id: home
# local_private_only: true
tls:
  insecure_skip_verify: false
  server_name: localhost
  ca: certs/edge.crt
# tunnels:                     # 省略 = 接受 Edge 下发的全部 local
#   - name: http-8080
#     local: "192.168.1.50:3000"
```

## 6. Allowlist 与 Admin

`allowlist.json` 示例：

```json
{
  "cidrs": ["127.0.0.1/32", "10.0.0.0/8"]
}
```

也接受 JSON 数组。裸 IP 视为 `/32` 或 `/128`。IPv4-mapped IPv6 会规范成 IPv4 再匹配。

**文件存在时忽略 YAML `allowlist`。** 文件不存在且 YAML 也未写时，默认写入环回。用 CLI/API 改名单会原子 `rename` 写盘并立刻用于新连接。

### 6.1 无效请求与 IP 封禁

下列情况各记一次**无效**：

- **业务口**（TCP / HTTP / UDP）：源 IP 不在 allowlist
- **隧道口**（`listen`，Agent 来连的 TLS 口）：TLS 握手失败或 token 错误
- **Admin**：Bearer 错误

同一 IP **连续 5 次**无效：

1. **第一次**：临时封禁 **6 小时**（该 IP 的业务口与隧道口直接拒绝，日志 `ip temp banned`）
2. **解禁后再连续 5 次**：永久封禁（日志 `ip permanently banned`）

封禁优先于 allowlist：被封的 IP 即使后来被加进白名单，也要先 `denylist rm` 或用 `allowlist add` / `add-self`（会顺带解封该 IP）。临时封禁到期后计数清零，但「已封过一次」会记在 `denylist.json` 里，所以第二次仍会永封。

已封禁期间的重复连接不再加计（避免一次扫描直接永封）。允许名单命中会清掉「连续无效」计数，但不会取消已经发出的封禁。

### 6.2 CLI

```text
faketunnel init               [-dir DIR] [-edge HOST] [-listen :8443]
                              [-http 8080:3000] [-tcp 2222] [-udp ...]
                              [-preset gitea] [-allow CIDR] [-force]
faketunnel allowlist list|add|add-self|rm|set  <cidr>...
faketunnel denylist list|rm   <ip>...
faketunnel status
faketunnel version
```

| 参数 / 环境变量 | 说明 |
|-----------------|------|
| `-admin` / `FAKETUNNEL_ADMIN` | 默认 `http://127.0.0.1:9090`；公网 Admin 用 `https://VPS:9090` |
| `-token` / `FAKETUNNEL_TOKEN` | Admin Bearer |
| `-token-file` | 从文件读 token |
| `-actor` | 写入审计日志的 `X-Admin-Actor` |
| `-insecure` | 跳过 HTTPS 证书校验（自签 Admin 证书） |

`add` 是追加，`set` 是全量替换，`rm` 按规范化 CIDR 删除。`add-self` 把**当前客户端源 IP** 加入 allowlist 并解封该 IP。

本机管理：

```bash
export FAKETUNNEL_ADMIN=http://127.0.0.1:9090
./bin/faketunnel allowlist add 198.51.100.20/32
./bin/faketunnel denylist list
./bin/faketunnel denylist rm 198.51.100.20
```

### 6.3 把 Admin 放到公网（方便加 IP）

默认仍只绑 `127.0.0.1:9090`。若希望出差时直接加自己的出口 IP，可以把 Admin 对公网开放，但必须同时满足：

1. `admin.listen` 写成 `:9090` 或 `0.0.0.0:9090`（非环回）→ Edge **只提供 HTTPS**，证书与隧道口相同（自签时 CLI 加 `-insecure`）
2. Admin token 必须是 `faketunnel init` 生成的随机串（或 ≥16 字符的自备口令），**禁止**占位符 `admin-dev-token-change-me`，也禁止与隧道 token 相同
3. 错误 Bearer 计入同一套 5 次 / 6 小时 / 永封；有效 token 仍可调用 API（以便 `add-self` 解封自己）
4. 防火墙可只放行 9090/tcp；token 当作口令保管，不要写进仓库

```yaml
admin:
  listen: ":9090"
  token_file: admin.token
```

在访问者自己的电脑上：

```bash
export FAKETUNNEL_ADMIN=https://VPS_IP:9090
export FAKETUNNEL_TOKEN='<admin.token 内容>'
./bin/faketunnel allowlist add-self -insecure -actor 'me'
```

自签证书用 `-insecure`。若已把 `certs/edge.crt` 配进系统信任库，可去掉 `-insecure`。

仍可用 SSH 转发，不必对公网开放 Admin。

### 6.4 HTTP API

鉴权：`Authorization: Bearer <admin.token>`。可选 `X-Admin-Actor`。

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/v1/allowlist` | 列出 CIDR |
| PUT | `/v1/allowlist` | 全量替换 `{"cidrs":[...]}` |
| POST | `/v1/allowlist` | 追加 `{"cidr":"..."}` 或 `{"cidrs":[...]}` |
| POST | `/v1/allowlist/self` | 把客户端源 IP 加入 allowlist 并解封 |
| DELETE | `/v1/allowlist` | `?cidr=` 可重复，或 JSON body |
| GET | `/v1/denylist` | 列出临时 / 永久封禁 |
| DELETE | `/v1/denylist` | `?ip=` 或 `{"ips":[...]}` 解封 |
| GET | `/v1/status` | Agent 是否在线、活跃会话、拒绝次数、封禁计数、隧道 RTT |
| GET | `/metrics` | Prometheus 文本（需 Bearer） |

`GET /v1/status` 示例：

```json
{
  "agent_connected": true,
  "active_sessions": 2,
  "acl_denies": 5,
  "temp_bans": 1,
  "permanent_bans": 0,
  "has_rtt": true,
  "tunnel_rtt_ms": 12.3
}
```

指标：`faketunnel_agent_connected`、`faketunnel_active_sessions`、`faketunnel_acl_denies_total`、`faketunnel_temp_bans`、`faketunnel_permanent_bans`、`faketunnel_tunnel_rtt_seconds`。

## 7. 运行时行为（稳定性）

- **信号处理**：Edge / Agent 捕获 SIGINT、SIGTERM，停止 accept、关闭 yamux、等待 `shutdown_timeout`。
- **Agent 重连**：断线后指数退避 + jitter（约 0.5s → 15s）。一旦曾经握手成功，下次重连从短间隔重新计，避免“连上很久再断”仍要等 15s。
- **Edge 重启**：Agent 会自动再连；业务在会话重建前会失败（HTTP 502 `no agent`）。
- **会话隔离**：单连接 panic 不会拖垮进程。
- **yamux keepalive**：30s；控制面 Ping 15s / 超时 45s，用于 RTT。
- **示例 token**：若仍使用文档占位 token，启动时会打 **warn**，提醒上公网前更换。公网 Admin 遇到占位 token 会**拒绝启动**。
- **Admin 非环回**：自动 HTTPS，并打 **warn** 提醒保管 Bearer。

用 systemd 的 `Restart=always` 保证进程崩溃后拉起；隧道层自己负责 Agent 重连。二者一起才能持续服务。

## 8. 生产部署

### 8.1 Token 与证书

推荐：

```bash
./bin/faketunnel init -dir /opt/faketunnel/configs -edge VPS_IP -listen :27443 -http 8080:3000
```

会生成 32 字节 hex 的隧道 token 与 Admin token（文件权限 `0600`）。也可以手写：

```bash
openssl rand -hex 32   # 隧道 token
openssl rand -hex 32   # Admin token，必须不同
```

生产关闭跳过校验：把 Edge 配置目录下 `certs/edge.crt` 拷到 Agent，设 `tls.ca` 与 `insecure_skip_verify: false`。隧道 TLS 也可用 Let’s Encrypt 等正式证书，把 `auto_self_signed` 设为 false 并填写 `tls.cert` / `tls.key`。

**隧道证书只加密 Agent ↔ Edge 的 `listen` 口，不是给浏览器访问业务口的。** 访问者走的 HTTP/SSH 看不到 `edge.crt`。自签 SAN 含 `localhost` / `127.0.0.1` / `::1`，Agent 的 `server_name` 保持 `localhost`，`edge:` 填真实 `VPS_IP` 加与 `listen` 相同的端口。

### 8.2 监听与防火墙

典型 VPS：

| 端口 | 谁访问 | 建议 |
|------|--------|------|
| 隧道 `listen`（可改，勿长期用 8443） | 仅你的 Agent | 防火墙可限制源 IP；TLS/token 无效连续 5 次会临时封禁 6 小时 |
| 业务 `public`（如 8080、2222） | allowlist 中的访问者 | 对公网开放；未允许的 IP 连续 5 次无效会被封 6 小时 |
| Admin（如 9090） | 本机、SSH 转发，或按 6.3 用 HTTPS 对公网 | 非环回必须 HTTPS + 强 token；错误口令同样计入封禁 |
| 源站端口 | 仅 Agent 能连到的网卡 | 同机则绑 `127.0.0.1`；跨机则绑内网并只放行 Agent |

### 8.3 systemd（持续运行）

示例单元：`deploy/systemd/faketunnel-edge.service`、`faketunnel-agent.service`。

在 **VPS** 上：

```bash
sudo useradd --system --home /opt/faketunnel --shell /usr/sbin/nologin faketunnel
sudo mkdir -p /opt/faketunnel/{bin,configs}
sudo cp bin/edge bin/faketunnel /opt/faketunnel/bin/
sudo cp configs/edge.yaml configs/allowlist.json configs/token configs/admin.token /opt/faketunnel/configs/
sudo chown -R faketunnel:faketunnel /opt/faketunnel
sudo chmod 600 /opt/faketunnel/configs/*
sudo cp deploy/systemd/faketunnel-edge.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now faketunnel-edge
```

在 **Agent 机器** 上同样安装 `agent` 与 `faketunnel-agent.service`。

```bash
journalctl -u faketunnel-edge -f
journalctl -u faketunnel-agent -f
```

配置变更（隧道列表、`local`、证书路径、监听地址）需要 **重启对应进程**。allowlist 与 denylist 可通过 Admin 热更新。

### 8.4 健康检查

- Edge：`curl http://127.0.0.1:<http口>/healthz`（需源 IP 在 allowlist；且为 HTTP/1；且配置了 `health_path`）。
- 进程：`systemctl is-active faketunnel-edge`。
- 隧道：`faketunnel status` 中 `agent_connected` 应为 `true`。

## 9. 故障排查

| 现象 | 常见原因 |
|------|----------|
| Agent `dial: ... connection refused` | Edge 未启动；`edge:` 写成了业务口而不是隧道口；防火墙未放行 `listen` 端口；Edge `listen` 与 Agent `edge` 端口不一致 |
| Agent `auth rejected` / Edge `handshake failed` | 两端 `token` 不一致；复制时多了换行（用 `token_file`） |
| Agent `certificate` 错误 | 设了 `insecure_skip_verify: false` 但未配 `ca`，或 `server_name` 与证书 CN/SAN 不符（自签默认 `localhost`） |
| HTTP 403 | 访问者公网 IP 不在 allowlist，或已被临时 / 永久封禁（看 `acl deny` / `ip temp banned`） |
| HTTP 502 `no agent` | Agent 没连上或刚断线，等重连 |
| HTTP 502 `no tunnel for host` | 配置了 `host` 但用 IP 访问；去掉 `host` 或改用匹配的域名 |
| TCP 立刻断开 | allowlist 拒绝、IP 封禁，或 `max_sessions` 打满 |
| `local target rejected` | `local` 不是私网地址；确认 `local_private_only` |
| `local dial` 失败 | 源站没监听；只绑了 `127.0.0.1` 而 Agent 在另一台；端口或防火墙不对 |
| `unknown tunnel` | Agent 写了 `tunnels` 但 `name` 与 Edge 不一致，或漏列了某条隧道 |
| UDP 无回包 | 源 IP 被 deny 或已封禁；assoc 空闲超时；客户端源端口变了 |
| Admin `unauthorized` | Bearer 错；漏了 `Authorization` 头。连续 5 次后该 IP 会被封，再试可能是 `forbidden` |
| Admin 公网连不上 / 证书错误 | 非环回只提供 HTTPS；自签证书用 `-insecure`，URL 用 `https://` |
| 改 YAML allowlist 不生效 | 已有 `allowlist_file` 时以文件为准 |
| 加了 allowlist 仍进不去 | 该 IP 仍在 denylist：`denylist rm` 或再 `allowlist add` / `add-self`（会解封） |

把 `log_level` 临时改为 `debug` 可看到 RTT、relay 结束原因。查完改回 `info`。

确认访问者出口 IP：

```bash
curl -s https://ifconfig.me
```

然后：

```bash
./bin/faketunnel allowlist add -admin http://127.0.0.1:9090 该IP/32
```

## 10. 安全注意

- Allowlist 默认 deny；不要为图省事写成 `0.0.0.0/0`，除非你清楚源站已有自己的鉴权且接受全网扫描。
- 同一 IP 连续 5 次无效（业务口未命中 allowlist、隧道口 TLS/token 失败、或 Admin Bearer 错误）临时封禁 6 小时；第二次封禁永久。记录在 `denylist.json`。
- Admin 与隧道 token 必须分开。默认只绑环回；对公网开放时强制 HTTPS + 强 token，用 `add-self` 加当前 IP。
- Agent 不听入站端口。源站同机时只对 localhost 开放；跨机时只对内网、且仅放行 Agent。
- 自签证书仅用于隧道或实验；浏览器 HTTPS 终止请换正式证书，或改用 `passthrough` 让源站持证。公网 Admin 若用自签，CLI 需 `-insecure`。
- 当前无多租户 / IdP；能出示隧道 token 的 Agent 会接管整台 Edge。能出示 Admin token 的人可以改 allowlist 与解封。

## 11. 尚未提供

多租户、Windows 服务安装包、完整 Prometheus histogram。需要新隧道类型或新公网口时改 YAML 并重启 Edge/Agent。
