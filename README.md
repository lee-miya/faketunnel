# fakeTunnel

自托管隧道：在公网 VPS 上运行 **Edge**，本机运行 **Agent** 主动出站建连，把本地 TCP / HTTP / UDP 服务暴露到 VPS 端口。Edge 在转发前强制 **IP allowlist**（默认拒绝），并可通过 **Admin API / CLI** 热更新名单。

当前实现为 **Phase 1–4**：TLS + token 隧道、yamux、TCP、HTTP/HTTPS（Host/SNI，连接级透传，含 HTTP/2 端到端）、UDP assoc/datagram、文件 allowlist、Admin 热更新、指标与运维 CLI。

## 构建

需要 Go 1.22+。

```bash
go test ./...
go build -o bin/edge ./cmd/edge
go build -o bin/agent ./cmd/agent
go build -o bin/faketunnel ./cmd/faketunnel
```

## 快速试用（本机回环）

1. 本地 TCP echo（任选其一）：

```bash
ncat -e /bin/cat -k -l 127.0.0.1 9000
```

或：

```bash
python3 -c 'import socket,threading
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("127.0.0.1",9000)); s.listen()
while True:
    c,_=s.accept()
    threading.Thread(target=lambda c: (c.sendall(c.recv(65536)), c.close()), args=(c,), daemon=True).start()'
```

2. （可选）本地 HTTP：

```bash
python3 -m http.server 3000 --bind 127.0.0.1
```

3. （可选）本地 UDP echo：

```bash
python3 -c 'import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("127.0.0.1",9053))
while True:
    data,addr=s.recvfrom(65535); s.sendto(data,addr)'
```

4. 启动 Edge，再启动 Agent：

```bash
./bin/edge -config configs/examples/edge.yaml
./bin/agent -config configs/examples/agent.yaml
```

首次启动会按配置生成自签证书（`configs/certs/`，已 gitignore）。

5. 访问公网侧（示例 allowlist 仅允许 `127.0.0.1` / `::1`）：

```bash
printf 'hello' | ncat 127.0.0.1 2222
curl -H 'Host: web.localhost' http://127.0.0.1:8080/
curl -k --resolve secure.localhost:8444:127.0.0.1 https://secure.localhost:8444/
curl -k --http2 --resolve h2.localhost:8445:127.0.0.1 https://h2.localhost:8445/
curl http://127.0.0.1:8080/healthz
printf 'hello-udp' | ncat -u 127.0.0.1 5354
```

未在 allowlist 中的 IP 会被拒绝（TCP 尽量 RST；HTTP 回 403；UDP 丢弃）。

6. 热更新 allowlist（示例 Admin 口 `127.0.0.1:9090`）：

```bash
export FAKETUNNEL_TOKEN=admin-dev-token-change-me
./bin/faketunnel allowlist list -admin http://127.0.0.1:9090
./bin/faketunnel allowlist add -admin http://127.0.0.1:9090 203.0.113.10/32
./bin/faketunnel status -admin http://127.0.0.1:9090
```

## 配置要点

| 角色 | 关键字段 |
|------|----------|
| Edge | `listen`、`token`、`tls`、`allowlist_file` / `allowlist`、`admin`、`tunnels`、`health_path` |
| Agent | `edge`、同一 `token`、`tunnels[].local`（按 name 匹配） |

**Admin**（可选，`admin.listen` 非空时启用）：

| 字段 | 说明 |
|------|------|
| `listen` | 管理 HTTP 口（建议仅本机或经 SSH 转发） |
| `token` / `token_file` | Bearer 鉴权；与隧道 token 分离 |
| `metrics` | 是否提供 `/metrics`（默认 true；同样需要 Bearer） |

启用 Admin 时必须配置 `allowlist_file`（变更会原子写盘并立即生效）。

**HTTP 隧道**（`type: http`）：HTTP/1 按请求反向代理；HTTP/2 与 `passthrough` 为整连接透传（多路复用、gRPC、mTLS）。

| 字段 | 说明 |
|------|------|
| `public` | 公网监听；同一地址可挂多个 `host` 路由 |
| `host` | 匹配 HTTP Host / TLS SNI / HTTP/2 `:authority`；省略为该端口 catch-all |
| `tls` | `true` 时公网为 TLS |
| `passthrough` | 与 `tls` 联用：Edge **不终止** TLS，按 SNI 把字节拼到源站（HTTP/2 / gRPC / mTLS 端到端）。源站自己持证 |
| `http2` | Edge **终止** TLS 时提供 ALPN `h2`；解密后把 h2c 拼到源站（源站需支持 h2c） |
| `cert` / `key` | 可选（终止模式）；缺省回退 Edge `tls`（含自签） |
| `local` | Agent 侧本机目标（Agent 配置里也要同名隧道） |

**UDP 隧道**（`type: udp`）：

| 字段 | 说明 |
|------|------|
| `public` | 公网 UDP 监听（不可与另一 UDP 隧道重复） |
| `local` | Agent 侧本机 UDP 目标 |
| `idle_timeout` | 可选；关联空闲回收时间（未设时 UDP 默认 60s） |

- **Allowlist**：若 `allowlist_file` 存在则以文件为准；否则使用 YAML 中的 `allowlist`。空名单 = 拒绝全部。Admin/`faketunnel` 变更会写回文件。
- **TLS（隧道）**：生产请使用真实证书，Agent 配置 `tls.ca` 并关闭 `insecure_skip_verify`。
- **本地目标**：Agent 默认只允许回环 / RFC1918 / IPv6 ULA；需要放宽时设 `local_private_only: false`。
- 示例中的 `dev-token-change-me` / `admin-dev-token-change-me` 仅为占位符，部署前必须更换。

## Admin API

鉴权：`Authorization: Bearer <admin.token>`。可选 `X-Admin-Actor` 写入审计日志。

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/v1/allowlist` | 列出 CIDR |
| PUT | `/v1/allowlist` | 全量替换 `{"cidrs":[...]}` |
| POST | `/v1/allowlist` | 追加 `{"cidr":"..."}` 或 `{"cidrs":[...]}` |
| DELETE | `/v1/allowlist` | 删除（`?cidr=` 可重复，或 JSON body） |
| GET | `/v1/status` | Agent 在线、活跃会话、拒绝计数、隧道 RTT |
| GET | `/metrics` | Prometheus 文本（需 Bearer） |

## 仓库结构

```
cmd/edge/          公网入口
cmd/agent/         本机出站客户端
cmd/faketunnel/      Admin CLI（allowlist / status）
internal/tunnel/   帧协议、握手、yamux
internal/acl/      IP/CIDR、JSON 文件、热更新 Store
internal/admin/    管理 HTTP API
internal/metrics/  会话 / deny / RTT 指标
internal/proxy/    TCP/UDP/HTTP 辅助与本地目标校验
internal/edge/     Edge 服务（TCP + HTTP + UDP + Admin）
internal/agent/    Agent 重连客户端
internal/config/   YAML 配置
configs/examples/  虚构示例（无真实密钥）
docs/architecture.md
```

## 文档

- [架构与协议](docs/architecture.md)

## 阶段状态

| 阶段 | 内容 | 状态 |
|------|------|------|
| 1 | Go 骨架、TLS+token、yamux、TCP、文件 allowlist | 已完成 |
| 2 | HTTP/HTTPS 连接透传与 Host/SNI（含 HTTP/2 端到端） | 已完成 |
| 3 | UDP assoc / datagram | 已完成 |
| 4 | Admin API/CLI 热更新 allowlist、指标、文档 | 已完成 |
