# myTunnel

自托管隧道：在公网 VPS 上运行 **Edge**，本机运行 **Agent** 主动出站建连，把本地 TCP / HTTP 服务暴露到 VPS 端口。Edge 在转发前强制 **IP allowlist**（默认拒绝）。

当前实现为 **Phase 1–2**：TLS + token 隧道、yamux、TCP 与 HTTP/HTTPS（Host/SNI 路由）、文件版 allowlist。UDP 与远程热更新 ACL 见后续阶段。

## 构建

需要 Go 1.22+。

```bash
go test ./...
go build -o bin/edge ./cmd/edge
go build -o bin/agent ./cmd/agent
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

3. 启动 Edge，再启动 Agent：

```bash
./bin/edge -config configs/examples/edge.yaml
./bin/agent -config configs/examples/agent.yaml
```

首次启动会按配置生成自签证书（`configs/certs/`，已 gitignore）。

4. 访问公网侧（示例 allowlist 仅允许 `127.0.0.1` / `::1`）：

```bash
printf 'hello' | ncat 127.0.0.1 2222
curl -H 'Host: web.localhost' http://127.0.0.1:8080/
curl -k --resolve secure.localhost:8444:127.0.0.1 https://secure.localhost:8444/
curl http://127.0.0.1:8080/healthz
```

未在 allowlist 中的 IP 会被拒绝（TCP 尽量 RST；HTTP 回 403）。

## 配置要点

| 角色 | 关键字段 |
|------|----------|
| Edge | `listen`、`token`、`tls`、`allowlist_file` / `allowlist`、`tunnels`、`health_path` |
| Agent | `edge`、同一 `token`、`tunnels[].local`（按 name 匹配） |

**HTTP 隧道**（`type: http`）：

| 字段 | 说明 |
|------|------|
| `public` | 公网监听；同一地址可挂多个 `host` 路由 |
| `host` | 匹配 HTTP Host / TLS SNI；省略为该端口 catch-all |
| `tls` | `true` 时在 Edge 终止 HTTPS |
| `cert` / `key` | 可选；缺省回退 Edge `tls`（含自签） |
| `local` | Agent 侧本机目标（Agent 配置里也要同名隧道） |

- **Allowlist**：若 `allowlist_file` 存在则以文件为准；否则使用 YAML 中的 `allowlist`。空名单 = 拒绝全部。
- **TLS（隧道）**：生产请使用真实证书，Agent 配置 `tls.ca` 并关闭 `insecure_skip_verify`。
- **本地目标**：Agent 默认只允许回环 / RFC1918 / IPv6 ULA；需要放宽时设 `local_private_only: false`。
- 示例中的 `dev-token-change-me` 仅为占位符，部署前必须更换。

## 仓库结构

```
cmd/edge/          公网入口
cmd/agent/         本机出站客户端
internal/tunnel/   帧协议、握手、yamux
internal/acl/      IP/CIDR 与 JSON 文件
internal/proxy/    TCP/HTTP 辅助与本地目标校验
internal/edge/     Edge 服务（TCP + HTTP）
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
| 2 | HTTP/HTTPS 反向代理与 Host/SNI | 已完成 |
| 3 | UDP assoc / datagram | 未开始 |
| 4 | Admin API/CLI 热更新 allowlist、指标、文档补全 | 未开始 |
