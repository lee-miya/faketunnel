# fakeTunnel

**fakeTunnel** 是一个自托管、安全、轻量的反向代理与内网穿透隧道系统（Cloudflare Tunnel 风格）。

只需在公网 VPS 上运行 **Edge**，并在内网或源站运行 **Agent**（仅需向外发起出站 TLS 连接），即可安全地将内网 Web、SSH、Git、DNS 等 TCP / HTTP / UDP 服务发布到公网。

---

## ✨ 核心特性

- **🔒 单向出站建连**：Agent 仅需出站发起 TLS 握手连接 Edge，内网无需公网 IP、动态域名或路由器端口映射。
- **🛡️ 严格安全防护**：
  - **IP Allowlist**：Edge 端口转发前强制执行 CIDR 白名单过滤（默认仅允许环回）。
  - **主动防爆破与封禁**：业务口非白名单、**隧道口 TLS/token 失败**、或 Admin 口令错误，同一 IP 连续 5 次自动触发 6 小时临时封禁，二次触发永久封禁。
  - **私网目标限制**：Agent 默认仅允许转发至内网与环回目标，防止内网横向越权。
- **🌐 全协议穿透支持**：
  - **TCP 端口转发**：支持 SSH、数据库、Git 等通用 TCP 协议。
  - **HTTP / HTTPS 路由**：支持 Host / SNI 多路复用路由、HTTP/1.1 请求反代、HTTP/2 整连接透传及自签/外部证书。
  - **UDP 穿透**：支持 DNS、游戏等 UDP 协议，内置会话关联与空闲超时管理。
- **⚡ 热更新与可观测性**：
  - 提供 **Admin API** 与 `faketunnel` CLI，支持无需重启服务的白名单热添加、删除与查询。
  - 内置 Prometheus 标准指标（`/metrics`）与隧道 RTT 延迟探测。
- **📦 零依赖与极简配置**：
  - 单一纯 Go 静态编译二进制，无 CGO 依赖。
  - 支持 `faketunnel init` 一键交互生成最小化生产配置。

---

## 🏗️ 架构概览

```
  [ 访问者 / 客户端 ]
          │ (TCP / HTTP / UDP)
          ▼
   ┌──────────────┐
   │  Edge 服务   │  (公网 VPS：业务口 + 可配的 TLS 隧道口 listen)
   │ (IP 白名单)  │
   └──────▲───────┘
          │ (单向出站 TLS 隧道 / Yamux 多路复用)
   ┌──────┴───────┐
   │  Agent 客户端 │  (运行于内网 / 容器 / 虚拟机)
   └──────┬───────┘
          │ (本地或局域网转发)
          ▼
   [ 内网源站服务 (Web / SSH / Gitea / DB...) ]
```

---

## 🚀 快速上手

### 1. 编译构建

项目内置标准 `Makefile`，需要 Go 1.22+ 环境：

```bash
# 编译所有程序至 bin/ 目录 (bin/edge, bin/agent, bin/faketunnel)
make build

# 运行测试套件
make test
```

> **交叉编译**：若开发机与 VPS 架构不同，可直接运行 `make cross-linux-amd64` 或 `make cross-all` 生成无依赖的静态二进制。

### 2. 生成配置

使用 `faketunnel init` 一键生成 Edge 与 Agent 的成套最小配置（自动生成高强度 Token 与证书）：

```bash
# 在当前目录下生成 configs/edge.yaml 和 configs/agent.yaml
# -listen 是 Agent 来连的隧道口（默认 :8443）。公网建议改成不常见端口，并与 agent.yaml 的 edge 端口一致。
./bin/faketunnel init -dir ./configs -edge <VPS_IP> -listen :27443 -http 8080:3000 -tcp 2222
```

### 3. 启动服务

```bash
# 1. 在 VPS 上启动 Edge
./bin/edge -config configs/edge.yaml

# 2. 在内网机器上启动 Agent
./bin/agent -config configs/agent.yaml
```

---

## 🛠️ 管理与常用命令

`faketunnel` CLI 用于通过 Admin API 动态管理 Edge 运行状态：

```bash
# 查看 Edge 运行状态与指标 (Agent 在线状态、会话数、RTT 等)
./bin/faketunnel status -admin http://127.0.0.1:9090

# 查看当前 IP 白名单
./bin/faketunnel allowlist list -admin http://127.0.0.1:9090

# 动态添加访问 IP 到白名单（支持 CIDR）
./bin/faketunnel allowlist add 203.0.113.10/32 -admin http://127.0.0.1:9090

# 将当前操作机器的外网 IP 一键加入白名单并解封
./bin/faketunnel allowlist add-self -admin https://vps.example.com:9090

# 查看与解封黑名单 IP
./bin/faketunnel denylist list -admin http://127.0.0.1:9090
./bin/faketunnel denylist rm 203.0.113.50 -admin http://127.0.0.1:9090
```

> 提示：若配置文件目录下存在 `admin.token`，CLI 会自动读取 Token，无需每次传递 `-token` 参数。

---

## 📖 详细文档

- 📘 **[完整使用文档 (docs/usage.md)](docs/usage.md)**：包含详细架构、全部 YAML 配置字段、编译指南、生产环境 Systemd 部署、性能调优与故障排查。
- 📙 **[场景实践：映射 Gitea 服务 (docs/scenarios/gitea.md)](docs/scenarios/gitea.md)**：包含 Web (HTTP) 与 Git (SSH) 双协议映射的端到端实战配置。
- 📗 **[示例配置说明 (configs/examples/README.md)](configs/examples/README.md)**：各项示例配置文件的用途与语法说明。
- 📐 **[技术架构与协议设计 (docs/architecture.md)](docs/architecture.md)**：Yamux 多路复用、帧结构与协议实现细节。

---

## 📄 License

MIT License
