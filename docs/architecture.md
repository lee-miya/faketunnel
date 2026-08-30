# fakeTunnel 架构

## 角色

- **Edge**：跑在公网 VPS。监听 Agent 隧道口（TLS）以及各 TCP / HTTP(S) / UDP 公网端口。入站连接先做 IP allowlist，命中后经 yamux 交给 Agent。
- **Agent**：只出站连接 Edge（NAT/防火墙友好）。默认按 Edge 在 OpenStream 里下发的 `local` 拨号（本机环回或内网 `IP:端口`）；配置里仍可列出 tunnels 作为允许名单或覆盖目标。
- **Allowlist**：Edge 本地 JSON 文件 + 内存原子替换；Admin API / CLI 写盘后立即生效，无需重启。文件缺失时默认写入环回。
- **Denylist**：同一 IP 连续 5 次无效（业务口 ACL deny 或 Admin 鉴权失败）临时封禁 6 小时；第二次封禁永久。持久化 `denylist.json`。
- **Admin**：默认在 `127.0.0.1:9090`；Bearer token 可自动生成到 `admin.token`。可热改 allowlist、解封、查看状态与 Prometheus 指标。非环回监听强制 HTTPS。

```
Internet client --TCP/HTTP(S)/UDP--> Edge --TLS+yamux--> Agent --TCP/UDP--> local
                 ACL deny / banned → RST/关闭/丢弃（HTTP 可回 403）

Admin CLI/API --Bearer--> Edge admin port → allowlist.json / denylist.json
```

## 安全模型

| 层 | 行为 |
|---|---|
| 隧道身份 | Agent 在 TLS 之后发送预共享 token；失败不进入 yamux |
| 访问控制 | 取 `RemoteAddr`（可选 PROXY protocol v1）；默认 deny；连续 5 次无效 → 6h 临时封禁，第二次永久 |
| 管理面 | Admin 独立 `listen` + Bearer；环回明文 HTTP，非环回强制 HTTPS（复用 Edge 证书）；错误口令计入封禁；审计日志记录 actor/动作/CIDR |
| 传输 | 隧道 TLS 1.2+，ALPN `faketunnel/1`；公网 HTTPS 终止用独立证书（无 faketunnel ALPN）；`passthrough` 时公网 TLS 直达源站；公网 Admin 为 HTTPS `http/1.1` |
| 最小暴露 | Agent 无入站端口；本地目标默认仅回环 / RFC1918 / ULA |

Token 使用 SHA-256 后恒定时间比较，日志不记录 token。Admin token 与隧道 token 分离。

## 隧道协议

TLS 握手完成后，先走自定义 **8 字节头 + payload** 帧（版本字段预留）：

| 偏移 | 字段 |
|------|------|
| 0 | version（当前为 1） |
| 1 | type |
| 2 | flags（保留 0） |
| 3 | reserved |
| 4–7 | payload length（uint32 BE，最大 64KiB） |

握手帧：

- `AuthRequest`：token、agent_id
- `AuthResponse`：ok、message

成功后该连接升级为 **yamux**：

- Agent 打开第一条 stream 作为 control；**Edge 发 `Ping`，Agent 回 `Pong`**（15s / 45s 超时），Edge 据此统计隧道 RTT
- 每条公网 TCP 连接 / HTTP/2 会话对应一条 yamux data stream：`OpenStream` → `OpenStreamAck` → 原始字节双向拷贝
  - `ProtoTCP` / `ProtoHTTP`（Agent 均 dial `local` 后 relay）
  - HTTP/1 仍按请求开 stream（Host 路由）；HTTP/2 / TLS passthrough 一条客户端连接一条 stream
- 每个 UDP 隧道对应一条专用 yamux stream（`ProtoUDP`）：其上复用 `OpenAssoc` / `OpenAssocAck` / `Datagram` / `CloseAssoc`（带 assoc id），避免每包开 stream

未实现（可后续扩展）：`CloseStream`。隧道列表由 Edge YAML 定义，经 OpenStream 的 `local` 字段交给 Agent，无需 ConfigPush。

## HTTP/HTTPS（连接透传）

- Edge 对 `type: http` 做 **协议分流**：ACL 之后按 Host / SNI / HTTP/2 `:authority` 选隧道。
  - **HTTP/1.1**：按请求反向代理（同一 TCP 上不同 Host 仍正确路由；keep-alive / WebSocket 走 `net/http`）。
  - **HTTP/2**（明文 h2c、或 `http2: true` 终止后的 h2）：整连接经 yamux 拼到 Agent，保留多路复用 / trailer / gRPC。
  - **`passthrough`**：不解密 TLS，按 SNI 把字节拼到源站（端到端 HTTP/2 / mTLS）。
- 同一 `public` 可挂多个 HTTP 隧道；省略 `host` 为该端口的 catch-all。
- 明文：探针首个 HTTP/1 请求或 HTTP/2 preface，路由后回放探针字节。
- `tls: true`（默认终止）：Edge 用隧道/Edge 证书握手。默认 ALPN 仅 `http/1.1`（兼容明文 HTTP/1 源站）。设 `http2: true` 则同时提供 `h2`，解密后把 **h2c** 拼到源站（源站需支持 h2c）。
- `tls: true` + `passthrough: true`：**不解密**。探针 ClientHello SNI 后原样转发 TLS。客户端与源站端到端协商 ALPN（HTTP/2 / HTTP/1.1）、证书与 mTLS。该隧道不需要 Edge 侧业务证书。同一 `public` 可混合终止与透传（按 SNI 分支）。
- 证书（终止模式）：隧道级 `cert`/`key`，否则回退 Edge `tls`（含 `auto_self_signed`）。
- 可选 `health_path`（如 `/healthz`）：allowlist 通过后，对 **HTTP/1.1** 首包路径直接 `200 ok`，不经 Agent。HTTP/2 与 TLS passthrough 上看不到明文路径，健康检查会到源站（或不可见）。

HTTP/2 能力（passthrough 或 terminate+h2c）：多路复用、HPACK、流式 body、trailer、gRPC、CONNECT。Edge 不改写 hop-by-hop 头。一条 HTTP/2 连接按握手时的 SNI / 首个 `:authority` 固定到一条隧道。

## UDP

- Edge 对 `type: udp` 做 `ListenPacket`；ACL 按源 IP 过滤，拒绝则丢弃。
- 首包到达且 Agent 在线时，Edge 打开该隧道的 UDP hub stream；按 `(clientIP, clientPort)` 建 **assoc**，分配 `uint32` id。
- 载荷经 `Datagram` 帧转发；单包上限约 64KiB−4（帧 payload 上限减去 assoc id）。
- **空闲超时**：默认 60s（若配置了 `idle_timeout` 则沿用）；超时双方 `CloseAssoc` 并回收。
- Agent 对每个 assoc `DialUDP` 到 `local`（connected socket），回程包按 id 写回 Edge，再 `WriteTo` 原客户端。

### NAT / 行为限制

- UDP 无连接状态：客户端必须保持源端口，否则 Edge 会视为新 assoc。
- 乱序与重复由应用层处理；隧道不做重排。
- 背压：hub stream 写失败时关闭对应 assoc；过大包直接丢弃并打日志。
- 与 TCP/HTTP 相同端口号可共存（协议不同）；同一 `public` 不可挂两个 UDP 隧道。

## Allowlist 与 Admin

`allowlist.json`：

```json
{
  "cidrs": ["127.0.0.1/32", "10.0.0.0/8"]
}
```

也接受 JSON 数组。裸 IP 视为 `/32` 或 `/128`。IPv4-mapped IPv6 会规范成 IPv4 再匹配。

文件存在时忽略 YAML 里的 `allowlist`。Admin / CLI 变更路径：

1. 校验 CIDR → 内存 `Replace` / `Add` / `Remove`
2. 临时文件 + `rename` 写盘
3. `slog` 审计：`action`、`actor`、`cidrs`、`entries`

启用 Admin 时（默认开启）必须能落到 Admin token 与 `allowlist_file`（均可由默认值补齐）。

API：`GET/PUT/POST/DELETE /v1/allowlist`，`POST /v1/allowlist/self`，`GET/DELETE /v1/denylist`，`GET /v1/status`，可选 `GET /metrics`。

CLI：`faketunnel init`、`faketunnel allowlist list|add|add-self|rm|set`、`faketunnel denylist list|rm`、`faketunnel status`（`-admin` / `-token` / `-insecure` 或环境变量 / `admin.token` 文件）。

## 指标

Prometheus 文本（Admin 口，需 Bearer）：

| 指标 | 类型 | 含义 |
|------|------|------|
| `faketunnel_agent_connected` | gauge | Agent 是否在线 |
| `faketunnel_active_sessions` | gauge | TCP/HTTP 会话 + 就绪 UDP assoc |
| `faketunnel_acl_denies_total` | counter | allowlist 拒绝或已封禁 IP 的次数 |
| `faketunnel_temp_bans` | gauge | 当前 6 小时临时封禁数 |
| `faketunnel_permanent_bans` | gauge | 永久封禁数 |
| `faketunnel_tunnel_rtt_seconds` | gauge | 最近一次 control Ping/Pong RTT |

## 运行时

- 结构化日志（`log/slog`），级别 `log_level`，格式 `text`/`json`
- SIGINT/SIGTERM：停止 accept、关闭 yamux、等待 drain（`shutdown_timeout`，默认 10s）
- Agent 断线：指数退避 + jitter（0.5s → 15s）自动重连；UDP hub 随会话关闭并在重连后按需重建
- 会话 panic 隔离在单连接 goroutine
- 并发会话数受 `max_sessions` 限制（默认 1024；UDP assoc 计入该上限）

## 尚未实现

- 多租户、IdP、Windows 服务
- 完整 Prometheus client 库 / 直方图分位（当前为轻量文本导出）
