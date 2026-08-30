# myTunnel 架构（Phase 1–2）

## 角色

- **Edge**：跑在公网 VPS。监听 Agent 隧道口（TLS）以及各 TCP / HTTP(S) 公网端口。入站连接先做 IP allowlist，命中后经 yamux 交给 Agent。
- **Agent**：只出站连接 Edge（NAT/防火墙友好）。按 tunnel name 把流拨到本机 `local` 目标。
- **Allowlist**：Edge 本地 JSON 文件 + 内存原子替换。Phase 1 启动加载；远程热更新属于 Phase 4。

```
Internet client --TCP/HTTP(S)--> Edge --TLS+yamux--> Agent --TCP--> 127.0.0.1:...
                 ACL deny → RST/关闭（HTTP 可回 403）
```

## 安全模型

| 层 | 行为 |
|---|---|
| 隧道身份 | Agent 在 TLS 之后发送预共享 token；失败不进入 yamux |
| 访问控制 | 取 `RemoteAddr`（可选 PROXY protocol v1）；默认 deny |
| 传输 | 隧道 TLS 1.2+，ALPN `mytunnel/1`；公网 HTTPS 终止另用独立证书（无 mytunnel ALPN） |
| 最小暴露 | Agent 无入站端口；本地目标默认仅回环 / RFC1918 / ULA |

Token 使用 SHA-256 后恒定时间比较，日志不记录 token。

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

- Agent 打开第一条 stream 作为 control：`Ping` / `Pong`（15s / 45s 超时）
- 每条公网 TCP 连接 / HTTP 请求对应一条 yamux data stream：`OpenStream` → `OpenStreamAck` → 原始字节双向拷贝
  - `ProtoTCP` / `ProtoHTTP`（Agent 均 dial `local` 后 relay）

未实现（为后续阶段保留类型号）：`CloseStream`、`ConfigPush`、UDP assoc。

## HTTP/HTTPS（Phase 2）

- Edge 对 `type: http` 做反向代理；可选 `tls: true` 在 Edge 终止 TLS。
- 同一 `public` 可挂多个 HTTP 隧道，用 `host` 匹配 **HTTP Host**（明文）或 **TLS SNI**（HTTPS）；省略 `host` 为该端口的 catch-all。
- 证书：隧道级 `cert`/`key`，否则回退 Edge `tls`（含 `auto_self_signed`）。
- 可选 `health_path`（如 `/healthz`）：allowlist 通过后直接 `200 ok`，不经 Agent。
- UDP 仍跳过并打 warn。

## Allowlist 文件

`allowlist.json`：

```json
{
  "cidrs": ["127.0.0.1/32", "10.0.0.0/8"]
}
```

也接受 JSON 数组。裸 IP 视为 `/32` 或 `/128`。IPv4-mapped IPv6 会规范成 IPv4 再匹配。

文件存在时忽略 YAML 里的 `allowlist`。更新文件后 **需重启 Edge**（进程内 `Replace` 已就绪，供 Phase 4 API）。

## 运行时

- 结构化日志（`log/slog`），级别 `log_level`，格式 `text`/`json`
- SIGINT/SIGTERM：停止 accept、关闭 yamux、等待 drain（`shutdown_timeout`，默认 10s）
- Agent 断线：指数退避 + jitter（0.5s → 15s）自动重连
- 会话 panic 隔离在单连接 goroutine
- 并发会话数受 `max_sessions` 限制（默认 1024）

## 尚未实现

- UDP
- Admin API / CLI 热更新
- 多租户、IdP、Windows 服务
