# myTunnel 架构（Phase 1）

## 角色

- **Edge**：跑在公网 VPS。监听 Agent 隧道口（TLS）以及各 TCP 公网端口。入站连接先做 IP allowlist，命中后经 yamux 交给 Agent。
- **Agent**：只出站连接 Edge（NAT/防火墙友好）。按 tunnel name 把流拨到本机 `local` 目标。
- **Allowlist**：Edge 本地 JSON 文件 + 内存原子替换。Phase 1 启动加载；远程热更新属于 Phase 4。

```
Internet client --TCP--> Edge --TLS+yamux--> Agent --TCP--> 127.0.0.1:...
                 ACL deny → RST/关闭
```

## 安全模型

| 层 | 行为 |
|---|---|
| 隧道身份 | Agent 在 TLS 之后发送预共享 token；失败不进入 yamux |
| 访问控制 | 取 `RemoteAddr`（可选 PROXY protocol v1）；默认 deny |
| 传输 | TLS 1.2+，ALPN `mytunnel/1` |
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
- 每条公网 TCP 连接对应一条 yamux data stream：`OpenStream` → `OpenStreamAck` → 原始字节双向拷贝

未实现（为后续阶段保留类型号）：`CloseStream`、`ConfigPush`、UDP assoc。

## Allowlist 文件

`allowlist.json`：

```json
{
  "cidrs": ["127.0.0.1/32", "10.0.0.0/8"]
}
```

也接受 JSON 数组。裸 IP 视为 `/32` 或 `/128`。IPv4-mapped IPv6 会规范成 IPv4 再匹配。

文件存在时忽略 YAML 里的 `allowlist`。更新文件后 **Phase 1 需重启 Edge**；进程内 `Replace` 已按原子替换实现，供 Phase 4 API 使用。

## 运行时

- 结构化日志（`log/slog`），级别 `log_level`，格式 `text`/`json`
- SIGINT/SIGTERM：停止 accept、关闭 yamux、等待 drain（`shutdown_timeout`，默认 10s）
- Agent 断线：指数退避 + jitter（0.5s → 15s）自动重连
- 会话 panic 隔离在单连接 goroutine
- 并发 TCP 会话数受 `max_sessions` 限制（默认 1024）

## Phase 1 明确不做

- HTTP/HTTPS 终止与 Host/SNI 路由
- UDP
- Admin API / CLI 热更新
- 多租户、IdP、Windows 服务
