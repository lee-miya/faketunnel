# 场景：把 Gitea 映射到公网（按 IP 加白名单访问）

目标：家里（或内网）跑着 **Gitea**，用 fakeTunnel 把它暴露到 VPS。你在 Edge 的 allowlist 里**添加访问者公网 IP** 之后，对方才能用浏览器和 `git` 使用这套 Gitea；未列出的 IP 进不来。

配套配置：可用 `faketunnel init -preset gitea` 生成，或参考模板 `configs/examples/gitea/`。

编译、完整字段说明与 systemd 见 [../usage.md](../usage.md)。

## 1. 拓扑

**常见：Agent 与 Gitea 同一台**

```
访问者浏览器 / git
    │  HTTP  :8080
    │  SSH   :2222   （可选）
    ▼
公网 VPS 上的 Edge
    │  TLS 隧道 :8443（仅 Agent 来连）
    │  Admin   :9090（仅 127.0.0.1，SSH 转发后改 allowlist）
    ▼
家宽 NAT 后的 Agent  ──►  同机 Gitea
                         HTTP 127.0.0.1:3000
                         SSH  127.0.0.1:2222
```

**也可以：Agent 与 Gitea 同一内网、不同机器**（见 [第 5.2 节](#52-agent-与-gitea-不在同一台同一内网)）

```
家宽 NAT 后的 Agent  ──►  内网另一台 Gitea
                         HTTP 192.168.x.x:3000
                         SSH  192.168.x.x:2222
```

- **Gitea 不要对公网监听。** 与 Agent 同机时绑 `127.0.0.1`；跨机时绑内网并只放行 Agent。
- 访问者永远连的是 **VPS 的 IP + Edge 端口**，不是你家路由器。
- 用 **IP** 访问时，HTTP 隧道必须 **省略 `host`**（模板已如此）。若写成 `host: git.example.com`，用 `http://VPS_IP:8080` 打开会得到 502 `no tunnel for host`。
- Edge 与 Gitea **必须是两台机器**（或至少两个网络命名空间）。模板里 Edge 公网 SSH 口与 Gitea SSH 都是 2222：在 VPS 上占 2222、在家里占 2222，互不冲突。若强行把 Edge 和 Gitea 跑在同一台，请把 Edge 的 `public` 改成别的端口（例如 2223），否则 Edge 会占住 2222，Agent 无法再连本机 Gitea SSH。

下文用占位符：

| 占位符 | 含义 |
|--------|------|
| `VPS_IP` | VPS 公网 IPv4，文档示例常用 `203.0.113.10` |
| `VISITOR_IP` | 访问者当前出口 IPv4 |
| `HOME_IP` | （可选）你家宽带出口，若要给隧道口加防火墙 |
| `GITEA_LAN_IP` | （仅跨机）Gitea 所在机器的内网 IPv4，例如 `192.168.1.50` |

## 2. 准备

1. VPS 已能 SSH；已按 [usage.md 第 3 节](../usage.md#3-构建与编译) 构建出 `bin/edge`、`bin/agent`、`bin/faketunnel`（开发机与 VPS 架构不同时用交叉编译）。
2. Gitea 已能打开：与 Agent 同机时 `http://127.0.0.1:3000`；跨机时从 Agent 那台能打开 `http://GITEA_LAN_IP:3000`。
3. 决定公网端口（默认：Web **8080**，SSH **2222**，隧道 **8443**）。若 80/443 已被占用，保持 8080 即可。
4. 用 init 生成 token 与配置（不要手抄占位符）：

```bash
./bin/faketunnel init -dir /opt/faketunnel/configs -edge VPS_IP -preset gitea
```

## 3. 配置 Gitea

编辑 Gitea 的 `app.ini`（路径因安装方式而异，常见于 `$GITEA_CUSTOM/conf/app.ini` 或 `/etc/gitea/app.ini`），使 **对外 URL 等于访问者将在浏览器里输入的地址**：

```ini
[server]
PROTOCOL = http
DOMAIN = VPS_IP
HTTP_ADDR = 127.0.0.1
HTTP_PORT = 3000
ROOT_URL = http://VPS_IP:8080/
SSH_DOMAIN = VPS_IP
SSH_PORT = 2222
START_SSH_SERVER = true
SSH_LISTEN_HOST = 127.0.0.1
SSH_LISTEN_PORT = 2222
```

Agent 与 Gitea **不在同一台**时，把 `HTTP_ADDR` / `SSH_LISTEN_HOST` 改成 `0.0.0.0`（或该机内网 IP），不要继续只绑 `127.0.0.1`。防火墙只放行 Agent 的内网 IP 访问 3000（以及 SSH 的 2222）。

说明：

- `ROOT_URL` 的端口是 Edge 的 **`public`（8080）**，不是 Gitea 自己的 3000。否则页面里的克隆地址、跳转、Cookie 会错。**不要**把 `ROOT_URL` / `DOMAIN` 写成内网 IP。
- 若你后面在 Edge 上做 HTTPS 终止（`tls: true`），把 `ROOT_URL` 改成 `https://...`，并保证 Edge 会发 `X-Forwarded-Proto: https`（HTTP/1 终止模式已自动加）。
- 只用 HTTP(S) 克隆、不用 `git@` SSH 时，可关掉 `START_SSH_SERVER`，并删掉 Edge 里 `public: 2222` 那条 TCP 隧道。
- 改完 `app.ini` 后重启 Gitea，在 **能连到 Gitea 的那台**（同机或 Agent 机器）验证：

```bash
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:3000/          # 同机
# curl -sS -o /dev/null -w '%{http_code}\n' http://GITEA_LAN_IP:3000/  # 跨机
ss -lnt | grep -E '3000|2222'
```

## 4. 配置 Edge（VPS）

```bash
mkdir -p /opt/faketunnel/{bin,configs}
# 若还没 init：
./bin/faketunnel init -dir /opt/faketunnel/configs -edge VPS_IP -preset gitea
cp bin/edge bin/faketunnel /opt/faketunnel/bin/
```

生成的 `edge.yaml` 类似：

```yaml
token_file: token
tunnels:
  - type: http
    public: 8080
    local: 3000          # 纯数字 = Agent 本机 127.0.0.1:3000
  - type: tcp
    public: 2222
    local: 2222
```

不必写 `name`：省略时内部自动为 `http-8080`、`tcp-2222`，**不会写回 YAML**。只有 Agent 也手写 tunnels 时才需要对上这个名字，见 [usage.md 第 5.3 节](../usage.md#53-隧道-name可省略)。

不要给 HTTP 隧道加 `host`，否则无法用 IP 访问。`listen`、TLS 自签证书、Admin 口、allowlist 文件都会用默认值。证书写在**配置文件旁**的 `certs/edge.crt`（首次启动自动生成），不必再改相对路径。

Agent 与 Gitea 不在同一台时，把上面的 `local` 改成 `"GITEA_LAN_IP:3000"` / `"GITEA_LAN_IP:2222"`（见 5.2），然后重启 Edge。

### 隧道证书是干什么的

**只给 Agent ↔ Edge 的隧道口（默认 8443）加密用，不是给浏览器访问 Gitea 的。**

访问者打开的是明文 `http://VPS_IP:8080/`，SSH 是裸 TCP `:2222`，都不会校验证书，也看不到 `edge.crt`。

| 文件 | 谁用 | 作用 |
|------|------|------|
| `certs/edge.crt` | Edge 出示；Agent 可把它当作 `tls.ca` | 隧道 TLS 公钥证书 |
| `certs/edge.key` | **仅 Edge**，权限保持 `0600` | 隧道 TLS 私钥 |

生产建议：把 `certs/edge.crt` 拷到 Agent，设 `tls.ca` 并 `insecure_skip_verify: false`。自签 SAN 含 `localhost` / `127.0.0.1` / `::1`，`server_name` 保持 `localhost`。

防火墙示例（nft/ufw 按你的系统改）：

```bash
# 隧道口（可选：只允许家宽出口）
sudo ufw allow 8443/tcp
# 业务口（真正限制靠 allowlist）
sudo ufw allow 8080/tcp
sudo ufw allow 2222/tcp
# 不要允许 9090/tcp 从外网进入
```

启动（先前台确认日志，再改 systemd）：

```bash
./bin/edge -config /opt/faketunnel/configs/edge.yaml
```

看到 `tunnel listen`、`http listen`、`tcp listen`、`admin listen` 即成功。若仍使用文档占位 token 会打 warn。

长期运行：

```bash
sudo cp deploy/systemd/faketunnel-edge.service /etc/systemd/system/
sudo systemctl enable --now faketunnel-edge
```

## 5. 配置 Agent

### 5.1 Agent 与 Gitea 同一台

把 init 生成的 `agent.yaml` 拷到家里（已含 token 和 `edge:` 地址）：

```bash
# 在跑 Agent 的机器上
cp agent.yaml /opt/faketunnel/configs/agent.yaml
```

内容就是：

```yaml
edge: "VPS_IP:8443"   # 隧道口，不是 8080
token: "<与 Edge 相同>"
```

不必再写 `tunnels`（Edge 会把 `local` 随每条流下发）。未配 `tls.ca` 时会跳过证书校验并打 warn；打通后建议：

```bash
scp /opt/faketunnel/configs/certs/edge.crt user@家宽机器:/opt/faketunnel/configs/certs/edge.crt
```

```yaml
edge: "VPS_IP:8443"
token: "<与 Edge 相同>"
tls:
  insecure_skip_verify: false
  server_name: localhost
  ca: "/opt/faketunnel/configs/certs/edge.crt"
```

自签证书的 SAN 不含 VPS 公网 IP，所以 `server_name` 仍写 `localhost`，**不要**改成 `VPS_IP`。`edge:` 地址照样填真实 `VPS_IP:8443`。

```bash
./bin/agent -config /opt/faketunnel/configs/agent.yaml
```

日志出现 `connected to edge`；VPS 上 Edge 出现 `agent connected`。然后：

```bash
sudo systemctl enable --now faketunnel-agent
```

### 5.2 Agent 与 Gitea 不在同一台（同一内网）

`local` 是 Agent 去拨的地址。推荐只改 **Edge** 的 `local`，Agent 仍然省略 `tunnels`，不必写 `name`。

```yaml
# VPS 上的 edge.yaml
tunnels:
  - type: http
    public: 8080
    local: "GITEA_LAN_IP:3000"
  - type: tcp
    public: 2222
    local: "GITEA_LAN_IP:2222"
```

把 `GITEA_LAN_IP` 换成 Gitea 那台的局域网 IP（RFC1918，默认允许）。改完 **重启 Edge**。

同时：

1. Gitea `HTTP_ADDR` / `SSH_LISTEN_HOST` 不能只绑 `127.0.0.1`（见第 3 节）。
2. 在 **Agent 那台** 确认：`curl -sS -o /dev/null -w '%{http_code}\n' http://GITEA_LAN_IP:3000/`。
3. Gitea 所在机防火墙只放行 Agent 访问 3000 / 2222。

也可以用 init 四节映射一次生成（`public` 仍听所有网卡）：

```bash
./bin/faketunnel init -dir /opt/faketunnel/configs -edge VPS_IP \
  -http 0.0.0.0:8080:GITEA_LAN_IP:3000 \
  -tcp 0.0.0.0:2222:GITEA_LAN_IP:2222
```

不要写成 `8080:GITEA_LAN_IP:3000`（三节会被解析错）。一般改 YAML 更直观。

只有当你要在 Agent 上覆盖目标、又不改 Edge 时，才需要 `name`。省略时 Edge 自动名是 `http-8080`、`tcp-2222`。Agent 列出 `tunnels` 会变成允许名单，**两条都要写**，漏写 SSH 那条会被拒绝：

```yaml
# agent.yaml — 仅在覆盖 local 时才需要
edge: "VPS_IP:8443"
token: "<与 Edge 相同>"
tunnels:
  - name: http-8080
    local: "GITEA_LAN_IP:3000"
  - name: tcp-2222
    local: "GITEA_LAN_IP:2222"
```

不想猜自动名字，就在 Edge 和 Agent 两边都显式写 `name: gitea-http` 这类字段。多数情况改 Edge 的 `local` 即可。

## 6. 添加访问 IP（核心操作）

初始 `allowlist.json` 只有环回，**外网谁都进不去**（这是故意的）。

### 6.1 查访问者出口 IP

在**访问者自己的电脑**上：

```bash
curl -sS https://ifconfig.me
# 或
curl -sS https://ipv4.icanhazip.com
```

得到 `VISITOR_IP`（例如 `198.51.100.20`）。家庭宽带若是 DHCP，IP 变了要重新加。

### 6.2 在 VPS 上写入 allowlist（立即生效）

SSH 到 VPS 后：

```bash
export FAKETUNNEL_ADMIN=http://127.0.0.1:9090
# init 生成了 admin.token 时，在该目录执行即可，不必 export token
cd /opt/faketunnel/configs
/opt/faketunnel/bin/faketunnel allowlist list
/opt/faketunnel/bin/faketunnel allowlist add -actor 'ops' VISITOR_IP/32
/opt/faketunnel/bin/faketunnel status
```

`status` 里应有 `"agent_connected": true`。`add` 会更新内存并写盘，**不用重启** Edge。

一次加多个、或加网段：

```bash
./bin/faketunnel allowlist add 198.51.100.20/32 203.0.113.0/24
```

删除某人：

```bash
./bin/faketunnel allowlist rm 198.51.100.20/32
```

全量覆盖（危险：漏写则已有 IP 全部失效）：

```bash
./bin/faketunnel allowlist set 127.0.0.1/32 ::1/128 198.51.100.20/32
```

从笔记本操作时，先转发 Admin 口：

```bash
ssh -N -L 9090:127.0.0.1:9090 user@VPS_IP
export FAKETUNNEL_ADMIN=http://127.0.0.1:9090
export FAKETUNNEL_TOKEN='<Admin token>'
./bin/faketunnel allowlist add VISITOR_IP/32
```

也可以把 Admin 对公网开放（HTTPS + 强 token），在访问者电脑上直接：

```bash
export FAKETUNNEL_ADMIN=https://VPS_IP:9090
export FAKETUNNEL_TOKEN='<Admin token>'
./bin/faketunnel allowlist add-self -insecure -actor 'me'
```

Edge 需设置 `admin.listen: ":9090"`（详见 [usage.md 6.3](../usage.md)）。自签证书必须加 `-insecure`。

未在 allowlist 中的 IP 连续探测 5 次会被封 6 小时（日志 `ip temp banned`）；同一 IP 第二次封禁则永久。解封：`faketunnel denylist rm IP`，或再次 `allowlist add` / `add-self`。

### 6.3 确认文件已保存

```bash
cat /opt/faketunnel/configs/allowlist.json
```

Edge 重启后仍以该文件为准。

## 7. 访问者怎么用

把下面的 `VPS_IP` 换成真实地址。访问者必须已在 allowlist 中。

### 7.1 浏览器

打开：

```text
http://VPS_IP:8080/
```

应出现 Gitea 登录/注册页。第一次请在 Gitea 里创建用户（或确认已有账号）。Edge 的 `/healthz` 由 Edge 直接返回 `ok`，**不是** Gitea 的健康接口（Gitea 一般为 `/api/healthz`）。

### 7.2 HTTP(S) Git

在 Gitea 网页复制 HTTP 地址，应类似：

```text
http://VPS_IP:8080/user/repo.git
```

```bash
git clone http://VPS_IP:8080/user/repo.git
```

推送时用 Gitea 用户名 + **应用令牌或密码**（视你的 Gitea 认证设置）。

### 7.3 SSH Git（若启用了 TCP 2222）

在访问者 `~/.ssh/config`：

```text
Host gitea-vps
    HostName VPS_IP
    Port 2222
    User git
    IdentityFile ~/.ssh/id_ed25519
```

把公钥加到 Gitea → 设置 → SSH 密钥。然后：

```bash
git clone git@gitea-vps:user/repo.git
```

或：

```bash
git clone ssh://git@VPS_IP:2222/user/repo.git
```

首次会提示主机指纹，这是 **Gitea 内置 SSH** 的密钥，不是系统 22 端口的 sshd。

## 8. 日常维护

| 事情 | 做法 |
|------|------|
| 新同事要访问 | 让对方提供出口 IP → `allowlist add IP/32`；或对方用 `allowlist add-self` |
| 某人离职 / IP 变更 | `allowlist rm 旧IP/32`，需要的话再 `add` 新 IP |
| 看谁被拒绝 | Edge 日志 `acl deny`；`status` 里 `acl_denies` 增加 |
| IP 被封 6 小时 / 永久 | 日志 `ip temp banned` / `ip permanently banned`；`denylist list`；`denylist rm` 或再 `allowlist add` |
| Agent 掉线 | systemd 会拉起进程；进程在则 Agent 会自动重连。`status.agent_connected` |
| 升级 fakeTunnel | 停服务、替换二进制、`systemctl start`。allowlist 文件保留 |
| 更换 token | 改两端 YAML，先重启 Edge 再重启 Agent |

不要对 Gitea 口设置短 `idle_timeout`：大仓库 `git push` 可能数十分钟无“应用层空闲”但连接仍在传数据；默认 TCP 无空闲超时是合适的。

## 9. 故障排查（本场景）

| 现象 | 处理 |
|------|------|
| 浏览器一直转圈 / 连接被重置 | IP 未加白名单。在访问者机器查出口 IP，与 `allowlist list` 对比。公司网络可能用 NAT 池，需加整个出口段 |
| 502 no agent | VPS 上看 Edge 日志是否 `agent connected`；家里 Agent 是否在跑；`edge:` 是否写成了 `:8080` |
| `local dial` 失败 / 连接被拒绝 | 源站没监听；或 Agent 在另一台而 Gitea 仍绑 `127.0.0.1`；或内网防火墙未放行 |
| `unknown tunnel` | Agent 手写了 `tunnels` 但 `name` 与 Edge 不一致，或漏列了 SSH 那条 |
| Agent `certificate` / x509 错误 | 设了 `insecure_skip_verify: false` 但 `tls.ca` 不是 Edge 的 `certs/edge.crt`；或 `server_name` 与证书 SAN 不符（自签默认 `localhost`） |
| 浏览器提示证书不安全 | 你在用 HTTPS 打开 **8080/443 业务口**，与 `configs/certs` 里的**隧道证书无关**。本场景默认是明文 8080，不应弹出证书警告 |
| 502 no tunnel for host | HTTP 隧道写了 `host`。删掉 `host` 后重启 Edge |
| 页面能开但 CSS/跳转指向 3000 或内网 IP | `ROOT_URL` / `DOMAIN` 仍是内网地址，改成 `http://VPS_IP:8080/` 并重启 Gitea |
| clone HTTP 401 | Gitea 账号权限或需要 token，不是隧道问题 |
| SSH `Connection refused` | Edge 未听 2222；或 Gitea `START_SSH_SERVER` 未开 |
| SSH `Connection reset` | allowlist 未包含该 IP（TCP 拒绝表现为 RST） |
| 能打开网页不能 git | 部分运营商对 8080 做干扰；或 git 走了代理。用 `GIT_CURL_VERBOSE=1 git ls-remote ...` 看 HTTP 状态码 |
| 家宽 IP 变了 Agent 连不上 | 隧道口若做了源 IP 防火墙，要更新 HOME_IP；allowlist 管的是**访问者**，不管 Agent |

本机自测（VPS 上 allowlist 已有 `127.0.0.1` 时）：

```bash
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/
curl -sS http://127.0.0.1:8080/healthz
```

外网自测必须从 **已加白** 的机器发起；从 VPS 自己 curl 公网 IP 时，源地址可能是 VPS IP，也需要把 `VPS_IP/32` 加进名单才会成功。

## 10. 可选：域名与 HTTPS

稳定后可以：

1. DNS A 记录 `git.example.com` → `VPS_IP`。
2. 继续省略 `host`（catch-all），浏览器即可用域名访问 8080。
3. 若要在 Edge 终止 TLS（**访问者浏览器**的 HTTPS，与配置目录 `certs/` 里那对**隧道证书**不是同一回事）：给 HTTP 隧道加 `tls: true` 和面向域名的 `cert`/`key`，`public` 改 `443`，Gitea `ROOT_URL` 改为 `https://git.example.com/`。
4. 若证书在 Gitea 上：用 `tls: true` + `passthrough: true`，并设置 `host: git.example.com`（此时请用域名访问，不要用裸 IP，除非再加一条无 `host` 的 catch-all）。

IP 加白名单的流程不变。
