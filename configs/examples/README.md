# 示例配置说明
#
# 完整字段、编译与生产部署见 docs/usage.md。
# Gitea 逐步操作见 docs/scenarios/gitea.md。
#
# 本目录文件：
#
#   edge.yaml / agent.yaml / allowlist.json
#     本机回环演示。listen 和 public 都绑 127.0.0.1。
#     配套源站：TCP 9000、HTTP 3000、UDP 9053。
#     自签证书生成在 configs/examples/certs/（已 gitignore）。
#
#   gitea/
#     把家里 Gitea 映射到 VPS 的模板（占位 token，不能直接上公网）。
#     推荐：faketunnel init -preset gitea -edge VPS_IP
#     local: 3000 表示 Agent 本机 127.0.0.1:3000。
#     跨机时改 Edge 的 local 为 "内网IP:端口"，Gitea 须听内网。
#
# 占位符：
#   dev-token-change-me / admin-dev-token-change-me — 必须更换
#   203.0.113.10 — 文档用的虚构 VPS IP（RFC 5737）
#
# allowlist.json 仅环回时，外网访问会被拒绝。用 faketunnel allowlist add 加访问者 IP。
# 连续 5 次无效请求会临时封禁 6 小时（denylist.json）；第二次封禁永久。
