package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"faketunnel/internal/config"
)

func runInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dir := fs.String("dir", ".", "output directory")
	edgeHost := fs.String("edge", "127.0.0.1", "Edge 公网主机名或 IP（写入 agent.yaml）")
	listen := fs.String("listen", config.DefaultListen, "Edge 隧道监听地址")
	preset := fs.String("preset", "", "隧道预设：gitea（HTTP 8080→3000 + TCP 2222）")
	force := fs.Bool("force", false, "overwrite existing files")
	var httpMaps, tcpMaps, udpMaps, allow strList
	fs.Var(&httpMaps, "http", "HTTP 映射 PUBLIC[:LOCAL]，可重复（例：8080:3000）")
	fs.Var(&tcpMaps, "tcp", "TCP 映射 PUBLIC[:LOCAL]，可重复（例：2222）")
	fs.Var(&udpMaps, "udp", "UDP 映射 PUBLIC[:LOCAL]，可重复")
	fs.Var(&allow, "allow", "allowlist CIDR，可重复（默认仅环回）")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `用法: faketunnel init [flags]

生成最小可用的 edge.yaml / agent.yaml、token、admin.token、allowlist.json。
Agent 配置不必再列 tunnels（Edge 会下发 local 目标）。

示例:
  faketunnel init -dir ./configs -edge 203.0.113.10 -http 8080:3000 -tcp 2222
  faketunnel init -dir ./configs -edge vps.example.com -preset gitea

`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	res, err := config.Init(config.InitOptions{
		Dir:      *dir,
		EdgeHost: *edgeHost,
		Listen:   *listen,
		HTTP:     httpMaps,
		TCP:      tcpMaps,
		UDP:      udpMaps,
		Allow:    allow,
		Preset:   *preset,
		Force:    *force,
	})
	if err != nil {
		return err
	}
	fmt.Printf("已生成 %s\n", res.Dir)
	fmt.Printf("  %s\n", res.EdgeYAML)
	fmt.Printf("  %s\n", res.AgentYAML)
	fmt.Printf("  %s  (隧道 token，权限 0600)\n", res.TokenFile)
	fmt.Printf("  %s  (Admin token，权限 0600)\n", res.AdminToken)
	fmt.Printf("  %s\n", res.Allowlist)
	fmt.Printf("\n下一步:\n")
	fmt.Printf("  VPS:   edge -config %s\n", res.EdgeYAML)
	fmt.Printf("  源站:  agent -config %s\n", res.AgentYAML)
	fmt.Printf("  加白:  faketunnel allowlist add <访问者IP>\n")
	return nil
}

type strList []string

func (s *strList) String() string { return strings.Join(*s, ",") }

func (s *strList) Set(v string) error {
	v = strings.TrimSpace(v)
	if v == "" {
		return fmt.Errorf("empty value")
	}
	*s = append(*s, v)
	return nil
}
