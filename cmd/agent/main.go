package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"faketunnel/internal/agent"
	"faketunnel/internal/config"
	"faketunnel/internal/logutil"
)

var version = "dev"

func main() {
	configPath := flag.String("config", "", "path to agent YAML (default: agent.yaml in cwd, configs/, or /opt/faketunnel/configs)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "fakeTunnel Agent — 本机出站隧道客户端（NAT/防火墙友好）\n\n")
		fmt.Fprintf(os.Stderr, "用法: agent [-config path/to/agent.yaml]\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	path := strings.TrimSpace(*configPath)
	if path == "" {
		path = config.Find("agent")
	}
	if path == "" {
		flag.Usage()
		os.Exit(2)
	}

	cfg, err := config.LoadAgent(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}
	log := logutil.New(cfg.LogLevelOrDefault(), cfg.LogFormatOrDefault())
	cli, err := agent.New(cfg, log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agent: %v\n", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Info("agent starting", "version", version, "config", path)
	if err := cli.Run(ctx); err != nil && ctx.Err() == nil {
		fmt.Fprintf(os.Stderr, "agent: %v\n", err)
		os.Exit(1)
	}
}
