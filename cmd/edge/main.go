package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"faketunnel/internal/acl"
	"faketunnel/internal/config"
	"faketunnel/internal/edge"
	"faketunnel/internal/logutil"
)

var version = "dev"

func main() {
	configPath := flag.String("config", "", "path to edge YAML (default: edge.yaml in cwd, configs/, or /opt/faketunnel/configs)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "fakeTunnel Edge — 公网入口（TLS 隧道 + TCP/HTTP/UDP + IP allowlist/denylist + Admin）\n\n")
		fmt.Fprintf(os.Stderr, "用法: edge [-config path/to/edge.yaml]\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	path := strings.TrimSpace(*configPath)
	if path == "" {
		path = config.Find("edge")
	}
	if path == "" {
		flag.Usage()
		os.Exit(2)
	}

	cfg, err := config.LoadEdge(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}
	log := logutil.New(cfg.LogLevelOrDefault(), cfg.LogFormatOrDefault())
	if cfg.AdminEnabled() && cfg.Admin.TokenFile != "" {
		log.Info("admin token file", "path", cfg.Admin.TokenFile)
	}
	list, err := acl.FromConfig(cfg.AllowlistFile, cfg.Allowlist, log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "allowlist: %v\n", err)
		os.Exit(1)
	}
	srv, err := edge.New(cfg, list, log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "edge: %v\n", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Info("edge starting", "version", version, "config", path)
	if err := srv.Run(ctx); err != nil && ctx.Err() == nil {
		fmt.Fprintf(os.Stderr, "edge: %v\n", err)
		os.Exit(1)
	}
}
