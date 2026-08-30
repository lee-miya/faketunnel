package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"mytunnel/internal/acl"
	"mytunnel/internal/config"
	"mytunnel/internal/edge"
	"mytunnel/internal/logutil"
)

var version = "dev"

func main() {
	configPath := flag.String("config", "", "path to edge YAML config")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "myTunnel Edge — 公网入口（TLS 隧道 + TCP/HTTP/UDP + IP allowlist + Admin）\n\n")
		fmt.Fprintf(os.Stderr, "用法: edge -config path/to/edge.yaml\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	if *configPath == "" {
		flag.Usage()
		os.Exit(2)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}
	if err := cfg.ValidateEdge(); err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}
	log := logutil.New(cfg.LogLevelOrDefault(), cfg.LogFormatOrDefault())
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
	log.Info("edge starting", "version", version)
	if err := srv.Run(ctx); err != nil && ctx.Err() == nil {
		fmt.Fprintf(os.Stderr, "edge: %v\n", err)
		os.Exit(1)
	}
}
