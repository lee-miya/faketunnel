package itest

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"faketunnel/internal/acl"
	"faketunnel/internal/agent"
	"faketunnel/internal/config"
	"faketunnel/internal/edge"
	"faketunnel/internal/logutil"
	"faketunnel/internal/tlsutil"
)

func TestEndToEndTCP(t *testing.T) {
	if testing.Short() {
		t.Skip("skip e2e in short mode")
	}
	backend := startEcho(t)
	edgeCfg, agentCfg := testPair(t)

	list, err := acl.New([]string{"127.0.0.1/32", "::1/128"})
	if err != nil {
		t.Fatal(err)
	}
	log := logutil.New("error", "text")
	edgeCfg.Tunnels[0].Local = backend
	agentCfg.Tunnels[0].Local = backend

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, err := edge.New(edgeCfg, list, log)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer srv.Shutdown()

	agentCfg.Edge = srv.TunnelAddr()
	cli, err := agent.New(agentCfg, log)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = cli.Run(ctx) }()

	public := srv.PublicAddr("echo")
	if public == "" {
		t.Fatal("missing public addr")
	}
	echoRetry(t, public, 8*time.Second)
}

func TestAgentOmitsTunnelsUsesEdgeLocal(t *testing.T) {
	if testing.Short() {
		t.Skip("skip e2e in short mode")
	}
	backend := startEcho(t)
	edgeCfg, agentCfg := testPair(t)
	agentCfg.Tunnels = nil

	list, err := acl.New([]string{"127.0.0.1/32", "::1/128"})
	if err != nil {
		t.Fatal(err)
	}
	log := logutil.New("error", "text")
	edgeCfg.Tunnels[0].Local = backend

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, err := edge.New(edgeCfg, list, log)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer srv.Shutdown()

	agentCfg.Edge = srv.TunnelAddr()
	cli, err := agent.New(agentCfg, log)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = cli.Run(ctx) }()

	public := srv.PublicAddr("echo")
	if public == "" {
		t.Fatal("missing public addr")
	}
	echoRetry(t, public, 8*time.Second)
}

func TestACLDeny(t *testing.T) {
	if testing.Short() {
		t.Skip("skip e2e in short mode")
	}
	edgeCfg, _ := testPair(t)
	list, err := acl.New([]string{"203.0.113.10/32"})
	if err != nil {
		t.Fatal(err)
	}
	log := logutil.New("error", "text")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv, err := edge.New(edgeCfg, list, log)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer srv.Shutdown()

	conn, err := net.DialTimeout("tcp", srv.PublicAddr("echo"), 2*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, err = conn.Write([]byte("should-fail"))
	if err == nil {
		buf := make([]byte, 16)
		_, err = conn.Read(buf)
	}
	if err == nil {
		t.Fatal("expected denied connection to fail")
	}
}

func TestReconnectAfterEdgeRestart(t *testing.T) {
	if testing.Short() {
		t.Skip("skip e2e in short mode")
	}
	backend := startEcho(t)
	edgeCfg, agentCfg := testPair(t)
	list, err := acl.New([]string{"127.0.0.1/32", "::1/128"})
	if err != nil {
		t.Fatal(err)
	}
	log := logutil.New("error", "text")
	edgeCfg.Tunnels[0].Local = backend
	agentCfg.Tunnels[0].Local = backend

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, err := edge.New(edgeCfg, list, log)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	tunnelAddr := srv.TunnelAddr()
	public := srv.PublicAddr("echo")
	agentCfg.Edge = tunnelAddr

	cli, err := agent.New(agentCfg, log)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = cli.Run(ctx) }()
	echoRetry(t, public, 8*time.Second)

	if err := srv.Shutdown(); err != nil {
		t.Fatal(err)
	}

	edgeCfg.Listen = tunnelAddr
	edgeCfg.Tunnels[0].Public = public
	srv2, err := edge.New(edgeCfg, list, log)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv2.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer srv2.Shutdown()
	echoRetry(t, public, 12*time.Second)
}

func testPair(t *testing.T) (*config.File, *config.File) {
	t.Helper()
	dir := t.TempDir()
	certPEM, keyPEM, err := tlsutil.GenerateSelfSigned([]string{"localhost", "127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "edge.crt")
	keyPath := filepath.Join(dir, "edge.key")
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	edgeCfg := &config.File{
		Listen: "127.0.0.1:0",
		Token:  "test-token",
		TLS:    config.TLS{Cert: certPath, Key: keyPath},
		Tunnels: []config.Tunnel{{
			Name:   "echo",
			Type:   config.TypeTCP,
			Public: "127.0.0.1:0",
			Local:  "127.0.0.1:9",
		}},
	}
	agentCfg := &config.File{
		Token: "test-token",
		TLS:   config.TLS{CA: certPath, ServerName: "localhost"},
		Tunnels: []config.Tunnel{{
			Name:  "echo",
			Type:  config.TypeTCP,
			Local: "127.0.0.1:9",
		}},
	}
	return edgeCfg, agentCfg
}

func startEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().String()
}

func echoRetry(t *testing.T, addr string, wait time.Duration) {
	t.Helper()
	deadline := time.Now().Add(wait)
	var last error
	for time.Now().Before(deadline) {
		if err := tryEcho(addr); err == nil {
			return
		} else {
			last = err
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("echo %s: %v", addr, last)
}

func tryEcho(addr string) error {
	c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
	if err != nil {
		return err
	}
	defer c.Close()
	msg := []byte("hello-faketunnel")
	_ = c.SetDeadline(time.Now().Add(time.Second))
	if _, err := c.Write(msg); err != nil {
		return err
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil {
		return err
	}
	if string(got) != string(msg) {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func TestEdgeAgentShorthandConnect(t *testing.T) {
	if testing.Short() {
		t.Skip("skip e2e in short mode")
	}
	backend := startEcho(t)
	dir := t.TempDir()

	edgeYAML := filepath.Join(dir, "edge.yaml")
	agentYAML := filepath.Join(dir, "agent.yaml")

	// Start a dummy listener to find a free port for Edge tunnel
	freeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, portStr, err := net.SplitHostPort(freeLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = freeLn.Close()

	edgeContent := fmt.Sprintf(`
token: "secret-test-token"
listen: "127.0.0.1:%s"
tunnels:
  - name: echo
    public: "127.0.0.1:0"
    local: %q
`, portStr, backend)
	if err := os.WriteFile(edgeYAML, []byte(edgeContent), 0o600); err != nil {
		t.Fatal(err)
	}

	agentContent := fmt.Sprintf(`
token: "secret-test-token"
edge: "127.0.0.1:%s"
`, portStr)
	if err := os.WriteFile(agentYAML, []byte(agentContent), 0o600); err != nil {
		t.Fatal(err)
	}

	edgeCfg, err := config.LoadEdge(edgeYAML)
	if err != nil {
		t.Fatal(err)
	}
	list, err := acl.FromConfig(edgeCfg.AllowlistFile, []string{"127.0.0.1/32"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	log := logutil.New("error", "text")
	srv, err := edge.New(edgeCfg, list, log)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer srv.Shutdown()

	agentCfg, err := config.LoadAgent(agentYAML)
	if err != nil {
		t.Fatal(err)
	}
	cli, err := agent.New(agentCfg, log)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = cli.Run(ctx) }()

	public := srv.PublicAddr("echo")
	echoRetry(t, public, 8*time.Second)
}

func TestTunnelPortBanAfterInvalidTLS(t *testing.T) {
	if testing.Short() {
		t.Skip("skip e2e in short mode")
	}
	edgeCfg, _ := testPair(t)
	list, err := acl.New([]string{"127.0.0.1/32", "::1/128"})
	if err != nil {
		t.Fatal(err)
	}
	log := logutil.New("error", "text")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv, err := edge.New(edgeCfg, list, log)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer srv.Shutdown()

	addr := srv.TunnelAddr()
	if addr == "" {
		t.Fatal("missing tunnel addr")
	}
	for i := 0; i < 5; i++ {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
		_ = c.Close()
		time.Sleep(40 * time.Millisecond)
	}
	deadline := time.Now().Add(2 * time.Second)
	blocked := false
	for time.Now().Before(deadline) {
		if srv.Bans().Blocked(net.ParseIP("127.0.0.1")) || srv.Bans().Blocked(net.ParseIP("::1")) {
			blocked = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !blocked {
		t.Fatalf("want tunnel temp ban, bans=%v", srv.Bans().List())
	}
}
