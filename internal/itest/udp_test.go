package itest

import (
	"context"
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

func TestEndToEndUDP(t *testing.T) {
	if testing.Short() {
		t.Skip("skip e2e in short mode")
	}
	backend := startUDPEcho(t)
	edgeCfg, agentCfg := testUDPPair(t)

	list, err := acl.New([]string{"127.0.0.1/32", "::1/128"})
	if err != nil {
		t.Fatal(err)
	}
	log := logutil.New("error", "text")
	edgeCfg.Tunnels[0].Local = backend
	agentCfg.Tunnels[0].Local = backend
	edgeCfg.IdleTimeout = config.Duration(5 * time.Second)

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

	public := srv.PublicAddr("dns-demo")
	if public == "" {
		t.Fatal("missing public udp addr")
	}
	udpEchoRetry(t, public, 8*time.Second)
}

func TestUDPACLDeny(t *testing.T) {
	if testing.Short() {
		t.Skip("skip e2e in short mode")
	}
	backend := startUDPEcho(t)
	edgeCfg, agentCfg := testUDPPair(t)
	edgeCfg.Tunnels[0].Local = backend
	agentCfg.Tunnels[0].Local = backend

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

	agentCfg.Edge = srv.TunnelAddr()
	cli, err := agent.New(agentCfg, log)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = cli.Run(ctx) }()

	// Wait until agent is likely connected, then ensure echo still fails (ACL).
	time.Sleep(500 * time.Millisecond)
	public := srv.PublicAddr("dns-demo")
	conn, err := net.Dial("udp", public)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := conn.Write([]byte("nope")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("expected acl-denied udp to get no reply")
	}
}

func testUDPPair(t *testing.T) (*config.File, *config.File) {
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
			Name:   "dns-demo",
			Type:   config.TypeUDP,
			Public: "127.0.0.1:0",
			Local:  "127.0.0.1:9",
		}},
	}
	agentCfg := &config.File{
		Token: "test-token",
		TLS:   config.TLS{CA: certPath, ServerName: "localhost"},
		Tunnels: []config.Tunnel{{
			Name:  "dns-demo",
			Type:  config.TypeUDP,
			Local: "127.0.0.1:9",
		}},
	}
	return edgeCfg, agentCfg
}

func startUDPEcho(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()
	return pc.LocalAddr().String()
}

func udpEchoRetry(t *testing.T, addr string, wait time.Duration) {
	t.Helper()
	deadline := time.Now().Add(wait)
	var last error
	for time.Now().Before(deadline) {
		if err := tryUDPEcho(addr); err == nil {
			return
		} else {
			last = err
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("udp echo %s: %v", addr, last)
}

func tryUDPEcho(addr string) error {
	conn, err := net.DialTimeout("udp", addr, 300*time.Millisecond)
	if err != nil {
		return err
	}
	defer conn.Close()
	msg := []byte("hello-udp-faketunnel")
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := conn.Write(msg); err != nil {
		return err
	}
	got := make([]byte, len(msg)+8)
	n, err := conn.Read(got)
	if err != nil {
		return err
	}
	if string(got[:n]) != string(msg) {
		return net.ErrClosed
	}
	return nil
}
