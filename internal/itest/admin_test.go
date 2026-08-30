package itest

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"faketunnel/internal/acl"
	"faketunnel/internal/agent"
	"faketunnel/internal/config"
	"faketunnel/internal/edge"
	"faketunnel/internal/logutil"
)

func TestAdminAllowlistHotReload(t *testing.T) {
	if testing.Short() {
		t.Skip("skip e2e in short mode")
	}
	backend := startEcho(t)
	edgeCfg, agentCfg := testPair(t)
	dir := t.TempDir()
	allowPath := filepath.Join(dir, "allowlist.json")
	if err := acl.SaveFile(allowPath, []string{"203.0.113.10/32"}); err != nil {
		t.Fatal(err)
	}
	edgeCfg.AllowlistFile = allowPath
	edgeCfg.Admin = config.Admin{
		Listen: "127.0.0.1:0",
		Token:  "admin-test-token",
	}
	list, err := acl.LoadFile(allowPath)
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
	adminBase := "http://" + srv.AdminAddr()
	if adminBase == "http://" {
		t.Fatal("admin not listening")
	}

	// Loopback is denied until hot-add.
	if err := tryEcho(public); err == nil {
		t.Fatal("expected acl deny before allowlist update")
	}

	payload, _ := json.Marshal(map[string]any{"cidrs": []string{"127.0.0.1/32", "::1/128"}})
	req, err := http.NewRequest(http.MethodPut, adminBase+"/v1/allowlist", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer admin-test-token")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Actor", "itest")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("admin put status=%d body=%s", resp.StatusCode, body)
	}

	echoRetry(t, public, 8*time.Second)

	data, err := os.ReadFile(allowPath)
	if err != nil {
		t.Fatal(err)
	}
	cidrs, err := acl.ParseJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(cidrs) != 2 {
		t.Fatalf("persisted cidrs=%v", cidrs)
	}

	// Remove loopback → deny again without Edge restart.
	req, err = http.NewRequest(http.MethodDelete, adminBase+"/v1/allowlist?cidr=127.0.0.1/32&cidr=::1/128", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer admin-test-token")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("admin delete status=%d", resp.StatusCode)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if err := tryEcho(public); err != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("expected deny after allowlist remove")
}

func TestIPBanAfterFiveDenies(t *testing.T) {
	if testing.Short() {
		t.Skip("skip e2e in short mode")
	}
	edgeCfg, _ := testPair(t)
	dir := t.TempDir()
	allowPath := filepath.Join(dir, "allowlist.json")
	if err := acl.SaveFile(allowPath, []string{"203.0.113.10/32"}); err != nil {
		t.Fatal(err)
	}
	edgeCfg.AllowlistFile = allowPath
	edgeCfg.DenylistFile = filepath.Join(dir, "denylist.json")
	edgeCfg.Admin = config.Admin{Listen: "127.0.0.1:0", Token: "admin-test-token"}
	list, err := acl.LoadFile(allowPath)
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

	if srv.Store().Allow(net.ParseIP("127.0.0.1")) || srv.Store().Allow(net.ParseIP("::1")) {
		t.Fatalf("loopback should be denied, entries=%v", srv.Store().Entries())
	}
	public := srv.PublicAddr("echo")
	if public == "" {
		t.Fatal("missing public addr")
	}
	for i := 0; i < 8; i++ {
		c, err := net.DialTimeout("tcp", public, time.Second)
		if err != nil {
			continue
		}
		_ = c.SetDeadline(time.Now().Add(time.Second))
		_, _ = c.Write([]byte("x"))
		_ = c.Close()
	}

	adminBase := "http://" + srv.AdminAddr()
	deadline := time.Now().Add(3 * time.Second)
	var body []byte
	for time.Now().Before(deadline) {
		req, err := http.NewRequest(http.MethodGet, adminBase+"/v1/denylist", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer admin-test-token")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == 200 && bytes.Contains(body, []byte("temporary")) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !bytes.Contains(body, []byte("temporary")) {
		t.Fatalf("want temp ban in denylist (denies=%d entries=%v bans=%v): %s", srv.Metrics().Denies(), srv.Store().Entries(), srv.Bans().List(), body)
	}
	data, err := os.ReadFile(edgeCfg.DenylistFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte("127.0.0.1")) && !bytes.Contains(data, []byte("::1")) {
		t.Fatalf("denylist file missing loopback: %s", data)
	}
}

func TestMetricsAndStatus(t *testing.T) {
	if testing.Short() {
		t.Skip("skip e2e in short mode")
	}
	backend := startEcho(t)
	edgeCfg, agentCfg := testPair(t)
	dir := t.TempDir()
	allowPath := filepath.Join(dir, "allowlist.json")
	if err := acl.SaveFile(allowPath, []string{"127.0.0.1/32", "::1/128"}); err != nil {
		t.Fatal(err)
	}
	edgeCfg.AllowlistFile = allowPath
	edgeCfg.Admin = config.Admin{Listen: "127.0.0.1:0", Token: "admin-test-token"}
	list, err := acl.LoadFile(allowPath)
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
	echoRetry(t, srv.PublicAddr("echo"), 8*time.Second)

	// Force a deny for counter.
	denyList, _ := acl.New([]string{"203.0.113.9/32"})
	_ = denyList
	// Directly bump via public with empty temporarily — use Metrics after ACL deny on a fresh dial
	// after replacing allowlist to exclude loopback briefly is heavy; call IncDeny via ACL miss:
	srv.Store().Replace([]string{"203.0.113.9/32"}, "itest")
	c, err := net.DialTimeout("tcp", srv.PublicAddr("echo"), time.Second)
	if err == nil {
		_, _ = c.Write([]byte("x"))
		_ = c.Close()
	}
	_ = srv.Store().Replace([]string{"127.0.0.1/32", "::1/128"}, "itest")

	base := "http://" + srv.AdminAddr()
	req, _ := http.NewRequest(http.MethodGet, base+"/v1/status", nil)
	req.Header.Set("Authorization", "Bearer admin-test-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d %s", resp.StatusCode, body)
	}
	var st map[string]any
	if err := json.Unmarshal(body, &st); err != nil {
		t.Fatal(err)
	}
	if st["agent_connected"] != true {
		t.Fatalf("status=%v", st)
	}

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		req, _ = http.NewRequest(http.MethodGet, base+"/metrics", nil)
		req.Header.Set("Authorization", "Bearer admin-test-token")
		resp, err = http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		if bytes.Contains(body, []byte("faketunnel_tunnel_rtt_seconds")) &&
			bytes.Contains(body, []byte("faketunnel_agent_connected 1")) {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("metrics missing rtt/agent: %s", body)
}

func TestAllowlistRemoveDisconnectsExistingTCPConnection(t *testing.T) {
	if testing.Short() {
		t.Skip("skip e2e in short mode")
	}
	backend := startEcho(t)
	edgeCfg, agentCfg := testPair(t)
	dir := t.TempDir()
	allowPath := filepath.Join(dir, "allowlist.json")
	if err := acl.SaveFile(allowPath, []string{"127.0.0.1/32", "::1/128"}); err != nil {
		t.Fatal(err)
	}
	edgeCfg.AllowlistFile = allowPath
	edgeCfg.Admin = config.Admin{
		Listen: "127.0.0.1:0",
		Token:  "admin-test-token",
	}
	list, err := acl.LoadFile(allowPath)
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
	adminBase := "http://" + srv.AdminAddr()
	echoRetry(t, public, 8*time.Second)

	// Open a long-lived TCP connection to public echo.
	conn, err := net.DialTimeout("tcp", public, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("ping\n")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil || string(buf[:n]) != "ping\n" {
		t.Fatalf("echo failed: %v, got %q", err, string(buf[:n]))
	}

	if srv.Metrics().ActiveSessions() == 0 {
		t.Fatal("want active sessions > 0")
	}

	// Remove loopback from allowlist.
	req, err := http.NewRequest(http.MethodDelete, adminBase+"/v1/allowlist?cidr=127.0.0.1/32&cidr=::1/128", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer admin-test-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("admin delete status=%d", resp.StatusCode)
	}

	// The existing connection must be disconnected promptly.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = conn.Read(buf)
	if err == nil {
		_, err = conn.Write([]byte("after-rm\n"))
		if err == nil {
			_, err = conn.Read(buf)
		}
	}
	if err == nil {
		t.Fatal("expected connection to be closed after allowlist rm")
	}

	// Active session count in metrics should drop to 0.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if srv.Metrics().ActiveSessions() == 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if srv.Metrics().ActiveSessions() != 0 {
		t.Fatalf("want 0 active sessions after rm, got %d", srv.Metrics().ActiveSessions())
	}
}

func TestAllowlistRemoveDisconnectsExistingHTTPConnection(t *testing.T) {
	if testing.Short() {
		t.Skip("skip e2e in short mode")
	}
	backend := startHTTPBackend(t, "test-backend")
	edgeCfg, agentCfg := testPair(t)
	dir := t.TempDir()
	allowPath := filepath.Join(dir, "allowlist.json")
	if err := acl.SaveFile(allowPath, []string{"127.0.0.1/32", "::1/128"}); err != nil {
		t.Fatal(err)
	}
	edgeCfg.AllowlistFile = allowPath
	edgeCfg.Admin = config.Admin{
		Listen: "127.0.0.1:0",
		Token:  "admin-test-token",
	}
	edgeCfg.Tunnels = []config.Tunnel{
		{
			Name:   "web",
			Type:   config.TypeHTTP,
			Public: "127.0.0.1:0",
			Host:   "web.example",
			Local:  backend,
		},
	}
	agentCfg.Tunnels = []config.Tunnel{
		{
			Name:  "web",
			Type:  config.TypeHTTP,
			Local: backend,
		},
	}
	list, err := acl.LoadFile(allowPath)
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

	public := srv.PublicAddr("web")
	adminBase := "http://" + srv.AdminAddr()

	waitHTTP(t, "http://"+public+"/ping", "web.example", http.StatusOK, "test-backend", 8*time.Second)

	// Establish raw keep-alive HTTP connection.
	conn, err := net.DialTimeout("tcp", public, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	reqStr := "GET /ping HTTP/1.1\r\nHost: web.example\r\n\r\n"
	if _, err := conn.Write([]byte(reqStr)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1024)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := conn.Read(buf)
	if err != nil || !bytes.Contains(buf[:n], []byte("200 OK")) {
		t.Fatalf("first HTTP request failed: err=%v resp=%s", err, string(buf[:n]))
	}

	// Remove loopback from allowlist.
	req, err := http.NewRequest(http.MethodDelete, adminBase+"/v1/allowlist?cidr=127.0.0.1/32&cidr=::1/128", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer admin-test-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("admin delete status=%d", resp.StatusCode)
	}

	// Attempting to use the connection must fail (closed/reset).
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = conn.Read(buf)
	if err == nil {
		_, _ = conn.Write([]byte(reqStr))
		_, err = conn.Read(buf)
	}
	if err == nil {
		t.Fatal("expected HTTP connection to be closed after allowlist rm")
	}
}

func TestAllowlistRemoveEvictsUDPAssoc(t *testing.T) {
	if testing.Short() {
		t.Skip("skip e2e in short mode")
	}
	backend := startUDPEcho(t)
	edgeCfg, agentCfg := testUDPPair(t)
	dir := t.TempDir()
	allowPath := filepath.Join(dir, "allowlist.json")
	if err := acl.SaveFile(allowPath, []string{"127.0.0.1/32", "::1/128"}); err != nil {
		t.Fatal(err)
	}
	edgeCfg.AllowlistFile = allowPath
	edgeCfg.Admin = config.Admin{
		Listen: "127.0.0.1:0",
		Token:  "admin-test-token",
	}
	list, err := acl.LoadFile(allowPath)
	if err != nil {
		t.Fatal(err)
	}
	log := logutil.New("error", "text")
	edgeCfg.Tunnels[0].Local = backend
	agentCfg.Tunnels[0].Local = backend
	edgeCfg.IdleTimeout = config.Duration(30 * time.Second)

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
	adminBase := "http://" + srv.AdminAddr()
	udpEchoRetry(t, public, 8*time.Second)

	if srv.Metrics().ActiveSessions() == 0 {
		t.Fatal("want active UDP session count > 0")
	}

	// Remove loopback from allowlist.
	req, err := http.NewRequest(http.MethodDelete, adminBase+"/v1/allowlist?cidr=127.0.0.1/32&cidr=::1/128", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer admin-test-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("admin delete status=%d", resp.StatusCode)
	}

	// Session count should drop to 0 immediately (evicted).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if srv.Metrics().ActiveSessions() == 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if srv.Metrics().ActiveSessions() != 0 {
		t.Fatalf("want 0 active UDP sessions after allowlist rm, got %d", srv.Metrics().ActiveSessions())
	}
}
