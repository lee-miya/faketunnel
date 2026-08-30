package itest

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"mytunnel/internal/acl"
	"mytunnel/internal/agent"
	"mytunnel/internal/config"
	"mytunnel/internal/edge"
	"mytunnel/internal/logutil"
)

func TestEndToEndHTTPHostRouting(t *testing.T) {
	if testing.Short() {
		t.Skip("skip e2e in short mode")
	}
	backendA := startHTTPBackend(t, "alpha")
	backendB := startHTTPBackend(t, "beta")

	edgeCfg, agentCfg := testPair(t)
	edgeCfg.HealthPath = "/healthz"
	edgeCfg.Tunnels = []config.Tunnel{
		{
			Name:   "web-a",
			Type:   config.TypeHTTP,
			Public: "127.0.0.1:0",
			Host:   "a.example",
			Local:  backendA,
		},
		{
			Name:   "web-b",
			Type:   config.TypeHTTP,
			Public: "127.0.0.1:0",
			Host:   "b.example",
			Local:  backendB,
		},
	}
	agentCfg.Tunnels = []config.Tunnel{
		{Name: "web-a", Type: config.TypeHTTP, Local: backendA},
		{Name: "web-b", Type: config.TypeHTTP, Local: backendB},
	}

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

	agentCfg.Edge = srv.TunnelAddr()
	cli, err := agent.New(agentCfg, log)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = cli.Run(ctx) }()

	public := srv.PublicAddr("web-a")
	if public == "" {
		t.Fatal("missing public addr")
	}
	if srv.PublicAddr("web-b") != public {
		t.Fatal("host-routed tunnels should share listener")
	}

	waitHTTP(t, "http://"+public+"/healthz", "", http.StatusOK, "ok\n", 5*time.Second)

	bodyA := waitHTTP(t, "http://"+public+"/ping", "a.example", http.StatusOK, "alpha", 8*time.Second)
	if bodyA != "alpha" {
		t.Fatalf("bodyA=%q", bodyA)
	}
	bodyB := waitHTTP(t, "http://"+public+"/ping", "b.example", http.StatusOK, "beta", 8*time.Second)
	if bodyB != "beta" {
		t.Fatalf("bodyB=%q", bodyB)
	}
}

func TestEndToEndHTTPSNI(t *testing.T) {
	if testing.Short() {
		t.Skip("skip e2e in short mode")
	}
	backend := startHTTPBackend(t, "secure")
	edgeCfg, agentCfg := testPair(t)
	edgeCfg.Tunnels = []config.Tunnel{{
		Name:   "web-tls",
		Type:   config.TypeHTTP,
		Public: "127.0.0.1:0",
		TLS:    true,
		Host:   "secure.example",
		Local:  backend,
	}}
	agentCfg.Tunnels = []config.Tunnel{{
		Name:  "web-tls",
		Type:  config.TypeHTTP,
		Local: backend,
	}}

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

	agentCfg.Edge = srv.TunnelAddr()
	cli, err := agent.New(agentCfg, log)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = cli.Run(ctx) }()

	public := srv.PublicAddr("web-tls")
	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         "secure.example",
				MinVersion:         tls.VersionTLS12,
			},
		},
	}
	deadline := time.Now().Add(8 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		req, err := http.NewRequest(http.MethodGet, "https://"+public+"/ping", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = "secure.example"
		resp, err := client.Do(req)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK && string(body) == "secure" {
				return
			}
			last = fmt.Errorf("status=%d body=%q", resp.StatusCode, body)
		} else {
			last = err
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("https: %v", last)
}

func startHTTPBackend(t *testing.T, body string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, body)
	})
	srv := &http.Server{Handler: mux}
	t.Cleanup(func() {
		_ = srv.Close()
		_ = ln.Close()
	})
	go func() { _ = srv.Serve(ln) }()
	return ln.Addr().String()
}

func waitHTTP(t *testing.T, url, host string, wantStatus int, wantBody string, wait time.Duration) string {
	t.Helper()
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(wait)
	var last error
	for time.Now().Before(deadline) {
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			t.Fatal(err)
		}
		if host != "" {
			req.Host = host
		}
		resp, err := client.Do(req)
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == wantStatus && (wantBody == "" || string(b) == wantBody) {
				return string(b)
			}
			last = fmt.Errorf("status=%d body=%q", resp.StatusCode, b)
		} else {
			last = err
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("http %s host=%q: %v", url, host, last)
	return ""
}
