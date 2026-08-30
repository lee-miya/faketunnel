package itest

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"faketunnel/internal/acl"
	"faketunnel/internal/agent"
	"faketunnel/internal/config"
	"faketunnel/internal/edge"
	"faketunnel/internal/logutil"
	"faketunnel/internal/tlsutil"
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

	srv, err := edge.New(edgeCfg, list, log)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err := srv.Start(ctx); err != nil {
		cancel()
		t.Fatal(err)
	}
	defer func() {
		cancel()
		_ = srv.Shutdown()
	}()

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

	srv, err := edge.New(edgeCfg, list, log)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err := srv.Start(ctx); err != nil {
		cancel()
		t.Fatal(err)
	}
	defer func() {
		cancel()
		_ = srv.Shutdown()
	}()

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

func TestEndToEndHTTPCatchAllByIP(t *testing.T) {
	if testing.Short() {
		t.Skip("skip e2e in short mode")
	}
	backend := startHTTPBackend(t, "gitea-like")
	edgeCfg, agentCfg := testPair(t)
	edgeCfg.Tunnels = []config.Tunnel{{
		Name: "web", Type: config.TypeHTTP, Public: "127.0.0.1:0", Local: backend,
	}}
	agentCfg.Tunnels = []config.Tunnel{{Name: "web", Type: config.TypeHTTP, Local: backend}}
	public := startHTTPPair(t, edgeCfg, agentCfg, "web")
	// No Host override: client uses the IP:port, as a browser would when given a VPS address.
	body := waitHTTP(t, "http://"+public+"/ping", "", http.StatusOK, "gitea-like", 8*time.Second)
	if body != "gitea-like" {
		t.Fatalf("body=%q", body)
	}
}

func TestEndToEndHTTPForwardedHeaders(t *testing.T) {
	if testing.Short() {
		t.Skip("skip e2e in short mode")
	}
	backend := startHTTPBackend(t, "unused")
	edgeCfg, agentCfg := testPair(t)
	edgeCfg.Tunnels = []config.Tunnel{{
		Name: "web-tls", Type: config.TypeHTTP, Public: "127.0.0.1:0",
		TLS: true, Host: "app.example", Local: backend,
	}}
	agentCfg.Tunnels = []config.Tunnel{{Name: "web-tls", Type: config.TypeHTTP, Local: backend}}
	public := startHTTPPair(t, edgeCfg, agentCfg, "web-tls")

	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         "app.example",
				MinVersion:         tls.VersionTLS12,
			},
		},
	}
	deadline := time.Now().Add(8 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		req, err := http.NewRequest(http.MethodGet, "https://"+public+"/headers", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = "app.example"
		resp, err := client.Do(req)
		if err != nil {
			last = err
			time.Sleep(50 * time.Millisecond)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			last = fmt.Errorf("status=%d body=%q", resp.StatusCode, body)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		got := string(body)
		if !strings.Contains(got, "X-Forwarded-Proto=https") {
			t.Fatalf("missing proto header: %q", got)
		}
		if !strings.Contains(got, "X-Forwarded-Host=app.example") {
			t.Fatalf("missing host header: %q", got)
		}
		return
	}
	t.Fatalf("headers: %v", last)
}

func TestEndToEndHTTPKeepAlive(t *testing.T) {
	if testing.Short() {
		t.Skip("skip e2e in short mode")
	}
	backend := startHTTPBackend(t, "ka")
	edgeCfg, agentCfg := testPair(t)
	edgeCfg.Tunnels = []config.Tunnel{{
		Name: "web", Type: config.TypeHTTP, Public: "127.0.0.1:0", Host: "ka.example", Local: backend,
	}}
	agentCfg.Tunnels = []config.Tunnel{{Name: "web", Type: config.TypeHTTP, Local: backend}}
	public := startHTTPPair(t, edgeCfg, agentCfg, "web")
	waitHTTP(t, "http://"+public+"/ping", "ka.example", http.StatusOK, "ka", 8*time.Second)

	tr := &http.Transport{DisableKeepAlives: false}
	client := &http.Client{Timeout: 3 * time.Second, Transport: tr}
	defer tr.CloseIdleConnections()
	for i := 0; i < 2; i++ {
		req, err := http.NewRequest(http.MethodGet, "http://"+public+"/ping", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = "ka.example"
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("req %d: %v", i, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || string(body) != "ka" {
			t.Fatalf("req %d status=%d body=%q", i, resp.StatusCode, body)
		}
	}
}

func TestEndToEndHTTP2Passthrough(t *testing.T) {
	if testing.Short() {
		t.Skip("skip e2e in short mode")
	}
	backend := startHTTP2TLSBackend(t, "h2e2e", []string{"h2.example"})
	edgeCfg, agentCfg := testPair(t)
	edgeCfg.Tunnels = []config.Tunnel{{
		Name: "web-h2", Type: config.TypeHTTP, Public: "127.0.0.1:0",
		TLS: true, Passthrough: true, Host: "h2.example", Local: backend,
	}}
	agentCfg.Tunnels = []config.Tunnel{{Name: "web-h2", Type: config.TypeHTTP, Local: backend}}
	public := startHTTPPair(t, edgeCfg, agentCfg, "web-h2")

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         "h2.example",
			MinVersion:         tls.VersionTLS12,
		},
		ForceAttemptHTTP2: true,
	}
	client := &http.Client{Timeout: 3 * time.Second, Transport: tr}
	defer tr.CloseIdleConnections()

	deadline := time.Now().Add(8 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		req, err := http.NewRequest(http.MethodGet, "https://"+public+"/ping", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = "h2.example"
		resp, err := client.Do(req)
		if err != nil {
			last = err
			time.Sleep(50 * time.Millisecond)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || string(body) != "h2e2e" {
			last = fmt.Errorf("status=%d body=%q proto=%s", resp.StatusCode, body, resp.Proto)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if resp.ProtoMajor != 2 {
			t.Fatalf("want HTTP/2, got %s", resp.Proto)
		}
		last = nil
		break
	}
	if last != nil {
		t.Fatalf("http2 passthrough: %v", last)
	}

	// Multiplex two streams on the same HTTP/2 connection.
	errc := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			req, err := http.NewRequest(http.MethodGet, "https://"+public+"/ping", nil)
			if err != nil {
				errc <- err
				return
			}
			req.Host = "h2.example"
			resp, err := client.Do(req)
			if err != nil {
				errc <- err
				return
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.ProtoMajor != 2 || string(body) != "h2e2e" {
				errc <- fmt.Errorf("proto=%s body=%q", resp.Proto, body)
				return
			}
			errc <- nil
		}()
	}
	for i := 0; i < 2; i++ {
		if err := <-errc; err != nil {
			t.Fatal(err)
		}
	}

	req, err := http.NewRequest(http.MethodPost, "https://"+public+"/echo", bytes.NewReader(bytes.Repeat([]byte("x"), 64*1024)))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "h2.example"
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	trail := resp.Trailer.Get("X-Echo")
	resp.Body.Close()
	if resp.ProtoMajor != 2 || len(body) != 64*1024 || trail != "trail" {
		t.Fatalf("echo proto=%s n=%d trailer=%q", resp.Proto, len(body), trail)
	}
}

func TestEndToEndHTTP2TerminateALPN(t *testing.T) {
	if testing.Short() {
		t.Skip("skip e2e in short mode")
	}
	backend := startHTTPBackend(t, "unused")
	edgeCfg, agentCfg := testPair(t)
	edgeCfg.Tunnels = []config.Tunnel{{
		Name: "web-h2c", Type: config.TypeHTTP, Public: "127.0.0.1:0",
		TLS: true, HTTP2: true, Host: "h2c.example", Local: backend,
	}}
	agentCfg.Tunnels = []config.Tunnel{{Name: "web-h2c", Type: config.TypeHTTP, Local: backend}}
	public := startHTTPPair(t, edgeCfg, agentCfg, "web-h2c")

	deadline := time.Now().Add(8 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: 500 * time.Millisecond}, "tcp", public, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         "h2c.example",
			MinVersion:         tls.VersionTLS12,
			NextProtos:         []string{"h2", "http/1.1"},
		})
		if err != nil {
			last = err
			time.Sleep(50 * time.Millisecond)
			continue
		}
		alpn := c.ConnectionState().NegotiatedProtocol
		_ = c.Close()
		if alpn != "h2" {
			last = fmt.Errorf("alpn=%q", alpn)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		return
	}
	t.Fatalf("http2 alpn: %v", last)
}

func startHTTPPair(t *testing.T, edgeCfg, agentCfg *config.File, name string) string {
	t.Helper()
	list, err := acl.New([]string{"127.0.0.1/32", "::1/128"})
	if err != nil {
		t.Fatal(err)
	}
	log := logutil.New("error", "text")
	ctx, cancel := context.WithCancel(context.Background())
	srv, err := edge.New(edgeCfg, list, log)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err := srv.Start(ctx); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		_ = srv.Shutdown()
	})
	agentCfg.Edge = srv.TunnelAddr()
	cli, err := agent.New(agentCfg, log)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = cli.Run(ctx) }()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if srv.Metrics().Snapshot().AgentConnected {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	public := srv.PublicAddr(name)
	if public == "" {
		t.Fatal("missing public addr")
	}
	return public
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
	mux.HandleFunc("/headers", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "X-Forwarded-Proto=%s\nX-Forwarded-Host=%s\n",
			r.Header.Get("X-Forwarded-Proto"), r.Header.Get("X-Forwarded-Host"))
	})
	srv := &http.Server{Handler: mux}
	t.Cleanup(func() {
		_ = srv.Close()
		_ = ln.Close()
	})
	go func() { _ = srv.Serve(ln) }()
	return ln.Addr().String()
}

func startHTTP2TLSBackend(t *testing.T, body string, hosts []string) string {
	t.Helper()
	certPEM, keyPEM, err := tlsutil.GenerateSelfSigned(hosts, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, body)
	})
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trailer", "X-Echo")
		w.WriteHeader(http.StatusOK)
		_, _ = io.Copy(w, r.Body)
		w.Header().Set("X-Echo", "trail")
	})
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   tls.VersionTLS12,
	}
	srv := &http.Server{Handler: mux, TLSConfig: tlsCfg}
	t.Cleanup(func() {
		_ = srv.Close()
		_ = ln.Close()
	})
	go func() { _ = srv.Serve(tls.NewListener(ln, tlsCfg)) }()
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
