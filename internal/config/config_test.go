package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeTemp(t *testing.T, name, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadEdgeValid(t *testing.T) {
	t.Parallel()
	p := writeTemp(t, "edge.yaml", `
listen: ":8443"
token: "dev-token-change-me"
tls:
  auto_self_signed: true
allowlist:
  - "127.0.0.1/32"
tunnels:
  - name: echo
    type: tcp
    public: "127.0.0.1:2222"
    local: "127.0.0.1:9000"
idle_timeout: 5m
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.ValidateEdge(); err != nil {
		t.Fatal(err)
	}
	if cfg.IdleOrDefault() != 5*time.Minute {
		t.Fatalf("idle=%s", cfg.IdleOrDefault())
	}
	if !cfg.PrivateOnly() {
		t.Fatal("private only should default true")
	}
}

func TestLoadRejectsEmptyToken(t *testing.T) {
	t.Parallel()
	p := writeTemp(t, "bad.yaml", `listen: ":1"`+"\n")
	if _, err := Load(p); err == nil {
		t.Fatal("expected error")
	}
}

func TestTokenFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	tok := filepath.Join(dir, "token")
	if err := os.WriteFile(tok, []byte(" from-file \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "edge.yaml")
	body := "listen: \":8443\"\ntoken_file: token\ntls:\n  auto_self_signed: true\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Token != "from-file" {
		t.Fatalf("token=%q", cfg.Token)
	}
}

func TestDuplicateTunnelName(t *testing.T) {
	t.Parallel()
	p := writeTemp(t, "dup.yaml", `
listen: ":1"
token: x
tls:
  auto_self_signed: true
tunnels:
  - name: a
    type: tcp
    public: ":1"
    local: "127.0.0.1:1"
  - name: a
    type: tcp
    public: ":2"
    local: "127.0.0.1:2"
`)
	if _, err := Load(p); err == nil {
		t.Fatal("expected duplicate name error")
	}
}

func TestValidateAgentRequiresEdge(t *testing.T) {
	t.Parallel()
	cfg := &File{Token: "x"}
	if err := cfg.ValidateAgent(); err == nil {
		t.Fatal("expected error")
	}
	cfg.Edge = "127.0.0.1:8443"
	if err := cfg.ValidateAgent(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateEdgeHTTPHostRouting(t *testing.T) {
	t.Parallel()
	cfg := &File{
		Listen: ":8443",
		Token:  "x",
		TLS:    TLS{AutoSelfSigned: true},
		Tunnels: []Tunnel{
			{Name: "a", Type: TypeHTTP, Public: "127.0.0.1:8080", Host: "a.example", Local: "127.0.0.1:1"},
			{Name: "b", Type: TypeHTTP, Public: "127.0.0.1:8080", Host: "b.example", Local: "127.0.0.1:2"},
		},
	}
	if err := cfg.ValidateEdge(); err != nil {
		t.Fatal(err)
	}
	cfg.Tunnels = append(cfg.Tunnels, Tunnel{
		Name: "dup", Type: TypeHTTP, Public: "127.0.0.1:8080", Host: "a.example", Local: "127.0.0.1:3",
	})
	if err := cfg.ValidateEdge(); err == nil {
		t.Fatal("expected duplicate host error")
	}
}

func TestValidateEdgeHTTPHealthPath(t *testing.T) {
	t.Parallel()
	cfg := &File{
		Listen:     ":8443",
		Token:      "x",
		TLS:        TLS{AutoSelfSigned: true},
		HealthPath: "healthz",
		Tunnels: []Tunnel{
			{Name: "web", Type: TypeHTTP, Public: "127.0.0.1:80", Local: "127.0.0.1:1"},
		},
	}
	if err := cfg.ValidateEdge(); err == nil {
		t.Fatal("expected health_path error")
	}
}

func TestValidateEdgeUDP(t *testing.T) {
	t.Parallel()
	cfg := &File{
		Listen: ":8443",
		Token:  "x",
		TLS:    TLS{AutoSelfSigned: true},
		Tunnels: []Tunnel{
			{Name: "dns", Type: TypeUDP, Public: "127.0.0.1:5353", Local: "127.0.0.1:53"},
		},
	}
	if err := cfg.ValidateEdge(); err != nil {
		t.Fatal(err)
	}
	if len(cfg.UDPTunnels()) != 1 {
		t.Fatal("expected one udp tunnel")
	}
	cfg.Tunnels = append(cfg.Tunnels, Tunnel{
		Name: "dup", Type: TypeUDP, Public: "127.0.0.1:5353", Local: "127.0.0.1:54",
	})
	if err := cfg.ValidateEdge(); err == nil {
		t.Fatal("expected duplicate udp public error")
	}
}

func TestValidateEdgeHTTPPassthrough(t *testing.T) {
	t.Parallel()
	cfg := &File{
		Listen: ":8443",
		Token:  "x",
		TLS:    TLS{AutoSelfSigned: true},
		Tunnels: []Tunnel{{
			Name: "h2", Type: TypeHTTP, Public: "127.0.0.1:443",
			TLS: true, Passthrough: true, Host: "h2.example", Local: "127.0.0.1:1",
		}},
	}
	if err := cfg.ValidateEdge(); err != nil {
		t.Fatal(err)
	}
	// Passthrough does not need public HTTPS certs; tunnel TLS still uses auto_self_signed.
	cfg.TLS.Cert = ""
	cfg.TLS.Key = ""
	if err := cfg.ValidateEdge(); err != nil {
		t.Fatal(err)
	}
	cfg.Tunnels[0].Passthrough = false
	cfg.TLS.AutoSelfSigned = false
	if err := cfg.ValidateEdge(); err == nil {
		t.Fatal("expected cert required for terminate")
	}
	cfg.TLS.AutoSelfSigned = true
	cfg.Tunnels[0].Passthrough = true
	cfg.Tunnels[0].TLS = false
	if err := cfg.ValidateEdge(); err == nil {
		t.Fatal("expected passthrough requires tls")
	}
}

func TestValidateEdgeAdminRequiresTokenAndAllowlistFile(t *testing.T) {
	t.Parallel()
	cfg := &File{
		Listen: ":8443",
		Token:  "x",
		TLS:    TLS{AutoSelfSigned: true},
		Admin:  Admin{Listen: "127.0.0.1:9090"},
	}
	if err := cfg.ValidateEdge(); err == nil {
		t.Fatal("expected admin.token error")
	}
	cfg.Admin.Token = "admin"
	if err := cfg.ValidateEdge(); err == nil {
		t.Fatal("expected allowlist_file error")
	}
	cfg.AllowlistFile = "allowlist.json"
	if err := cfg.ValidateEdge(); err != nil {
		t.Fatal(err)
	}
	if !cfg.AdminEnabled() || !cfg.AdminMetricsOrDefault() {
		t.Fatal("admin defaults")
	}
}
