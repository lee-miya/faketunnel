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
