package config

import (
	"os"
	"path/filepath"
	"strings"
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

func TestValidateEdgeHTTP2RequiresTLS(t *testing.T) {
	t.Parallel()
	cfg := &File{
		Listen: ":8443",
		Token:  "x",
		TLS:    TLS{AutoSelfSigned: true},
		Tunnels: []Tunnel{{
			Name: "h2", Type: TypeHTTP, Public: "127.0.0.1:443",
			HTTP2: true, Local: "127.0.0.1:1",
		}},
	}
	if err := cfg.ValidateEdge(); err == nil {
		t.Fatal("expected http2 requires tls")
	}
	cfg.Tunnels[0].TLS = true
	if err := cfg.ValidateEdge(); err != nil {
		t.Fatal(err)
	}
}

func TestExampleConfigsLoad(t *testing.T) {
	t.Parallel()
	root := moduleRoot(t)
	edgePath := filepath.Join(root, "configs", "examples", "edge.yaml")
	edge, err := LoadEdge(edgePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(edge.TCPTunnels()) != 1 || len(edge.HTTPTunnels()) != 3 || len(edge.UDPTunnels()) != 1 {
		t.Fatalf("example tunnels tcp=%d http=%d udp=%d", len(edge.TCPTunnels()), len(edge.HTTPTunnels()), len(edge.UDPTunnels()))
	}
	agent, err := LoadAgent(filepath.Join(root, "configs", "examples", "agent.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(agent.Tunnels) != 0 {
		t.Fatal("example agent should omit tunnels")
	}
}

func TestGiteaExampleConfigsLoad(t *testing.T) {
	t.Parallel()
	root := moduleRoot(t)
	edge, err := LoadEdge(filepath.Join(root, "configs", "examples", "gitea", "edge.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(edge.HTTPTunnels()) != 1 || len(edge.TCPTunnels()) != 1 {
		t.Fatalf("gitea edge tunnels http=%d tcp=%d", len(edge.HTTPTunnels()), len(edge.TCPTunnels()))
	}
	if strings.TrimSpace(edge.HTTPTunnels()[0].Host) != "" {
		t.Fatal("gitea http tunnel should omit host so IP access works")
	}
	if edge.HTTPTunnels()[0].Local != "127.0.0.1:3000" {
		t.Fatalf("local=%q", edge.HTTPTunnels()[0].Local)
	}
	if edge.Listen != DefaultListen {
		t.Fatalf("listen default=%q", edge.Listen)
	}
	agent, err := LoadAgent(filepath.Join(root, "configs", "examples", "gitea", "agent.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(agent.Tunnels) != 0 {
		t.Fatal("gitea agent should omit tunnels")
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
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

func TestLoadEdgeFillsDefaults(t *testing.T) {
	t.Parallel()
	p := writeTemp(t, "edge.yaml", `
token: "x"
tunnels:
  - public: 8080
    local: 3000
    host: web.example
  - public: 2222
    local: 2222
`)
	cfg, err := LoadEdge(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != DefaultListen {
		t.Fatalf("listen=%q", cfg.Listen)
	}
	if !cfg.TLS.AutoSelfSigned || cfg.TLS.Cert == "" || cfg.TLS.Key == "" {
		t.Fatal("expected self-signed cert paths")
	}
	if !cfg.AdminEnabled() || cfg.Admin.Listen != DefaultAdminListen {
		t.Fatal("admin should default on")
	}
	if cfg.Admin.Token == "" {
		t.Fatal("admin token should be generated")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(p), DefaultAdminToken)); err != nil {
		t.Fatal(err)
	}
	if cfg.AllowlistFile != filepath.Join(filepath.Dir(p), DefaultAllowlist) {
		t.Fatalf("allowlist_file=%q", cfg.AllowlistFile)
	}
	if len(cfg.HTTPTunnels()) != 1 || len(cfg.TCPTunnels()) != 1 {
		t.Fatalf("types http=%d tcp=%d", len(cfg.HTTPTunnels()), len(cfg.TCPTunnels()))
	}
	httpTun := cfg.HTTPTunnels()[0]
	if httpTun.Public != ":8080" || httpTun.Local != "127.0.0.1:3000" {
		t.Fatalf("http addrs public=%q local=%q", httpTun.Public, httpTun.Local)
	}
	if httpTun.Name != "http-8080-web-example" {
		t.Fatalf("http name=%q", httpTun.Name)
	}
	if cfg.TCPTunnels()[0].Name != "tcp-2222" {
		t.Fatalf("tcp name=%q", cfg.TCPTunnels()[0].Name)
	}
	if cfg.DenylistFile != filepath.Join(filepath.Dir(p), DefaultDenylist) {
		t.Fatalf("denylist_file=%q", cfg.DenylistFile)
	}
}

func TestLoadAgentOmitsTunnels(t *testing.T) {
	t.Parallel()
	p := writeTemp(t, "agent.yaml", `
edge: "203.0.113.10:8443"
token: "x"
`)
	cfg, err := LoadAgent(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RestrictTunnels() {
		t.Fatal("expected no tunnel allowlist")
	}
	if !cfg.SkipVerify() {
		t.Fatal("skip verify should default on without ca")
	}
	if cfg.TLS.ServerName != "localhost" {
		t.Fatalf("server_name=%q", cfg.TLS.ServerName)
	}
}

func TestSkipVerifyExplicitFalse(t *testing.T) {
	t.Parallel()
	f := false
	cfg := &File{TLS: TLS{InsecureSkipVerify: &f}}
	if cfg.SkipVerify() {
		t.Fatal("explicit false must verify")
	}
}

func TestPublicAdminRejectsExampleToken(t *testing.T) {
	t.Parallel()
	cfg := &File{
		Listen:        ":8443",
		Token:         "tunnel-token-is-long-enough",
		TLS:           TLS{AutoSelfSigned: true},
		AllowlistFile: "allowlist.json",
		Admin:         Admin{Listen: "0.0.0.0:9090", Token: ExampleAdminToken},
	}
	if err := cfg.ValidateEdge(); err == nil || !strings.Contains(err.Error(), "example placeholder") {
		t.Fatalf("want example token error, got %v", err)
	}
	cfg.Admin.Token = "short"
	if err := cfg.ValidateEdge(); err == nil || !strings.Contains(err.Error(), "at least") {
		t.Fatalf("want length error, got %v", err)
	}
	cfg.Admin.Token = "tunnel-token-is-long-enough"
	if err := cfg.ValidateEdge(); err == nil || !strings.Contains(err.Error(), "must differ") {
		t.Fatalf("want differ error, got %v", err)
	}
	cfg.Admin.Token = "admin-token-is-long-enough"
	if err := cfg.ValidateEdge(); err != nil {
		t.Fatal(err)
	}
}

func TestAdminEnableFalse(t *testing.T) {
	t.Parallel()
	off := false
	p := writeTemp(t, "edge.yaml", `
token: x
tunnels:
  - public: 1
    local: 2
`)
	cfg, err := loadYAML(p)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Admin.Enable = &off
	cfg.applyCommon()
	if err := cfg.applyEdgeDefaults(); err != nil {
		t.Fatal(err)
	}
	if cfg.AdminEnabled() {
		t.Fatal("admin disabled")
	}
}

func TestParseMapping(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, pub, loc string
	}{
		{"8080", "8080", "127.0.0.1:8080"},
		{"8080:3000", "8080", "127.0.0.1:3000"},
		{"0.0.0.0:8080", "0.0.0.0:8080", "127.0.0.1:8080"},
		{"127.0.0.1:8080:3000", "127.0.0.1:8080", "127.0.0.1:3000"},
		{"0.0.0.0:8080:10.0.0.1:3000", "0.0.0.0:8080", "10.0.0.1:3000"},
	}
	for _, tc := range cases {
		pub, loc, err := ParseMapping(tc.in)
		if err != nil {
			t.Fatalf("%s: %v", tc.in, err)
		}
		if pub != tc.pub || loc != tc.loc {
			t.Fatalf("%s: pub=%q loc=%q", tc.in, pub, loc)
		}
	}
	if _, _, err := ParseMapping(""); err == nil {
		t.Fatal("expected error")
	}
}

func TestInitWritesPair(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	res, err := Init(InitOptions{
		Dir:      dir,
		EdgeHost: "203.0.113.10",
		HTTP:     []string{"8080:3000"},
		TCP:      []string{"2222"},
	})
	if err != nil {
		t.Fatal(err)
	}
	edge, err := LoadEdge(res.EdgeYAML)
	if err != nil {
		t.Fatal(err)
	}
	if len(edge.HTTPTunnels()) != 1 || len(edge.TCPTunnels()) != 1 {
		t.Fatal("init tunnels")
	}
	agent, err := LoadAgent(res.AgentYAML)
	if err != nil {
		t.Fatal(err)
	}
	if agent.Edge != "203.0.113.10:8443" {
		t.Fatalf("agent edge=%q", agent.Edge)
	}
	if agent.Token != edge.Token || agent.Token == "" {
		t.Fatal("tokens should match")
	}
	if len(agent.Tunnels) != 0 {
		t.Fatal("init agent should omit tunnels")
	}
	if _, err := Init(InitOptions{Dir: dir, HTTP: []string{"80:80"}}); err == nil {
		t.Fatal("expected exists error")
	}
}

func TestInitPresetGitea(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	res, err := Init(InitOptions{Dir: dir, EdgeHost: "vps.example.com", Preset: "gitea"})
	if err != nil {
		t.Fatal(err)
	}
	edge, err := LoadEdge(res.EdgeYAML)
	if err != nil {
		t.Fatal(err)
	}
	if len(edge.HTTPTunnels()) != 1 || len(edge.TCPTunnels()) != 1 {
		t.Fatal("gitea preset tunnels")
	}
	if edge.HTTPTunnels()[0].Local != "127.0.0.1:3000" {
		t.Fatalf("gitea http local=%q", edge.HTTPTunnels()[0].Local)
	}
}

func TestFindConfig(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "edge.yaml")
	if err := os.WriteFile(p, []byte("token: x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKETUNNEL_CONFIG", p)
	if got := Find("edge"); got != p {
		t.Fatalf("Find=%q", got)
	}
}

func TestExpandAddr(t *testing.T) {
	t.Parallel()
	if ExpandAddr("8080", false) != ":8080" {
		t.Fatal("public port")
	}
	if ExpandAddr("3000", true) != "127.0.0.1:3000" {
		t.Fatal("local port")
	}
	if ExpandAddr("127.0.0.1:9", true) != "127.0.0.1:9" {
		t.Fatal("unchanged")
	}
	if ExpandAddr("8443", false) != ":8443" {
		t.Fatal("listen port")
	}
}

func TestExpandEdgeAddr(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
	}{
		{"8443", "127.0.0.1:8443"},
		{":8443", "127.0.0.1:8443"},
		{"127.0.0.1", "127.0.0.1:8443"},
		{"127.0.0.1:8443", "127.0.0.1:8443"},
		{"localhost", "localhost:8443"},
		{"203.0.113.10", "203.0.113.10:8443"},
		{"203.0.113.10:8443", "203.0.113.10:8443"},
		{"vps.example.com", "vps.example.com:8443"},
		{"vps.example.com:9443", "vps.example.com:9443"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := ExpandEdgeAddr(tc.in); got != tc.want {
			t.Errorf("ExpandEdgeAddr(%q) = %q; want %q", tc.in, got, tc.want)
		}
	}
}

func TestExpandAdminListen(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
	}{
		{"9090", "127.0.0.1:9090"},
		{":9090", "127.0.0.1:9090"},
		{"127.0.0.1:9090", "127.0.0.1:9090"},
		{"0.0.0.0:9090", "0.0.0.0:9090"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := ExpandAdminListen(tc.in); got != tc.want {
			t.Errorf("ExpandAdminListen(%q) = %q; want %q", tc.in, got, tc.want)
		}
	}
}

func TestLoadEdgeListenShorthand(t *testing.T) {
	t.Parallel()
	p := writeTemp(t, "edge.yaml", `
token: "x"
listen: 8443
tunnels:
  - public: 8080
    local: 3000
`)
	cfg, err := LoadEdge(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != ":8443" {
		t.Fatalf("listen=%q; want :8443", cfg.Listen)
	}
}

func TestLoadAgentEdgeShorthandAndServerName(t *testing.T) {
	t.Parallel()
	// Test bare host IP with CA
	p := writeTemp(t, "agent.yaml", `
token: "x"
edge: "203.0.113.10"
tls:
  ca: "some-ca.crt"
  insecure_skip_verify: false
`)
	cfg, err := LoadAgent(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Edge != "203.0.113.10:8443" {
		t.Fatalf("edge=%q; want 203.0.113.10:8443", cfg.Edge)
	}
	// For IP target, server_name should default to localhost so self-signed cert SANs match.
	if cfg.TLS.ServerName != "localhost" {
		t.Fatalf("server_name=%q; want localhost", cfg.TLS.ServerName)
	}

	// Test bare port
	p2 := writeTemp(t, "agent2.yaml", `
token: "x"
edge: 8443
`)
	cfg2, err := LoadAgent(p2)
	if err != nil {
		t.Fatal(err)
	}
	if cfg2.Edge != "127.0.0.1:8443" {
		t.Fatalf("edge=%q; want 127.0.0.1:8443", cfg2.Edge)
	}
}
