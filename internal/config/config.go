package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	TypeHTTP = "http"
	TypeTCP  = "tcp"
	TypeUDP  = "udp"
)

// File is the YAML configuration for edge or agent.
type File struct {
	Path string `yaml:"-"`

	Listen        string   `yaml:"listen"`
	Edge          string   `yaml:"edge"`
	Token         string   `yaml:"token"`
	TokenFile     string   `yaml:"token_file"`
	AgentID       string   `yaml:"agent_id"`
	TLS           TLS      `yaml:"tls"`
	AllowlistFile string   `yaml:"allowlist_file"`
	Allowlist     []string `yaml:"allowlist"`
	Tunnels       []Tunnel `yaml:"tunnels"`

	IdleTimeout      Duration `yaml:"idle_timeout"`
	DialTimeout      Duration `yaml:"dial_timeout"`
	MaxSessions      int      `yaml:"max_sessions"`
	ShutdownTimeout  Duration `yaml:"shutdown_timeout"`
	LogLevel         string   `yaml:"log_level"`
	LogFormat        string   `yaml:"log_format"`
	ProxyProtocol    bool     `yaml:"proxy_protocol"`
	LocalPrivateOnly *bool    `yaml:"local_private_only"`
	HealthPath       string   `yaml:"health_path"`
}

// TLS holds certificate settings for the tunnel.
type TLS struct {
	Cert               string `yaml:"cert"`
	Key                string `yaml:"key"`
	CA                 string `yaml:"ca"`
	ServerName         string `yaml:"server_name"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	AutoSelfSigned     bool   `yaml:"auto_self_signed"`
}

// Tunnel is one public-to-local mapping.
type Tunnel struct {
	Name   string `yaml:"name"`
	Type   string `yaml:"type"`
	Public string `yaml:"public"`
	TLS    bool   `yaml:"tls"` // when type=http: terminate TLS on Edge (HTTPS)
	Local  string `yaml:"local"`
	Host   string `yaml:"host"` // HTTP Host / TLS SNI; empty = catch-all on that public
	Cert   string `yaml:"cert"` // optional per-tunnel HTTPS cert (relative to config dir)
	Key    string `yaml:"key"`
}

// Duration wraps time.Duration for YAML strings like "5m".
type Duration time.Duration

func (d Duration) Duration() time.Duration { return time.Duration(d) }

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	if value == nil || value.ShortTag() == "!!null" || strings.TrimSpace(value.Value) == "" {
		*d = 0
		return nil
	}
	var s string
	if err := value.Decode(&s); err == nil {
		s = strings.TrimSpace(s)
		if s == "" || s == "0" {
			*d = 0
			return nil
		}
		parsed, err := time.ParseDuration(s)
		if err != nil {
			return err
		}
		*d = Duration(parsed)
		return nil
	}
	var n int64
	if err := value.Decode(&n); err != nil {
		return err
	}
	*d = Duration(time.Duration(n) * time.Second)
	return nil
}

// Load reads and validates a YAML config file. Relative paths are resolved
// against the config file directory.
func Load(path string) (*File, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, err
	}
	var cfg File
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	cfg.Path = abs
	base := filepath.Dir(abs)
	cfg.resolvePaths(base)
	if err := cfg.loadToken(); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *File) resolvePaths(base string) {
	c.TokenFile = resolve(base, c.TokenFile)
	c.AllowlistFile = resolve(base, c.AllowlistFile)
	c.TLS.Cert = resolve(base, c.TLS.Cert)
	c.TLS.Key = resolve(base, c.TLS.Key)
	c.TLS.CA = resolve(base, c.TLS.CA)
	for i := range c.Tunnels {
		c.Tunnels[i].Cert = resolve(base, c.Tunnels[i].Cert)
		c.Tunnels[i].Key = resolve(base, c.Tunnels[i].Key)
	}
}

func resolve(base, p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(base, p)
}

func (c *File) loadToken() error {
	if c.TokenFile == "" {
		return nil
	}
	data, err := os.ReadFile(c.TokenFile)
	if err != nil {
		return fmt.Errorf("read token_file: %w", err)
	}
	tok := strings.TrimSpace(string(data))
	if tok == "" {
		return fmt.Errorf("token_file is empty")
	}
	c.Token = tok
	return nil
}

// Validate checks required fields shared by edge and agent.
func (c *File) Validate() error {
	if strings.TrimSpace(c.Token) == "" {
		return fmt.Errorf("token is required (or token_file)")
	}
	names := make(map[string]struct{})
	for i, t := range c.Tunnels {
		if strings.TrimSpace(t.Name) == "" {
			return fmt.Errorf("tunnels[%d]: name is required", i)
		}
		if _, ok := names[t.Name]; ok {
			return fmt.Errorf("duplicate tunnel name %q", t.Name)
		}
		names[t.Name] = struct{}{}
		typ := strings.ToLower(strings.TrimSpace(t.Type))
		if typ == "" {
			typ = TypeTCP
			c.Tunnels[i].Type = TypeTCP
		} else {
			c.Tunnels[i].Type = typ
		}
		switch c.Tunnels[i].Type {
		case TypeHTTP, TypeTCP, TypeUDP:
		default:
			return fmt.Errorf("tunnel %q: unknown type %q", t.Name, t.Type)
		}
	}
	if c.MaxSessions < 0 {
		return fmt.Errorf("max_sessions must be >= 0")
	}
	return nil
}

// ValidateEdge checks edge-specific fields.
func (c *File) ValidateEdge() error {
	if err := c.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(c.Listen) == "" {
		return fmt.Errorf("listen is required for edge")
	}
	if !c.TLS.AutoSelfSigned && (c.TLS.Cert == "" || c.TLS.Key == "") {
		return fmt.Errorf("tls.cert and tls.key are required (or set tls.auto_self_signed)")
	}
	if hp := strings.TrimSpace(c.HealthPath); hp != "" && !strings.HasPrefix(hp, "/") {
		return fmt.Errorf("health_path must start with /")
	}
	publicTCP := make(map[string]struct{})
	publicUDP := make(map[string]struct{})
	for _, t := range c.Tunnels {
		if t.Type != TypeTCP {
			continue
		}
		if strings.TrimSpace(t.Public) == "" {
			return fmt.Errorf("tunnel %q: public is required for tcp", t.Name)
		}
		if _, ok := publicTCP[t.Public]; ok {
			return fmt.Errorf("duplicate public listen %q", t.Public)
		}
		publicTCP[t.Public] = struct{}{}
		if strings.TrimSpace(t.Local) == "" {
			return fmt.Errorf("tunnel %q: local is required", t.Name)
		}
	}
	for _, t := range c.Tunnels {
		if t.Type != TypeUDP {
			continue
		}
		if strings.TrimSpace(t.Public) == "" {
			return fmt.Errorf("tunnel %q: public is required for udp", t.Name)
		}
		if _, ok := publicUDP[t.Public]; ok {
			return fmt.Errorf("duplicate public udp listen %q", t.Public)
		}
		publicUDP[t.Public] = struct{}{}
		if strings.TrimSpace(t.Local) == "" {
			return fmt.Errorf("tunnel %q: local is required", t.Name)
		}
	}
	type httpGroupMeta struct {
		tls   bool
		hosts map[string]string // normalized host -> tunnel name; "" = catch-all
	}
	httpGroups := make(map[string]*httpGroupMeta)
	for _, t := range c.Tunnels {
		if t.Type != TypeHTTP {
			continue
		}
		if strings.TrimSpace(t.Public) == "" {
			return fmt.Errorf("tunnel %q: public is required for http", t.Name)
		}
		if strings.TrimSpace(t.Local) == "" {
			return fmt.Errorf("tunnel %q: local is required", t.Name)
		}
		if _, ok := publicTCP[t.Public]; ok {
			return fmt.Errorf("public listen %q used by both tcp and http", t.Public)
		}
		if t.TLS {
			hasPair := (t.Cert != "" && t.Key != "") || (c.TLS.Cert != "" && c.TLS.Key != "") || c.TLS.AutoSelfSigned
			if !hasPair {
				return fmt.Errorf("tunnel %q: https requires cert/key (tunnel or edge tls) or tls.auto_self_signed", t.Name)
			}
			if (t.Cert == "") != (t.Key == "") {
				return fmt.Errorf("tunnel %q: cert and key must both be set", t.Name)
			}
		}
		g, ok := httpGroups[t.Public]
		if !ok {
			g = &httpGroupMeta{tls: t.TLS, hosts: make(map[string]string)}
			httpGroups[t.Public] = g
		} else if g.tls != t.TLS {
			return fmt.Errorf("public listen %q mixes tls and non-tls http tunnels", t.Public)
		}
		hostKey := normalizeConfigHost(t.Host)
		if _, dup := g.hosts[hostKey]; dup {
			if hostKey == "" {
				return fmt.Errorf("duplicate catch-all http tunnel on %q", t.Public)
			}
			return fmt.Errorf("duplicate http host %q on %q", hostKey, t.Public)
		}
		g.hosts[hostKey] = t.Name
	}
	return nil
}

func normalizeConfigHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		return strings.ToLower(h)
	}
	return strings.ToLower(host)
}

// ValidateAgent checks agent-specific fields.
func (c *File) ValidateAgent() error {
	if err := c.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(c.Edge) == "" {
		return fmt.Errorf("edge is required for agent")
	}
	for _, t := range c.Tunnels {
		switch t.Type {
		case TypeTCP, TypeHTTP, TypeUDP:
			if strings.TrimSpace(t.Local) == "" {
				return fmt.Errorf("tunnel %q: local is required", t.Name)
			}
		}
	}
	return nil
}

// TunnelByName returns a tunnel definition by name.
func (c *File) TunnelByName(name string) (Tunnel, bool) {
	for _, t := range c.Tunnels {
		if t.Name == name {
			return t, true
		}
	}
	return Tunnel{}, false
}

// TCPTunnels returns TCP mappings only.
func (c *File) TCPTunnels() []Tunnel {
	var out []Tunnel
	for _, t := range c.Tunnels {
		if t.Type == TypeTCP {
			out = append(out, t)
		}
	}
	return out
}

// HTTPTunnels returns HTTP/HTTPS mappings only.
func (c *File) HTTPTunnels() []Tunnel {
	var out []Tunnel
	for _, t := range c.Tunnels {
		if t.Type == TypeHTTP {
			out = append(out, t)
		}
	}
	return out
}

// UDPTunnels returns UDP mappings only.
func (c *File) UDPTunnels() []Tunnel {
	var out []Tunnel
	for _, t := range c.Tunnels {
		if t.Type == TypeUDP {
			out = append(out, t)
		}
	}
	return out
}

// HealthPathOrDefault returns the optional Edge health-check path (empty = disabled).
func (c *File) HealthPathOrDefault() string {
	return strings.TrimSpace(c.HealthPath)
}

// PrivateOnly reports whether local dials must stay on loopback/RFC1918/ULA.
func (c *File) PrivateOnly() bool {
	if c.LocalPrivateOnly == nil {
		return true
	}
	return *c.LocalPrivateOnly
}

// IdleOrDefault is the TCP idle timeout (0 = none).
func (c *File) IdleOrDefault() time.Duration {
	return c.IdleTimeout.Duration()
}

// UDPIdleOrDefault is the UDP association idle timeout.
// Uses idle_timeout when set; otherwise defaults to 60s (UDP always needs a TTL).
func (c *File) UDPIdleOrDefault() time.Duration {
	if d := c.IdleTimeout.Duration(); d > 0 {
		return d
	}
	return 60 * time.Second
}

// DialOrDefault is the local/agent dial timeout.
func (c *File) DialOrDefault() time.Duration {
	if c.DialTimeout.Duration() <= 0 {
		return 10 * time.Second
	}
	return c.DialTimeout.Duration()
}

// MaxSessionsOrDefault returns the session cap (0 = default 1024).
func (c *File) MaxSessionsOrDefault() int {
	if c.MaxSessions <= 0 {
		return 1024
	}
	return c.MaxSessions
}

// ShutdownOrDefault is the graceful drain timeout.
func (c *File) ShutdownOrDefault() time.Duration {
	if c.ShutdownTimeout.Duration() <= 0 {
		return 10 * time.Second
	}
	return c.ShutdownTimeout.Duration()
}

// LogLevelOrDefault returns slog level name.
func (c *File) LogLevelOrDefault() string {
	if strings.TrimSpace(c.LogLevel) == "" {
		return "info"
	}
	return c.LogLevel
}

// LogFormatOrDefault returns text or json.
func (c *File) LogFormatOrDefault() string {
	if strings.TrimSpace(c.LogFormat) == "" {
		return "text"
	}
	return c.LogFormat
}
