package config

import (
	"fmt"
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
	TLS    bool   `yaml:"tls"`
	Local  string `yaml:"local"`
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
	publics := make(map[string]struct{})
	for _, t := range c.Tunnels {
		if t.Type != TypeTCP {
			continue
		}
		if strings.TrimSpace(t.Public) == "" {
			return fmt.Errorf("tunnel %q: public is required for tcp", t.Name)
		}
		if _, ok := publics[t.Public]; ok {
			return fmt.Errorf("duplicate public listen %q", t.Public)
		}
		publics[t.Public] = struct{}{}
		if strings.TrimSpace(t.Local) == "" {
			return fmt.Errorf("tunnel %q: local is required", t.Name)
		}
	}
	return nil
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
		if t.Type != TypeTCP {
			continue
		}
		if strings.TrimSpace(t.Local) == "" {
			return fmt.Errorf("tunnel %q: local is required", t.Name)
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
