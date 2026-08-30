package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
)

const (
	DefaultListen       = ":8443"
	DefaultAdminListen  = "127.0.0.1:9090"
	DefaultTokenFile    = "token"
	DefaultAdminToken   = "admin.token"
	DefaultAllowlist    = "allowlist.json"
	DefaultDenylist     = "denylist.json"
	ExampleAdminToken   = "admin-dev-token-change-me"
	MinPublicAdminToken = 16
)

func (c *File) applyCommon() {
	if strings.TrimSpace(c.Token) == "" && c.TokenFile == "" && c.Path != "" {
		cand := filepath.Join(filepath.Dir(c.Path), DefaultTokenFile)
		if st, err := os.Stat(cand); err == nil && !st.IsDir() {
			c.TokenFile = cand
		}
	}
	used := make(map[string]struct{}, len(c.Tunnels))
	for i := range c.Tunnels {
		t := &c.Tunnels[i]
		t.Public = ExpandAddr(t.Public, false)
		t.Local = ExpandAddr(t.Local, true)
		inferType(t)
		name := strings.TrimSpace(t.Name)
		if name == "" {
			name = uniqueName(defaultTunnelName(*t), used)
			t.Name = name
		}
		used[name] = struct{}{}
	}
}

func (c *File) applyEdgeDefaults() error {
	if strings.TrimSpace(c.Listen) == "" {
		c.Listen = DefaultListen
	}
	dir := ""
	if c.Path != "" {
		dir = filepath.Dir(c.Path)
	}
	if c.Admin.Enable != nil && !*c.Admin.Enable {
		c.Admin.Listen = ""
	} else if strings.TrimSpace(c.Admin.Listen) == "" {
		c.Admin.Listen = DefaultAdminListen
	}
	if c.AdminEnabled() && strings.TrimSpace(c.Admin.Token) == "" && c.Admin.TokenFile == "" && dir != "" {
		c.Admin.TokenFile = filepath.Join(dir, DefaultAdminToken)
	}
	if strings.TrimSpace(c.AllowlistFile) == "" && dir != "" {
		c.AllowlistFile = filepath.Join(dir, DefaultAllowlist)
	}
	if strings.TrimSpace(c.DenylistFile) == "" && dir != "" {
		c.DenylistFile = filepath.Join(dir, DefaultDenylist)
	}
	if c.TLS.Cert == "" && c.TLS.Key == "" && dir != "" {
		c.TLS.AutoSelfSigned = true
		c.TLS.Cert = filepath.Join(dir, "certs", "edge.crt")
		c.TLS.Key = filepath.Join(dir, "certs", "edge.key")
	} else if c.TLS.Cert == "" && c.TLS.Key == "" {
		c.TLS.AutoSelfSigned = true
	}
	return nil
}

func (c *File) applyAgentDefaults() {
	if strings.TrimSpace(c.TLS.ServerName) != "" {
		return
	}
	if c.SkipVerify() {
		c.TLS.ServerName = "localhost"
		return
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(c.Edge))
	if err == nil && host != "" {
		c.TLS.ServerName = host
	}
}

func inferType(t *Tunnel) {
	typ := strings.ToLower(strings.TrimSpace(t.Type))
	if typ != "" {
		t.Type = typ
		return
	}
	if t.Host != "" || t.TLS || t.Passthrough || t.HTTP2 {
		t.Type = TypeHTTP
		return
	}
	t.Type = TypeTCP
}

func defaultTunnelName(t Tunnel) string {
	typ := t.Type
	if typ == "" {
		typ = TypeTCP
	}
	port := addrPort(t.Public)
	if port == "" {
		port = addrPort(t.Local)
	}
	host := sanitizeName(t.Host)
	var b strings.Builder
	b.WriteString(typ)
	if port != "" {
		b.WriteByte('-')
		b.WriteString(port)
	}
	if host != "" {
		b.WriteByte('-')
		b.WriteString(host)
	}
	if b.Len() == len(typ) {
		return typ
	}
	return b.String()
}

func uniqueName(base string, used map[string]struct{}) string {
	if base == "" {
		base = "tun"
	}
	if _, ok := used[base]; !ok {
		return base
	}
	for i := 2; ; i++ {
		n := fmt.Sprintf("%s-%d", base, i)
		if _, ok := used[n]; !ok {
			return n
		}
	}
}

func sanitizeName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	var b strings.Builder
	prevDash := false
	for _, r := range s {
		ok := unicode.IsLetter(r) || unicode.IsDigit(r)
		if ok {
			b.WriteRune(r)
			prevDash = false
			continue
		}
		if !prevDash && b.Len() > 0 {
			b.WriteByte('-')
			prevDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

// ExpandAddr turns a bare port into a host:port.
// Public/listen ports become ":N" (all interfaces); local targets become 127.0.0.1:N.
func ExpandAddr(s string, localTarget bool) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	if isPort(s) {
		if localTarget {
			return "127.0.0.1:" + s
		}
		return ":" + s
	}
	return s
}

func isPort(s string) bool {
	n, err := strconv.Atoi(s)
	return err == nil && n >= 0 && n <= 65535
}

func addrPort(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if isPort(s) {
		return s
	}
	if _, port, err := net.SplitHostPort(s); err == nil {
		return port
	}
	return ""
}
