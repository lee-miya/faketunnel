package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// InitOptions controls faketunnel init.
type InitOptions struct {
	Dir      string
	EdgeHost string // host or host:port of the public Edge
	Listen   string // Edge tunnel listen; default :8443
	HTTP     []string
	TCP      []string
	UDP      []string
	Allow    []string
	Preset   string
	Force    bool
}

// InitResult is the set of files written by Init.
type InitResult struct {
	Dir        string
	EdgeYAML   string
	AgentYAML  string
	TokenFile  string
	AdminToken string
	Allowlist  string
	Token      string
}

// Init writes a minimal Edge/Agent pair plus tokens and allowlist.
func Init(opts InitOptions) (*InitResult, error) {
	dir := strings.TrimSpace(opts.Dir)
	if dir == "" {
		dir = "."
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return nil, err
	}

	httpMaps := append([]string{}, opts.HTTP...)
	tcpMaps := append([]string{}, opts.TCP...)
	udpMaps := append([]string{}, opts.UDP...)
	switch strings.ToLower(strings.TrimSpace(opts.Preset)) {
	case "", "none":
	case "gitea":
		if len(httpMaps) == 0 && len(tcpMaps) == 0 && len(udpMaps) == 0 {
			httpMaps = []string{"8080:3000"}
			tcpMaps = []string{"2222:2222"}
		}
	default:
		return nil, fmt.Errorf("unknown preset %q (supported: gitea)", opts.Preset)
	}
	if len(httpMaps)+len(tcpMaps)+len(udpMaps) == 0 {
		return nil, fmt.Errorf("at least one of -http / -tcp / -udp (or -preset gitea) is required")
	}

	listen := strings.TrimSpace(opts.Listen)
	if listen == "" {
		listen = DefaultListen
	}
	listen = ExpandAddr(listen, false)
	tunnelPort := addrPort(listen)
	if tunnelPort == "" {
		tunnelPort = "8443"
	}

	edgeHost := strings.TrimSpace(opts.EdgeHost)
	if edgeHost == "" {
		edgeHost = "127.0.0.1"
	}
	agentEdge := edgeHost
	if _, _, err := net.SplitHostPort(edgeHost); err != nil {
		agentEdge = net.JoinHostPort(edgeHost, tunnelPort)
	}

	token, err := RandomToken()
	if err != nil {
		return nil, err
	}
	adminTok, err := RandomToken()
	if err != nil {
		return nil, err
	}

	var tunnels []initTunnel
	for _, s := range httpMaps {
		pub, loc, err := ParseMapping(s)
		if err != nil {
			return nil, fmt.Errorf("http %q: %w", s, err)
		}
		tunnels = append(tunnels, initTunnel{Type: TypeHTTP, Public: pub, Local: loc})
	}
	for _, s := range tcpMaps {
		pub, loc, err := ParseMapping(s)
		if err != nil {
			return nil, fmt.Errorf("tcp %q: %w", s, err)
		}
		tunnels = append(tunnels, initTunnel{Type: TypeTCP, Public: pub, Local: loc})
	}
	for _, s := range udpMaps {
		pub, loc, err := ParseMapping(s)
		if err != nil {
			return nil, fmt.Errorf("udp %q: %w", s, err)
		}
		tunnels = append(tunnels, initTunnel{Type: TypeUDP, Public: pub, Local: loc})
	}

	allow := opts.Allow
	if len(allow) == 0 {
		allow = []string{"127.0.0.1/32", "::1/128"}
	}

	res := &InitResult{
		Dir:        abs,
		EdgeYAML:   filepath.Join(abs, "edge.yaml"),
		AgentYAML:  filepath.Join(abs, "agent.yaml"),
		TokenFile:  filepath.Join(abs, DefaultTokenFile),
		AdminToken: filepath.Join(abs, DefaultAdminToken),
		Allowlist:  filepath.Join(abs, DefaultAllowlist),
		Token:      token,
	}
	for _, p := range []string{res.EdgeYAML, res.AgentYAML, res.TokenFile, res.AdminToken, res.Allowlist} {
		if !opts.Force {
			if _, err := os.Stat(p); err == nil {
				return nil, fmt.Errorf("%s already exists (use -force to overwrite)", p)
			}
		}
	}

	edgeBody := renderEdgeYAML(listen, tunnels)
	agentBody := renderAgentYAML(agentEdge, token)
	if err := os.WriteFile(res.EdgeYAML, []byte(edgeBody), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(res.AgentYAML, []byte(agentBody), 0o600); err != nil {
		return nil, err
	}
	if err := WriteSecretFile(res.TokenFile, token); err != nil {
		return nil, err
	}
	if err := WriteSecretFile(res.AdminToken, adminTok); err != nil {
		return nil, err
	}
	if err := writeAllowlistJSON(res.Allowlist, allow); err != nil {
		return nil, err
	}
	return res, nil
}

type initTunnel struct {
	Type   string
	Public string
	Local  string
}

func renderEdgeYAML(listen string, tunnels []initTunnel) string {
	var b strings.Builder
	b.WriteString("# fakeTunnel Edge — 由 faketunnel init 生成。未写出的项使用默认值。\n")
	if listen != DefaultListen {
		fmt.Fprintf(&b, "listen: %q\n", listen)
	}
	b.WriteString("token_file: token\n")
	b.WriteString("tunnels:\n")
	for _, t := range tunnels {
		fmt.Fprintf(&b, "  - type: %s\n", t.Type)
		fmt.Fprintf(&b, "    public: %s\n", yamlScalar(t.Public))
		fmt.Fprintf(&b, "    local: %s\n", yamlScalar(compactLocal(t.Local)))
	}
	return b.String()
}

func renderAgentYAML(edge, token string) string {
	var b strings.Builder
	b.WriteString("# fakeTunnel Agent — 拷到源站机器即可；不必再列 tunnels。\n")
	fmt.Fprintf(&b, "edge: %q\n", edge)
	fmt.Fprintf(&b, "token: %q\n", token)
	return b.String()
}

func compactLocal(local string) string {
	host, port, err := net.SplitHostPort(local)
	if err == nil && (host == "127.0.0.1" || host == "localhost") && isPort(port) {
		return port
	}
	if isPort(local) {
		return local
	}
	return local
}

func yamlScalar(s string) string {
	if isPort(s) {
		return s
	}
	return strconv.Quote(s)
}

func writeAllowlistJSON(path string, cidrs []string) error {
	var b strings.Builder
	b.WriteString("{\n  \"cidrs\": [")
	for i, c := range cidrs {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(strconv.Quote(c))
	}
	b.WriteString("]\n}\n")
	return os.WriteFile(path, []byte(b.String()), 0o600)
}

// ParseMapping parses PUBLIC[:LOCAL] used by faketunnel init flags.
//
//	8080              public :8080, local 127.0.0.1:8080
//	8080:3000         public :8080, local 127.0.0.1:3000
//	0.0.0.0:8080      public 0.0.0.0:8080, local 127.0.0.1:8080
//	127.0.0.1:8080:3000
//	0.0.0.0:8080:127.0.0.1:3000
func ParseMapping(s string) (public, local string, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", fmt.Errorf("empty mapping")
	}
	parts := strings.Split(s, ":")
	switch len(parts) {
	case 1:
		if !isPort(parts[0]) {
			return "", "", fmt.Errorf("invalid mapping %q", s)
		}
		return parts[0], "127.0.0.1:" + parts[0], nil
	case 2:
		if isPort(parts[0]) && isPort(parts[1]) {
			return parts[0], "127.0.0.1:" + parts[1], nil
		}
		if isPort(parts[1]) {
			return s, "127.0.0.1:" + parts[1], nil
		}
		return "", "", fmt.Errorf("invalid mapping %q", s)
	case 3:
		if isPort(parts[2]) {
			return parts[0] + ":" + parts[1], "127.0.0.1:" + parts[2], nil
		}
		return "", "", fmt.Errorf("invalid mapping %q", s)
	case 4:
		return parts[0] + ":" + parts[1], parts[2] + ":" + parts[3], nil
	default:
		return "", "", fmt.Errorf("invalid mapping %q", s)
	}
}
