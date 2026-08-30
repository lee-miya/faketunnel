package netutil

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
)

const maxProxyLine = 108

// ListenHostIsLoopback reports whether a listen address (host:port) is bound
// to a loopback IP or the name "localhost". Empty or unparseable hosts are not.
func ListenHostIsLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// IPFromConn returns the remote IP, or nil if it cannot be parsed.
func IPFromConn(c net.Conn) net.IP {
	if c == nil {
		return nil
	}
	addr := c.RemoteAddr()
	if addr == nil {
		return nil
	}
	switch a := addr.(type) {
	case *net.TCPAddr:
		if a != nil && len(a.IP) > 0 {
			return a.IP
		}
	case *net.UDPAddr:
		if a != nil && len(a.IP) > 0 {
			return a.IP
		}
	}
	return IPFromAddr(addr.String())
}

// IPFromAddr parses a host:port or bare IP string into an IP.
func IPFromAddr(addr string) net.IP {
	if addr == "" {
		return nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}
	return net.ParseIP(host)
}

// CloseReset closes c so a TCP peer typically sees RST (SO_LINGER 0).
func CloseReset(c net.Conn) {
	if c == nil {
		return
	}
	cur := c
	for {
		if tc, ok := cur.(*net.TCPConn); ok {
			_ = tc.SetLinger(0)
			_ = tc.Close()
			return
		}
		if pc, ok := cur.(*proxiedConn); ok {
			cur = pc.Conn
			continue
		}
		if nc, ok := cur.(interface{ NetConn() net.Conn }); ok {
			cur = nc.NetConn()
			continue
		}
		type unwrapper interface {
			Unwrap() net.Conn
		}
		if u, ok := cur.(unwrapper); ok {
			cur = u.Unwrap()
			continue
		}
		break
	}
	_ = c.Close()
}

type proxiedConn struct {
	net.Conn
	r      *bufio.Reader
	remote *net.TCPAddr
}

func (c *proxiedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (c *proxiedConn) RemoteAddr() net.Addr {
	if c.remote != nil {
		return c.remote
	}
	return c.Conn.RemoteAddr()
}

// MaybeProxy wraps conn with PROXY protocol v1 when enabled.
// If the header is missing or invalid, the connection is closed and an error returned.
func MaybeProxy(conn net.Conn, enabled bool) (net.Conn, error) {
	if !enabled {
		return conn, nil
	}
	r := bufio.NewReaderSize(conn, maxProxyLine+1)
	line, err := readLineLimit(r, maxProxyLine)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	ip, port, err := parseProxyV1(line)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	remote := &net.TCPAddr{IP: ip, Port: port}
	if ta, ok := conn.RemoteAddr().(*net.TCPAddr); ok && port == 0 {
		remote.Port = ta.Port
	}
	return &proxiedConn{Conn: conn, r: r, remote: remote}, nil
}

func readLineLimit(r *bufio.Reader, max int) (string, error) {
	var b []byte
	for i := 0; i < max; i++ {
		c, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		b = append(b, c)
		if c == '\n' {
			return string(b), nil
		}
	}
	return "", fmt.Errorf("proxy protocol header too long")
}

func parseProxyV1(line string) (net.IP, int, error) {
	line = strings.TrimRight(line, "\r\n")
	parts := strings.Split(line, " ")
	if len(parts) < 2 || parts[0] != "PROXY" {
		return nil, 0, fmt.Errorf("invalid proxy protocol header")
	}
	if parts[1] == "UNKNOWN" {
		return nil, 0, fmt.Errorf("proxy protocol UNKNOWN (fail closed)")
	}
	if len(parts) < 6 {
		return nil, 0, fmt.Errorf("invalid proxy protocol header")
	}
	switch parts[1] {
	case "TCP4", "TCP6":
	default:
		return nil, 0, fmt.Errorf("unsupported proxy protocol family %q", parts[1])
	}
	ip := net.ParseIP(parts[2])
	if ip == nil {
		return nil, 0, fmt.Errorf("invalid proxy protocol src ip")
	}
	var port int
	if _, err := fmt.Sscanf(parts[4], "%d", &port); err != nil || port < 0 || port > 65535 {
		return nil, 0, fmt.Errorf("invalid proxy protocol src port")
	}
	return ip, port, nil
}

var _ io.Reader = (*proxiedConn)(nil)
