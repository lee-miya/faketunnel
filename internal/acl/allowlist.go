package acl

import (
	"fmt"
	"net"
	"strings"
	"sync"
)

// List is a thread-safe IP/CIDR allowlist. Default policy is deny.
type List struct {
	mu      sync.RWMutex
	entries []string
	nets    []*net.IPNet
}

// New builds a list from CIDR or bare IP strings. An empty input denies all.
func New(cidrs []string) (*List, error) {
	l := &List{}
	if err := l.Replace(cidrs); err != nil {
		return nil, err
	}
	return l, nil
}

// Replace atomically swaps the in-memory set. On parse error the previous set is kept.
func (l *List) Replace(cidrs []string) error {
	entries, nets, err := parseAll(cidrs)
	if err != nil {
		return err
	}
	l.mu.Lock()
	l.entries = entries
	l.nets = nets
	l.mu.Unlock()
	return nil
}

// Allow reports whether ip is permitted. Unknown or unspecified addresses are denied.
func (l *List) Allow(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() {
		return false
	}
	ip = normalizeIP(ip)
	l.mu.RLock()
	defer l.mu.RUnlock()
	for _, n := range l.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Entries returns a copy of the configured CIDR/IP strings.
func (l *List) Entries() []string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]string, len(l.entries))
	copy(out, l.entries)
	return out
}

// Len returns the number of entries.
func (l *List) Len() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.entries)
}

func parseAll(cidrs []string) ([]string, []*net.IPNet, error) {
	entries := make([]string, 0, len(cidrs))
	nets := make([]*net.IPNet, 0, len(cidrs))
	for i, raw := range cidrs {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		n, err := ParseCIDR(s)
		if err != nil {
			return nil, nil, fmt.Errorf("allowlist entry %d %q: %w", i, s, err)
		}
		entries = append(entries, s)
		nets = append(nets, n)
	}
	return entries, nets, nil
}

// ParseCIDR accepts a CIDR or a bare IP (IPv4 → /32, IPv6 → /128).
func ParseCIDR(s string) (*net.IPNet, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty cidr")
	}
	if strings.Contains(s, "/") {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, err
		}
		return canonicalizeNet(n), nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, fmt.Errorf("invalid ip or cidr")
	}
	if v4 := ip.To4(); v4 != nil {
		return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}, nil
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
}

func canonicalizeNet(n *net.IPNet) *net.IPNet {
	if n == nil {
		return nil
	}
	if v4 := n.IP.To4(); v4 != nil {
		ones, _ := n.Mask.Size()
		if len(n.Mask) == net.IPv6len {
			// IPv4-mapped prefix; keep IPv4 form when mask is equivalent.
			if ones >= 96 {
				return &net.IPNet{IP: v4, Mask: net.CIDRMask(ones-96, 32)}
			}
		}
		return &net.IPNet{IP: v4, Mask: n.Mask}
	}
	return n
}

func normalizeIP(ip net.IP) net.IP {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip
}
