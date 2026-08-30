package proxy

import (
	"fmt"
	"net"
	"strings"
)

var (
	loopbackV4 = mustCIDR("127.0.0.0/8")
	rfc1918a   = mustCIDR("10.0.0.0/8")
	rfc1918b   = mustCIDR("172.16.0.0/12")
	rfc1918c   = mustCIDR("192.168.0.0/16")
	ulaV6      = mustCIDR("fc00::/7")
)

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

// ValidateLocal checks host:port. When privateOnly is true, every resolved IP
// must be loopback, RFC1918, or IPv6 ULA / ::1.
func ValidateLocal(addr string, privateOnly bool) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("local address: %w", err)
	}
	if strings.TrimSpace(host) == "" {
		return fmt.Errorf("local address %q has empty host", addr)
	}
	if strings.TrimSpace(port) == "" {
		return fmt.Errorf("local address %q has empty port", addr)
	}
	ip := net.ParseIP(host)
	var ips []net.IP
	if ip != nil {
		ips = []net.IP{ip}
	} else {
		ips, err = net.LookupIP(host)
		if err != nil {
			return fmt.Errorf("resolve local %q: %w", host, err)
		}
		if len(ips) == 0 {
			return fmt.Errorf("resolve local %q: no addresses", host)
		}
	}
	for _, ip := range ips {
		if err := checkIP(ip, privateOnly); err != nil {
			return fmt.Errorf("local target %s: %w", addr, err)
		}
	}
	return nil
}

func checkIP(ip net.IP, privateOnly bool) error {
	if ip == nil {
		return fmt.Errorf("invalid ip")
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalMulticast() {
		return fmt.Errorf("%s is not a permitted destination", ip)
	}
	if !privateOnly {
		return nil
	}
	if ip.To4() != nil {
		if loopbackV4.Contains(ip) || rfc1918a.Contains(ip) || rfc1918b.Contains(ip) || rfc1918c.Contains(ip) {
			return nil
		}
		return fmt.Errorf("%s is not loopback or RFC1918 (set local_private_only: false to allow)", ip)
	}
	if ip.IsLoopback() || ulaV6.Contains(ip) {
		return nil
	}
	return fmt.Errorf("%s is not loopback or unique-local (set local_private_only: false to allow)", ip)
}

// IsPrivateOrLoopback reports whether ip is in the default local-target set.
func IsPrivateOrLoopback(ip net.IP) bool {
	return checkIP(ip, true) == nil
}
