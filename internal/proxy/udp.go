package proxy

import (
	"fmt"
	"net"

	"mytunnel/internal/tunnel"
)

// MaxUDPPayload is the largest UDP datagram accepted for tunnel forwarding.
const MaxUDPPayload = tunnel.MaxDatagramPayload

// ResolveUDPAddr parses host:port as a UDP address.
func ResolveUDPAddr(addr string) (*net.UDPAddr, error) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("resolve udp %q: %w", addr, err)
	}
	return ua, nil
}

// DialUDPLocal dials a connected UDP socket to local after ValidateLocal.
func DialUDPLocal(local string, privateOnly bool) (*net.UDPConn, error) {
	if err := ValidateLocal(local, privateOnly); err != nil {
		return nil, err
	}
	raddr, err := ResolveUDPAddr(local)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, fmt.Errorf("dial udp %s: %w", local, err)
	}
	return conn, nil
}
