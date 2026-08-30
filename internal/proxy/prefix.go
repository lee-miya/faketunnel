package proxy

import "net"

// PrefixConn replays prefix bytes before reading from the underlying conn.
type PrefixConn struct {
	net.Conn
	prefix []byte
}

// WithPrefix returns c unchanged when prefix is empty.
func WithPrefix(c net.Conn, prefix []byte) net.Conn {
	if len(prefix) == 0 {
		return c
	}
	p := make([]byte, len(prefix))
	copy(p, prefix)
	return &PrefixConn{Conn: c, prefix: p}
}

func (c *PrefixConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		if len(c.prefix) == 0 {
			c.prefix = nil
		}
		return n, nil
	}
	return c.Conn.Read(p)
}
