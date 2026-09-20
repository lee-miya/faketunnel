package tunnel

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
)

const (
	PingInterval = 15 * time.Second
	PingTimeout  = 45 * time.Second
	OpenTimeout  = 15 * time.Second

	// closeWait is how long Session.Close waits for yamux/TLS teardown.
	// A blocked tls.Conn.Close used to stall Agent reconnect for minutes.
	closeWait = 2 * time.Second

	tcpKeepAlivePeriod = 30 * time.Second
)

// Session is a yamux session on an authenticated TLS connection.
type Session struct {
	mux    *yamux.Session
	logger *slog.Logger
}

func muxConfig() *yamux.Config {
	c := yamux.DefaultConfig()
	// Yamux keepalive Ping shares the multiplexer's send loop. A large HTTP
	// body (Gitea git pack / page assets) can occupy that loop longer than
	// the default 10s ConnectionWriteTimeout; the ping then fails and yamux
	// tears down the whole tunnel. Application Ping/Pong still measures RTT;
	// TCP keepalive detects a dead peer.
	c.EnableKeepAlive = false
	c.KeepAliveInterval = 30 * time.Second
	c.ConnectionWriteTimeout = 5 * time.Minute
	c.MaxStreamWindowSize = 1 << 20
	c.StreamOpenTimeout = 0
	c.StreamCloseTimeout = 10 * time.Second
	c.LogOutput = io.Discard
	return c
}

func prepareMuxConn(conn net.Conn) net.Conn {
	enableTCPKeepAlive(conn)
	return &fastCloseConn{Conn: conn}
}

func enableTCPKeepAlive(conn net.Conn) {
	cur := conn
	for i := 0; i < 8 && cur != nil; i++ {
		if tc, ok := cur.(*net.TCPConn); ok {
			_ = tc.SetKeepAlive(true)
			_ = tc.SetKeepAlivePeriod(tcpKeepAlivePeriod)
			return
		}
		nc, ok := cur.(interface{ NetConn() net.Conn })
		if !ok {
			return
		}
		cur = nc.NetConn()
	}
}

// fastCloseConn sets an expired deadline before Close so an in-flight TLS
// write cannot deadlock session teardown.
type fastCloseConn struct {
	net.Conn
	once sync.Once
	err  error
}

func (c *fastCloseConn) Close() error {
	c.once.Do(func() {
		_ = c.Conn.SetDeadline(time.Now())
		c.err = c.Conn.Close()
	})
	return c.err
}

func (c *fastCloseConn) NetConn() net.Conn {
	if nc, ok := c.Conn.(interface{ NetConn() net.Conn }); ok {
		return nc.NetConn()
	}
	return c.Conn
}

// ServerSession wraps a connection Edge accepted (yamux server).
func ServerSession(conn net.Conn, logger *slog.Logger) (*Session, error) {
	if logger == nil {
		logger = slog.Default()
	}
	mux, err := yamux.Server(prepareMuxConn(conn), muxConfig())
	if err != nil {
		return nil, err
	}
	return &Session{mux: mux, logger: logger}, nil
}

// ClientSession wraps a connection Agent dialed (yamux client).
func ClientSession(conn net.Conn, logger *slog.Logger) (*Session, error) {
	if logger == nil {
		logger = slog.Default()
	}
	mux, err := yamux.Client(prepareMuxConn(conn), muxConfig())
	if err != nil {
		return nil, err
	}
	return &Session{mux: mux, logger: logger}, nil
}

func (s *Session) Open() (net.Conn, error) { return s.mux.Open() }

func (s *Session) Accept() (net.Conn, error) { return s.mux.Accept() }

func (s *Session) Close() error {
	done := make(chan error, 1)
	go func() {
		done <- s.mux.Close()
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(closeWait):
		return nil
	}
}

func (s *Session) IsClosed() bool { return s.mux.IsClosed() }

func (s *Session) CloseChan() <-chan struct{} { return s.mux.CloseChan() }

func (s *Session) NumStreams() int { return s.mux.NumStreams() }

// OpenData opens a yamux stream, writes OpenMeta, and waits for OpenAck.
func (s *Session) OpenData(meta OpenMeta) (net.Conn, error) {
	stream, err := s.mux.Open()
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = stream.Close()
		}
	}()
	payload, err := meta.Marshal()
	if err != nil {
		return nil, err
	}
	_ = stream.SetDeadline(time.Now().Add(OpenTimeout))
	if err := WriteFrame(stream, TypeOpenStream, payload); err != nil {
		return nil, err
	}
	fr, err := ReadFrame(stream)
	if err != nil {
		return nil, fmt.Errorf("read open ack: %w", err)
	}
	_ = stream.SetDeadline(time.Time{})
	if fr.Type != TypeOpenStreamAck {
		return nil, fmt.Errorf("expected OpenStreamAck, got %s", fr.Type)
	}
	ack, err := ParseOpenAck(fr.Payload)
	if err != nil {
		return nil, err
	}
	if !ack.OK {
		if ack.Message == "" {
			return nil, fmt.Errorf("agent rejected stream")
		}
		return nil, fmt.Errorf("agent rejected stream: %s", ack.Message)
	}
	ok = true
	return stream, nil
}

// AcceptData accepts a yamux stream and reads OpenMeta.
func (s *Session) AcceptData() (net.Conn, OpenMeta, error) {
	stream, err := s.mux.Accept()
	if err != nil {
		return nil, OpenMeta{}, err
	}
	_ = stream.SetDeadline(time.Now().Add(OpenTimeout))
	fr, err := ReadFrame(stream)
	if err != nil {
		_ = stream.Close()
		return nil, OpenMeta{}, err
	}
	if fr.Type != TypeOpenStream {
		_ = stream.Close()
		return nil, OpenMeta{}, fmt.Errorf("expected OpenStream, got %s", fr.Type)
	}
	meta, err := ParseOpenMeta(fr.Payload)
	if err != nil {
		_ = stream.Close()
		return nil, OpenMeta{}, err
	}
	_ = stream.SetDeadline(time.Time{})
	return stream, meta, nil
}

// AckData writes OpenAck on a data stream. Deadline should already be cleared
// or set by the caller around dial.
func AckData(stream net.Conn, ok bool, msg string) error {
	payload, err := (OpenAck{OK: ok, Message: msg}).Marshal()
	if err != nil {
		return err
	}
	_ = stream.SetDeadline(time.Now().Add(OpenTimeout))
	err = WriteFrame(stream, TypeOpenStreamAck, payload)
	_ = stream.SetDeadline(time.Time{})
	return err
}

// ServePong replies to Ping frames until the stream fails.
func ServePong(stream net.Conn) error {
	defer stream.Close()
	for {
		_ = stream.SetReadDeadline(time.Now().Add(PingTimeout))
		fr, err := ReadFrame(stream)
		if err != nil {
			return err
		}
		if fr.Type != TypePing {
			continue
		}
		_ = stream.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if err := WriteFrame(stream, TypePong, fr.Payload); err != nil {
			return err
		}
	}
}

// PingObserver is called after each successful Ping/Pong round-trip.
type PingObserver func(rtt time.Duration)

// RunPing sends Ping frames and waits for Pong until the stream fails.
func RunPing(stream net.Conn, interval time.Duration, obs PingObserver) error {
	defer stream.Close()
	if interval <= 0 {
		interval = PingInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	if err := sendPingWaitPong(stream, obs); err != nil {
		return err
	}
	for range ticker.C {
		if err := sendPingWaitPong(stream, obs); err != nil {
			return err
		}
	}
	return nil
}

func sendPingWaitPong(stream net.Conn, obs PingObserver) error {
	start := time.Now()
	nsec := start.UnixNano()
	_ = stream.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := WriteFrame(stream, TypePing, PingPayload(nsec)); err != nil {
		return err
	}
	_ = stream.SetReadDeadline(time.Now().Add(PingTimeout))
	fr, err := ReadFrame(stream)
	if err != nil {
		return err
	}
	if fr.Type != TypePong {
		return fmt.Errorf("expected Pong, got %s", fr.Type)
	}
	if obs != nil {
		obs(time.Since(start))
	}
	return nil
}
