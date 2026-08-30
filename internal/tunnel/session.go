package tunnel

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/hashicorp/yamux"
)

const (
	PingInterval = 15 * time.Second
	PingTimeout  = 45 * time.Second
	OpenTimeout  = 15 * time.Second
)

// Session is a yamux session on an authenticated TLS connection.
type Session struct {
	mux    *yamux.Session
	logger *slog.Logger
}

func muxConfig() *yamux.Config {
	c := yamux.DefaultConfig()
	c.EnableKeepAlive = true
	c.KeepAliveInterval = 30 * time.Second
	c.LogOutput = io.Discard
	return c
}

// ServerSession wraps a connection Edge accepted (yamux server).
func ServerSession(conn net.Conn, logger *slog.Logger) (*Session, error) {
	if logger == nil {
		logger = slog.Default()
	}
	mux, err := yamux.Server(conn, muxConfig())
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
	mux, err := yamux.Client(conn, muxConfig())
	if err != nil {
		return nil, err
	}
	return &Session{mux: mux, logger: logger}, nil
}

func (s *Session) Open() (net.Conn, error) { return s.mux.Open() }

func (s *Session) Accept() (net.Conn, error) { return s.mux.Accept() }

func (s *Session) Close() error { return s.mux.Close() }

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
