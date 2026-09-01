package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"strings"
	"time"

	"faketunnel/internal/config"
	"faketunnel/internal/proxy"
	"faketunnel/internal/safe"
	"faketunnel/internal/tlsutil"
	"faketunnel/internal/tunnel"
)

const (
	minBackoff = 500 * time.Millisecond
	maxBackoff = 15 * time.Second
)

// Client is the local Agent: outbound-only connection to Edge.
type Client struct {
	cfg *config.File
	log *slog.Logger
	tls *tls.Config
}

// New constructs an agent client.
func New(cfg *config.File, log *slog.Logger) (*Client, error) {
	if cfg == nil {
		return nil, fmt.Errorf("nil config")
	}
	if err := cfg.ValidateAgent(); err != nil {
		return nil, err
	}
	if log == nil {
		log = slog.Default()
	}
	tlsCfg, err := tlsutil.ClientConfig(cfg.TLS.CA, cfg.TLS.ServerName, cfg.SkipVerify())
	if err != nil {
		return nil, err
	}
	if cfg.SkipVerify() && strings.TrimSpace(cfg.TLS.CA) == "" {
		log.Warn("tls.ca unset; skipping certificate verification — set tls.ca and insecure_skip_verify: false in production")
	}
	if cfg.Token == "dev-token-change-me" {
		log.Warn("using example tunnel token; replace before connecting to a public Edge")
	}
	return &Client{cfg: cfg, log: log, tls: tlsCfg}, nil
}

// Run connects and reconnects until ctx is cancelled.
func (c *Client) Run(ctx context.Context) error {
	backoff := time.Duration(0)
	for {
		established, err := c.connectOnce(ctx)
		if ctx.Err() != nil {
			c.log.Info("agent stopped")
			return ctx.Err()
		}
		if err != nil {
			c.log.Warn("tunnel disconnected", "err", err)
		}
		if established {
			// Healthy sessions should not inherit a long failure backoff.
			backoff = 0
		}
		backoff = nextBackoff(backoff)
		c.log.Info("reconnect scheduled", "wait", backoff.String())
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (c *Client) connectOnce(ctx context.Context) (bool, error) {
	d := &net.Dialer{Timeout: c.cfg.DialOrDefault()}
	tlsCfg := tlsutil.DialConfig(c.tls, c.cfg.Edge)
	c.log.Info("dialing edge", "addr", c.cfg.Edge, "sni", tlsCfg.ServerName)
	raw, err := d.DialContext(ctx, "tcp", c.cfg.Edge)
	if err != nil {
		return false, fmt.Errorf("dial: %w", err)
	}
	_ = raw.SetDeadline(time.Now().Add(c.cfg.DialOrDefault()))
	tlsConn := tls.Client(raw, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		if errors.Is(err, io.EOF) {
			return false, fmt.Errorf("tls handshake: EOF (TCP to %s ok, but peer closed TLS; edge: must be the tunnel listen port, usually 8443, not HTTP/TCP public)", c.cfg.Edge)
		}
		return false, fmt.Errorf("tls handshake: %w", err)
	}
	_ = raw.SetDeadline(time.Time{})
	conn := net.Conn(tlsConn)
	defer conn.Close()

	id := c.cfg.AgentID
	if id == "" {
		id = "agent"
	}
	if err := tunnel.ClientHandshake(conn, c.cfg.Token, id, 0); err != nil {
		return false, err
	}
	sess, err := tunnel.ClientSession(conn, c.log)
	if err != nil {
		return false, err
	}
	defer sess.Close()

	ctrl, err := sess.Open()
	if err != nil {
		return false, fmt.Errorf("open control: %w", err)
	}
	safe.Go(c.log, "control-pong", func() { _ = tunnel.ServePong(ctrl) })
	c.log.Info("connected to edge", "addr", c.cfg.Edge)

	errc := make(chan error, 1)
	safe.Go(c.log, "accept-loop", func() {
		errc <- c.acceptLoop(ctx, sess)
	})
	select {
	case <-ctx.Done():
		_ = sess.Close()
		<-errc
		return true, ctx.Err()
	case err := <-errc:
		return true, err
	}
}

func (c *Client) acceptLoop(ctx context.Context, sess *tunnel.Session) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		stream, meta, err := sess.AcceptData()
		if err != nil {
			return err
		}
		safe.Go(c.log, "stream-"+meta.Name, func() {
			c.handleStream(stream, meta)
		})
	}
}

func (c *Client) handleStream(stream net.Conn, meta tunnel.OpenMeta) {
	if meta.Proto == tunnel.ProtoUDP {
		c.handleUDPStream(stream, meta)
		return
	}
	defer stream.Close()
	local, err := c.resolveLocal(meta)
	if err != nil {
		c.log.Warn("unknown tunnel", "name", meta.Name, "err", err)
		_ = tunnel.AckData(stream, false, err.Error())
		return
	}
	if err := proxy.ValidateLocal(local, c.cfg.PrivateOnly()); err != nil {
		c.log.Warn("local target rejected", "tunnel", meta.Name, "err", err)
		_ = tunnel.AckData(stream, false, err.Error())
		return
	}
	conn, err := net.DialTimeout("tcp", local, c.cfg.DialOrDefault())
	if err != nil {
		c.log.Warn("local dial", "tunnel", meta.Name, "local", local, "err", err)
		_ = tunnel.AckData(stream, false, "dial failed")
		return
	}
	defer conn.Close()
	if err := tunnel.AckData(stream, true, "ok"); err != nil {
		return
	}
	c.log.Info("stream forwarded", "tunnel", meta.Name, "proto", meta.Proto, "local", local, "client", meta.ClientAddr)
	if err := proxy.Relay(stream, conn, c.cfg.IdleOrDefault()); err != nil {
		c.log.Debug("relay end", "tunnel", meta.Name, "err", err)
	}
}

func (c *Client) resolveLocal(meta tunnel.OpenMeta) (string, error) {
	if !c.cfg.RestrictTunnels() {
		if strings.TrimSpace(meta.Local) == "" {
			return "", fmt.Errorf("edge did not send local target")
		}
		return meta.Local, nil
	}
	tun, ok := c.cfg.TunnelByName(meta.Name)
	if !ok {
		return "", fmt.Errorf("unknown tunnel")
	}
	if strings.TrimSpace(tun.Local) != "" {
		return tun.Local, nil
	}
	if strings.TrimSpace(meta.Local) == "" {
		return "", fmt.Errorf("no local target for tunnel %q", meta.Name)
	}
	return meta.Local, nil
}

func nextBackoff(prev time.Duration) time.Duration {
	d := prev * 2
	if d < minBackoff {
		d = minBackoff
	}
	if d > maxBackoff {
		d = maxBackoff
	}
	jitter := time.Duration(rand.Int64N(int64(400 * time.Millisecond)))
	return d + jitter
}
