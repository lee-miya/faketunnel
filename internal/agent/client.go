package agent

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"time"

	"mytunnel/internal/config"
	"mytunnel/internal/proxy"
	"mytunnel/internal/safe"
	"mytunnel/internal/tlsutil"
	"mytunnel/internal/tunnel"
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
	tlsCfg, err := tlsutil.ClientConfig(cfg.TLS.CA, cfg.TLS.ServerName, cfg.TLS.InsecureSkipVerify)
	if err != nil {
		return nil, err
	}
	return &Client{cfg: cfg, log: log, tls: tlsCfg}, nil
}

// Run connects and reconnects until ctx is cancelled.
func (c *Client) Run(ctx context.Context) error {
	backoff := time.Duration(0)
	for {
		err := c.connectOnce(ctx)
		if ctx.Err() != nil {
			c.log.Info("agent stopped")
			return ctx.Err()
		}
		if err != nil {
			c.log.Warn("tunnel disconnected", "err", err)
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

func (c *Client) connectOnce(ctx context.Context) error {
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: c.cfg.DialOrDefault()},
		Config:    c.tls,
	}
	c.log.Info("dialing edge", "addr", c.cfg.Edge)
	conn, err := dialer.DialContext(ctx, "tcp", c.cfg.Edge)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	id := c.cfg.AgentID
	if id == "" {
		id = "agent"
	}
	if err := tunnel.ClientHandshake(conn, c.cfg.Token, id, 0); err != nil {
		return err
	}
	sess, err := tunnel.ClientSession(conn, c.log)
	if err != nil {
		return err
	}
	defer sess.Close()

	ctrl, err := sess.Open()
	if err != nil {
		return fmt.Errorf("open control: %w", err)
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
		return ctx.Err()
	case err := <-errc:
		return err
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
	tun, ok := c.cfg.TunnelByName(meta.Name)
	if !ok {
		c.log.Warn("unknown tunnel", "name", meta.Name)
		_ = tunnel.AckData(stream, false, "unknown tunnel")
		return
	}
	local := tun.Local
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
