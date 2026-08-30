package edge

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"faketunnel/internal/acl"
	"faketunnel/internal/admin"
	"faketunnel/internal/ban"
	"faketunnel/internal/config"
	"faketunnel/internal/metrics"
	"faketunnel/internal/netutil"
	"faketunnel/internal/proxy"
	"faketunnel/internal/safe"
	"faketunnel/internal/tlsutil"
	"faketunnel/internal/tunnel"
)

// Server is the public-side Edge process.
type Server struct {
	cfg   *config.File
	store *acl.Store
	acl   *acl.List
	bans  *ban.Store
	log   *slog.Logger
	tls   *tls.Config
	cert  tls.Certificate
	reg   *metrics.Registry

	mu       sync.RWMutex
	sess     *tunnel.Session
	tunnelLn net.Listener
	public   map[string]net.Listener
	httpL    []*httpListener
	udpPC    map[string]net.PacketConn
	udpMu    sync.Mutex
	udpHubs  map[string]*udpHub
	tcpMu    sync.Mutex
	tcpConns map[net.Conn]struct{}
	sem      chan struct{}
	wg       sync.WaitGroup

	admin *admin.Server
}

// New constructs a server. Call Start or Run to listen.
func New(cfg *config.File, list *acl.List, log *slog.Logger) (*Server, error) {
	if cfg == nil {
		return nil, fmt.Errorf("nil config")
	}
	if err := cfg.ValidateEdge(); err != nil {
		return nil, err
	}
	if list == nil {
		return nil, fmt.Errorf("nil allowlist")
	}
	if log == nil {
		log = slog.Default()
	}
	store := acl.NewStore(list, cfg.AllowlistFile, log)
	bans := ban.New(cfg.DenylistFile, log)
	srv := &Server{
		cfg:    cfg,
		store:  store,
		acl:    list,
		bans:   bans,
		log:    log,
		reg:    &metrics.Registry{},
		public: make(map[string]net.Listener),
		sem:    make(chan struct{}, cfg.MaxSessionsOrDefault()),
	}
	srv.store.OnChange(srv.evictDisallowed)
	if srv.bans != nil {
		srv.bans.OnChange(srv.evictDisallowed)
	}
	return srv, nil
}

// Store returns the hot-updatable allowlist store.
func (s *Server) Store() *acl.Store { return s.store }

// Bans returns the IP strike/ban store.
func (s *Server) Bans() *ban.Store { return s.bans }

// Metrics returns the runtime metrics registry.
func (s *Server) Metrics() *metrics.Registry { return s.reg }

// AdminAddr returns the bound Admin API address (empty if disabled).
func (s *Server) AdminAddr() string {
	if s.admin == nil {
		return ""
	}
	return s.admin.Addr()
}

// Start opens listeners and accept loops. It returns once they are bound.
func (s *Server) Start(ctx context.Context) error {
	cert, err := tlsutil.LoadOrGenerate(s.cfg.TLS.Cert, s.cfg.TLS.Key, s.cfg.TLS.AutoSelfSigned, []string{"localhost", "127.0.0.1", "::1"})
	if err != nil {
		return err
	}
	s.tls = tlsutil.ServerConfig(cert)
	s.cert = cert

	if s.cfg.Token == "dev-token-change-me" {
		s.log.Warn("using example tunnel token; replace before exposing Edge on a public network")
	}

	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen tunnel %s: %w", s.cfg.Listen, err)
	}
	s.tunnelLn = ln
	s.log.Info("tunnel listen", "addr", ln.Addr().String())

	for _, t := range s.cfg.Tunnels {
		switch t.Type {
		case config.TypeTCP, config.TypeHTTP, config.TypeUDP:
		default:
			s.log.Warn("skipping tunnel (unknown type)", "name", t.Name, "type", t.Type)
		}
	}
	for _, t := range s.cfg.TCPTunnels() {
		pln, err := net.Listen("tcp", t.Public)
		if err != nil {
			_ = s.closeListeners()
			return fmt.Errorf("listen public %s: %w", t.Public, err)
		}
		s.public[t.Name] = pln
		s.log.Info("tcp listen", "tunnel", t.Name, "addr", pln.Addr().String(), "local", t.Local)
		tun := t
		s.wg.Add(1)
		safe.Go(s.log, "public-"+tun.Name, func() {
			defer s.wg.Done()
			s.servePublic(ctx, tun, pln)
		})
	}
	if err := s.startHTTP(ctx); err != nil {
		return err
	}
	if err := s.startUDP(ctx); err != nil {
		return err
	}
	if err := s.startAdmin(); err != nil {
		_ = s.closeListeners()
		return err
	}

	s.wg.Add(1)
	safe.Go(s.log, "tunnel-accept", func() {
		defer s.wg.Done()
		s.serveTunnel(ctx)
	})
	return nil
}

func (s *Server) startAdmin() error {
	if !s.cfg.AdminEnabled() {
		return nil
	}
	cfg := admin.Config{
		Listen:  s.cfg.Admin.Listen,
		Token:   s.cfg.Admin.Token,
		Metrics: s.cfg.AdminMetricsOrDefault(),
		Bans:    s.bans,
	}
	public := !netutil.ListenHostIsLoopback(s.cfg.Admin.Listen)
	if public {
		cfg.TLS = tlsutil.HTTPSConfig(s.cert)
	}
	adm, err := admin.New(cfg, s.store, s.reg, s.status, s.log)
	if err != nil {
		return err
	}
	if err := adm.Start(); err != nil {
		return err
	}
	s.admin = adm
	if public {
		s.log.Warn("admin is on a non-loopback address; use HTTPS and keep the Bearer token secret")
	}
	if s.cfg.Admin.Token == config.ExampleAdminToken {
		s.log.Warn("using example admin token; replace before production")
	}
	return nil
}

func (s *Server) status() metrics.Status {
	st := s.reg.Snapshot()
	st.TempBans, st.PermanentBans = s.bans.Counts()
	return st
}

// Run starts listeners and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	if err := s.Start(ctx); err != nil {
		return err
	}
	<-ctx.Done()
	return s.Shutdown()
}

// Shutdown stops listeners, closes the agent session, and drains handlers.
func (s *Server) Shutdown() error {
	if s.admin != nil {
		_ = s.admin.Shutdown()
	}
	s.shutdownHTTP()
	s.closeTCPConns()
	s.closeUDPHubs()
	_ = s.closeListeners()
	s.mu.Lock()
	sess := s.sess
	s.sess = nil
	s.mu.Unlock()
	if sess != nil {
		_ = sess.Close()
	}
	s.reg.SetAgentConnected(false)
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(s.cfg.ShutdownOrDefault()):
		s.log.Warn("shutdown drain timeout")
	}
	s.log.Info("edge stopped")
	return nil
}

func (s *Server) isAllowed(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if s.bans != nil && s.bans.Blocked(ip) {
		return false
	}
	if s.acl != nil && s.acl.Allow(ip) {
		return true
	}
	return false
}

func (s *Server) evictDisallowed() {
	s.evictTCPConns()
	s.evictHTTPConns()
	s.evictUDPAssocs()
}

func (s *Server) evictTCPConns() {
	s.tcpMu.Lock()
	var toClose []net.Conn
	for c := range s.tcpConns {
		ip := netutil.IPFromConn(c)
		if !s.isAllowed(ip) {
			toClose = append(toClose, c)
		}
	}
	s.tcpMu.Unlock()
	for _, c := range toClose {
		s.log.Info("tcp conn evicted (acl/ban)", "remote", c.RemoteAddr().String())
		netutil.CloseReset(c)
	}
}

func (s *Server) evictHTTPConns() {
	s.mu.RLock()
	httpL := append([]*httpListener(nil), s.httpL...)
	s.mu.RUnlock()
	for _, hl := range httpL {
		hl.evictDisallowed(s.isAllowed)
	}
}

func (s *Server) evictUDPAssocs() {
	s.udpMu.Lock()
	hubs := make([]*udpHub, 0, len(s.udpHubs))
	for _, h := range s.udpHubs {
		if h != nil {
			hubs = append(hubs, h)
		}
	}
	s.udpMu.Unlock()
	for _, h := range hubs {
		h.evictDisallowed(s.isAllowed)
	}
}

func (s *Server) trackTCP(c net.Conn, add bool) {
	s.tcpMu.Lock()
	defer s.tcpMu.Unlock()
	if s.tcpConns == nil {
		s.tcpConns = make(map[net.Conn]struct{})
	}
	if add {
		s.tcpConns[c] = struct{}{}
	} else {
		delete(s.tcpConns, c)
	}
}

func (s *Server) closeTCPConns() {
	s.tcpMu.Lock()
	defer s.tcpMu.Unlock()
	for c := range s.tcpConns {
		_ = c.Close()
	}
	s.tcpConns = nil
}

func (s *Server) closeListeners() error {
	var first error
	if s.tunnelLn != nil {
		if err := s.tunnelLn.Close(); err != nil && first == nil {
			first = err
		}
	}
	for _, ln := range s.public {
		if err := ln.Close(); err != nil && first == nil {
			first = err
		}
	}
	for _, pc := range s.udpPC {
		if err := pc.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// TunnelAddr is the bound tunnel listen address.
func (s *Server) TunnelAddr() string {
	if s.tunnelLn == nil {
		return ""
	}
	return s.tunnelLn.Addr().String()
}

// PublicAddr is the bound public address for a named tunnel (TCP/HTTP/UDP).
func (s *Server) PublicAddr(name string) string {
	if ln := s.public[name]; ln != nil {
		return ln.Addr().String()
	}
	if pc := s.udpPC[name]; pc != nil {
		return pc.LocalAddr().String()
	}
	return ""
}

func (s *Server) setSession(sess *tunnel.Session) {
	s.closeUDPHubs()
	s.mu.Lock()
	old := s.sess
	s.sess = sess
	s.mu.Unlock()
	if old != nil && old != sess {
		_ = old.Close()
	}
	s.reg.SetAgentConnected(true)
	s.log.Info("agent session ready")
	safe.Go(s.log, "session-watch", func() {
		<-sess.CloseChan()
		s.mu.Lock()
		if s.sess == sess {
			s.sess = nil
		}
		s.mu.Unlock()
		s.closeUDPHubs()
		s.reg.SetAgentConnected(false)
		s.log.Info("agent disconnected")
	})
}

func (s *Server) getSession() *tunnel.Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.sess == nil || s.sess.IsClosed() {
		return nil
	}
	return s.sess
}

func (s *Server) serveTunnel(ctx context.Context) {
	ln := tls.NewListener(s.tunnelLn, s.tls)
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			s.log.Debug("tunnel accept", "err", err)
			return
		}
		s.wg.Add(1)
		safe.Go(s.log, "agent-conn", func() {
			defer s.wg.Done()
			s.handleAgent(conn)
		})
	}
}

func (s *Server) handleAgent(conn net.Conn) {
	defer conn.Close()
	agentID, err := tunnel.ServerHandshake(conn, s.cfg.Token, 0)
	if err != nil {
		s.log.Warn("agent handshake failed", "remote", conn.RemoteAddr().String(), "err", err)
		return
	}
	sess, err := tunnel.ServerSession(conn, s.log)
	if err != nil {
		s.log.Warn("yamux server", "err", err)
		return
	}
	defer sess.Close()

	timer := time.AfterFunc(10*time.Second, func() { _ = sess.Close() })
	ctrl, err := sess.Accept()
	timer.Stop()
	if err != nil {
		s.log.Warn("control stream", "err", err)
		return
	}
	// Edge initiates Ping so RTT is measured where metrics live.
	safe.Go(s.log, "control-ping", func() {
		_ = tunnel.RunPing(ctrl, 0, func(rtt time.Duration) {
			s.reg.ObserveRTT(rtt)
			s.log.Debug("tunnel rtt", "rtt", rtt.String())
		})
	})
	s.log.Info("agent connected", "agent_id", agentID, "remote", conn.RemoteAddr().String())
	s.setSession(sess)
	<-sess.CloseChan()
}

func (s *Server) servePublic(ctx context.Context, tun config.Tunnel, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			s.log.Debug("public accept", "tunnel", tun.Name, "err", err)
			return
		}
		conn, err = netutil.MaybeProxy(conn, s.cfg.ProxyProtocol)
		if err != nil {
			s.log.Warn("proxy protocol", "err", err)
			continue
		}
		s.trackTCP(conn, true)
		s.wg.Add(1)
		safe.Go(s.log, "public-conn", func() {
			defer func() {
				s.trackTCP(conn, false)
				s.wg.Done()
			}()
			s.handlePublic(tun, conn)
		})
	}
}

func (s *Server) handlePublic(tun config.Tunnel, conn net.Conn) {
	defer func() { _ = conn.Close() }()
	ip := netutil.IPFromConn(conn)
	if !s.publicAllowed(ip, "tcp", tun.Name) {
		netutil.CloseReset(conn)
		return
	}
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	default:
		s.log.Warn("max sessions reached", "tunnel", tun.Name)
		return
	}
	sess := s.getSession()
	if sess == nil {
		s.log.Warn("no agent connected", "tunnel", tun.Name)
		return
	}
	stream, err := sess.OpenData(tunnel.OpenMeta{
		Name:       tun.Name,
		Local:      tun.Local,
		ClientAddr: conn.RemoteAddr().String(),
		Proto:      tunnel.ProtoTCP,
	})
	if err != nil {
		s.log.Warn("open stream", "tunnel", tun.Name, "err", err)
		return
	}
	s.reg.AddSessions(1)
	defer s.reg.AddSessions(-1)
	s.log.Info("tcp session", "tunnel", tun.Name, "client", conn.RemoteAddr().String())
	if err := proxy.Relay(conn, stream, s.cfg.IdleOrDefault()); err != nil {
		s.log.Debug("relay end", "tunnel", tun.Name, "err", err)
	}
}

func (s *Server) publicAllowed(ip net.IP, proto, tunnel string) bool {
	if s.bans != nil && s.bans.Blocked(ip) {
		s.reg.IncDeny()
		ipStr := ""
		if ip != nil {
			ipStr = ip.String()
		}
		s.log.Debug("ip banned", "ip", ipStr, "proto", proto, "tunnel", tunnel, "kind", s.bans.Kind(ip))
		return false
	}
	if s.acl.Allow(ip) {
		s.bans.ObserveValid(ip)
		return true
	}
	s.reg.IncDeny()
	ipStr := ""
	if ip != nil {
		ipStr = ip.String()
	}
	s.log.Warn("acl deny", "ip", ipStr, "proto", proto, "tunnel", tunnel)
	s.bans.ObserveInvalid(ip, "acl")
	return false
}
