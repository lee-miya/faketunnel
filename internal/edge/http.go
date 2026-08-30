package edge

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"
	"time"

	"faketunnel/internal/config"
	"faketunnel/internal/netutil"
	"faketunnel/internal/proxy"
	"faketunnel/internal/safe"
	"faketunnel/internal/tlsutil"
	"faketunnel/internal/tunnel"
)

// httpListener is one public HTTP(S) bind shared by one or more Host/SNI routes.
type httpListener struct {
	public   string
	tls      bool
	ln       net.Listener
	tunnels  map[string]config.Tunnel // normalized host -> tunnel; "" = catch-all
	byName   map[string]config.Tunnel
	certs    map[string]*tls.Certificate
	fallback *tls.Certificate
}

func (s *Server) startHTTP(ctx context.Context) error {
	groups := groupHTTPTunnels(s.cfg.HTTPTunnels())
	for public, group := range groups {
		pln, err := net.Listen("tcp", public)
		if err != nil {
			_ = s.closeListeners()
			return fmt.Errorf("listen http %s: %w", public, err)
		}
		hl := &httpListener{
			public:  public,
			tls:     group.tls,
			ln:      pln,
			tunnels: group.byHost,
			byName:  make(map[string]config.Tunnel),
			certs:   make(map[string]*tls.Certificate),
		}
		for _, tun := range group.byHost {
			hl.byName[tun.Name] = tun
		}
		if group.tls && groupNeedsTerminate(group) {
			if err := s.loadHTTPCerts(hl, group); err != nil {
				_ = pln.Close()
				_ = s.closeListeners()
				return err
			}
		}
		for name := range group.names {
			s.public[name] = pln
		}
		s.httpL = append(s.httpL, hl)

		names := make([]string, 0, len(group.names))
		for n := range group.names {
			names = append(names, n)
		}
		s.log.Info("http listen", "addr", pln.Addr().String(), "tls", group.tls, "tunnels", names)

		s.wg.Add(1)
		safe.Go(s.log, "http-"+public, func() {
			defer s.wg.Done()
			s.serveHTTP(ctx, hl)
		})
	}
	return nil
}

type httpGroup struct {
	tls    bool
	byHost map[string]config.Tunnel
	names  map[string]struct{}
}

func groupNeedsTerminate(group *httpGroup) bool {
	for _, tun := range group.byHost {
		if tun.TLS && !tun.Passthrough {
			return true
		}
	}
	return false
}

func groupHTTPTunnels(tunnels []config.Tunnel) map[string]*httpGroup {
	out := make(map[string]*httpGroup)
	for _, t := range tunnels {
		g, ok := out[t.Public]
		if !ok {
			g = &httpGroup{
				tls:    t.TLS,
				byHost: make(map[string]config.Tunnel),
				names:  make(map[string]struct{}),
			}
			out[t.Public] = g
		}
		key := proxy.NormalizeHost(t.Host)
		g.byHost[key] = t
		g.names[t.Name] = struct{}{}
	}
	return out
}

func (s *Server) loadHTTPCerts(hl *httpListener, group *httpGroup) error {
	var hosts []string
	for host := range group.byHost {
		if host != "" {
			hosts = append(hosts, host)
		}
	}
	hosts = append(hosts, "localhost", "127.0.0.1", "::1")

	edgeCert, err := tlsutil.LoadOrGenerate(s.cfg.TLS.Cert, s.cfg.TLS.Key, s.cfg.TLS.AutoSelfSigned, hosts)
	if err != nil {
		return fmt.Errorf("http tls material: %w", err)
	}
	hl.fallback = &edgeCert

	for host, tun := range group.byHost {
		if tun.Passthrough {
			continue
		}
		if tun.Cert != "" && tun.Key != "" {
			cert, err := tls.LoadX509KeyPair(tun.Cert, tun.Key)
			if err != nil {
				return fmt.Errorf("tunnel %q tls: %w", tun.Name, err)
			}
			c := cert
			if host != "" {
				hl.certs[host] = &c
			} else {
				hl.fallback = &c
			}
			continue
		}
		if host != "" {
			hl.certs[host] = &edgeCert
		}
	}
	return nil
}

func (s *Server) serveHTTP(ctx context.Context, hl *httpListener) {
	for {
		conn, err := hl.ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			s.log.Debug("http accept", "addr", hl.public, "err", err)
			return
		}
		conn, err = netutil.MaybeProxy(conn, s.cfg.ProxyProtocol)
		if err != nil {
			s.log.Warn("proxy protocol", "err", err)
			continue
		}
		s.wg.Add(1)
		safe.Go(s.log, "http-conn", func() {
			defer s.wg.Done()
			s.handleHTTPConn(hl, conn)
		})
	}
}

func (s *Server) handleHTTPConn(hl *httpListener, conn net.Conn) {
	defer func() { _ = conn.Close() }()

	ip := netutil.IPFromConn(conn)
	if !s.acl.Allow(ip) {
		ipStr := ""
		if ip != nil {
			ipStr = ip.String()
		}
		s.reg.IncDeny()
		s.log.Warn("acl deny", "ip", ipStr, "proto", "http")
		if !hl.tls {
			writeHTTPStatus(conn, http.StatusForbidden, "forbidden")
		} else {
			netutil.CloseReset(conn)
		}
		return
	}

	_ = conn.SetReadDeadline(time.Now().Add(s.cfg.DialOrDefault()))

	var sni string
	alpn := ""
	if hl.tls {
		name, hello, err := proxy.PeekClientHello(conn)
		if err != nil {
			s.log.Debug("tls peek", "addr", hl.public, "err", err)
			return
		}
		sni = name
		conn = proxy.WithPrefix(conn, hello)
		tun, ok := lookupHTTPTunnel(hl, sni)
		if !ok {
			s.log.Debug("no tunnel for sni", "sni", sni)
			return
		}
		if tun.Passthrough {
			_ = conn.SetReadDeadline(time.Time{})
			s.spliceHTTP(tun, conn, sni, "", false, true)
			return
		}
		tlsConn := tls.Server(conn, hl.tlsConfig(tun))
		if err := tlsConn.Handshake(); err != nil {
			s.log.Debug("http tls handshake", "tunnel", tun.Name, "err", err)
			return
		}
		conn = tlsConn
		cs := tlsConn.ConnectionState()
		if cs.ServerName != "" {
			sni = cs.ServerName
		}
		alpn = cs.NegotiatedProtocol
	}

	if alpn == "h2" {
		_ = conn.SetReadDeadline(time.Time{})
		tun, ok := lookupHTTPTunnel(hl, sni)
		if !ok {
			return
		}
		s.spliceHTTP(tun, conn, sni, "", true, false)
		return
	}

	head, err := proxy.PeekHTTP(conn)
	if err != nil {
		s.log.Debug("http peek", "addr", hl.public, "err", err)
		return
	}
	conn = proxy.WithPrefix(conn, head.Raw)
	_ = conn.SetReadDeadline(time.Time{})

	if head.HTTP2 {
		tun, ok := lookupHTTPTunnel(hl, head.Host, sni)
		if !ok {
			return
		}
		s.spliceHTTP(tun, conn, sni, head.Path, true, false)
		return
	}

	s.serveHTTP1(hl, conn)
}

func (s *Server) serveHTTP1(hl *httpListener, conn net.Conn) {
	done := make(chan struct{})
	var once sync.Once
	closeDone := func() { once.Do(func() { close(done) }) }
	ln := &singleConnListener{conn: conn, addr: conn.LocalAddr(), done: done}
	srv := &http.Server{
		Handler:           s.http1Handler(hl),
		ReadHeaderTimeout: 10 * time.Second,
		ConnState: func(_ net.Conn, st http.ConnState) {
			if st == http.StateClosed || st == http.StateHijacked {
				closeDone()
			}
		},
	}
	_ = srv.Serve(ln)
	closeDone()
}

func (hl *httpListener) tlsConfig(tun config.Tunnel) *tls.Config {
	next := []string{"http/1.1"}
	if tun.HTTP2 {
		next = []string{"h2", "http/1.1"}
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: next,
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			key := proxy.NormalizeHost(chi.ServerName)
			if c, ok := hl.certs[key]; ok {
				return c, nil
			}
			if hl.fallback != nil {
				return hl.fallback, nil
			}
			return nil, fmt.Errorf("no certificate for sni %q", chi.ServerName)
		},
	}
}

func (s *Server) spliceHTTP(tun config.Tunnel, conn net.Conn, sni, path string, http2, passthrough bool) {
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	default:
		s.log.Warn("max sessions reached", "tunnel", tun.Name)
		if !passthrough && !http2 {
			writeHTTPStatus(conn, http.StatusServiceUnavailable, "too many sessions")
		}
		return
	}

	sess := s.getSession()
	if sess == nil {
		s.log.Warn("no agent connected", "tunnel", tun.Name)
		if !passthrough && !http2 {
			writeHTTPStatus(conn, http.StatusBadGateway, "no agent")
		}
		return
	}

	stream, err := sess.OpenData(tunnel.OpenMeta{
		Name:       tun.Name,
		Local:      tun.Local,
		ClientAddr: conn.RemoteAddr().String(),
		Proto:      tunnel.ProtoHTTP,
	})
	if err != nil {
		s.log.Warn("http open stream", "tunnel", tun.Name, "err", err)
		if !passthrough && !http2 {
			writeHTTPStatus(conn, http.StatusBadGateway, "bad gateway")
		}
		return
	}

	s.reg.AddSessions(1)
	defer s.reg.AddSessions(-1)

	mode := "h2c"
	if passthrough {
		mode = "h2-passthrough"
	}
	s.log.Info("http session", "tunnel", tun.Name, "sni", sni, "client", conn.RemoteAddr().String(), "path", path, "mode", mode)
	if err := proxy.Relay(conn, stream, s.cfg.IdleOrDefault()); err != nil {
		s.log.Debug("http relay end", "tunnel", tun.Name, "err", err)
	}
}

func (s *Server) http1Handler(hl *httpListener) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		health := s.cfg.HealthPathOrDefault()
		if health != "" && r.URL.Path == health {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok\n"))
			return
		}

		tun, ok := lookupHTTPTunnel(hl, r.Host)
		if !ok && r.TLS != nil {
			tun, ok = lookupHTTPTunnel(hl, r.TLS.ServerName)
		}
		if !ok {
			http.Error(w, "no tunnel for host", http.StatusBadGateway)
			return
		}

		select {
		case s.sem <- struct{}{}:
			defer func() { <-s.sem }()
		default:
			s.log.Warn("max sessions reached", "tunnel", tun.Name)
			http.Error(w, "too many sessions", http.StatusServiceUnavailable)
			return
		}

		sess := s.getSession()
		if sess == nil {
			s.log.Warn("no agent connected", "tunnel", tun.Name)
			http.Error(w, "no agent", http.StatusBadGateway)
			return
		}

		s.reg.AddSessions(1)
		defer s.reg.AddSessions(-1)

		rp := &httputil.ReverseProxy{
			Director: func(req *http.Request) {
				req.URL.Scheme = "http"
				req.URL.Host = tun.Local
				if req.Host == "" {
					req.Host = tun.Local
				}
			},
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return sess.OpenData(tunnel.OpenMeta{
						Name:       tun.Name,
						Local:      tun.Local,
						ClientAddr: r.RemoteAddr,
						Proto:      tunnel.ProtoHTTP,
					})
				},
				DisableKeepAlives: true,
				ForceAttemptHTTP2: false,
			},
			ErrorHandler: func(rw http.ResponseWriter, req *http.Request, err error) {
				s.log.Warn("http proxy", "tunnel", tun.Name, "err", err)
				http.Error(rw, "bad gateway", http.StatusBadGateway)
			},
		}
		s.log.Info("http session", "tunnel", tun.Name, "host", r.Host, "client", r.RemoteAddr, "path", r.URL.Path, "mode", "http1")
		rp.ServeHTTP(w, r)
	})
}

func lookupHTTPTunnel(hl *httpListener, hosts ...string) (config.Tunnel, bool) {
	byHost := make(map[string]string, len(hl.tunnels))
	empty := ""
	for host, tun := range hl.tunnels {
		if host == "" {
			empty = tun.Name
			continue
		}
		byHost[host] = tun.Name
	}
	for _, candidate := range hosts {
		if candidate == "" {
			continue
		}
		if name, ok := proxy.MatchHost(candidate, byHost, ""); ok {
			if tun, found := hl.byName[name]; found {
				return tun, true
			}
		}
	}
	if empty != "" {
		if tun, found := hl.byName[empty]; found {
			return tun, true
		}
	}
	return config.Tunnel{}, false
}

func writeHTTPStatus(w net.Conn, status int, body string) {
	if body != "" && body[len(body)-1] != '\n' {
		body += "\n"
	}
	_, _ = fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%s",
		status, http.StatusText(status), len(body), body)
}

type singleConnListener struct {
	conn net.Conn
	addr net.Addr
	done <-chan struct{}
	once sync.Once
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() { c = l.conn })
	if c != nil {
		return c, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *singleConnListener) Close() error { return nil }

func (l *singleConnListener) Addr() net.Addr { return l.addr }

func (s *Server) shutdownHTTP() {
	// Accept loops stop when listeners close; in-flight splices drain via WaitGroup.
}
