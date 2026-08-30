package edge

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"
	"time"

	"mytunnel/internal/config"
	"mytunnel/internal/netutil"
	"mytunnel/internal/proxy"
	"mytunnel/internal/safe"
	"mytunnel/internal/tlsutil"
	"mytunnel/internal/tunnel"
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
	server   *http.Server
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
		if group.tls {
			if err := s.loadHTTPCerts(hl, group); err != nil {
				_ = pln.Close()
				_ = s.closeListeners()
				return err
			}
		}
		for name := range group.names {
			s.public[name] = pln
		}
		hl.server = s.newHTTPServer(hl)
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

func (s *Server) newHTTPServer(hl *httpListener) *http.Server {
	return &http.Server{
		Handler:           s.httpHandler(hl),
		ReadHeaderTimeout: 10 * time.Second,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelDebug),
	}
}

func (s *Server) serveHTTP(ctx context.Context, hl *httpListener) {
	var err error
	if hl.tls {
		cfg := &tls.Config{
			MinVersion: tls.VersionTLS12,
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
		err = hl.server.Serve(tls.NewListener(hl.ln, cfg))
	} else {
		err = hl.server.Serve(hl.ln)
	}
	select {
	case <-ctx.Done():
		return
	default:
	}
	if err != nil && err != http.ErrServerClosed {
		s.log.Debug("http serve end", "addr", hl.public, "err", err)
	}
}

func (s *Server) httpHandler(hl *httpListener) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := netutil.IPFromAddr(r.RemoteAddr)
		if !s.acl.Allow(ip) {
			ipStr := ""
			if ip != nil {
				ipStr = ip.String()
			}
			s.reg.IncDeny()
			s.log.Warn("acl deny", "ip", ipStr, "proto", "http")
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		health := s.cfg.HealthPathOrDefault()
		if health != "" && r.URL.Path == health {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok\n"))
			return
		}

		tun, ok := lookupHTTPTunnel(hl, r)
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
		s.log.Info("http session", "tunnel", tun.Name, "host", r.Host, "client", r.RemoteAddr, "path", r.URL.Path)
		rp.ServeHTTP(w, r)
	})
}

func lookupHTTPTunnel(hl *httpListener, r *http.Request) (config.Tunnel, bool) {
	byHost := make(map[string]string, len(hl.tunnels))
	empty := ""
	for host, tun := range hl.tunnels {
		if host == "" {
			empty = tun.Name
			continue
		}
		byHost[host] = tun.Name
	}
	try := []string{r.Host}
	if r.TLS != nil && r.TLS.ServerName != "" {
		try = append(try, r.TLS.ServerName)
	}
	for _, candidate := range try {
		if name, ok := proxy.MatchHost(candidate, byHost, empty); ok {
			if tun, found := hl.byName[name]; found {
				return tun, true
			}
		}
	}
	return config.Tunnel{}, false
}

func (s *Server) shutdownHTTP() {
	var wg sync.WaitGroup
	for _, hl := range s.httpL {
		if hl.server == nil {
			continue
		}
		srv := hl.server
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), s.cfg.ShutdownOrDefault())
			defer cancel()
			_ = srv.Shutdown(ctx)
		}()
	}
	wg.Wait()
}
