package admin

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"faketunnel/internal/acl"
	"faketunnel/internal/ban"
	"faketunnel/internal/metrics"
	"faketunnel/internal/netutil"
)

const maxBody = 1 << 20

// Config is Admin HTTP listener settings.
type Config struct {
	Listen  string
	Token   string
	Metrics bool
	TLS     *tls.Config // nil = plaintext HTTP (loopback)
	Bans    *ban.Store
}

// StatusFunc returns Edge runtime status for GET /v1/status.
type StatusFunc func() metrics.Status

// Server is the management HTTP API (Bearer token).
type Server struct {
	cfg    Config
	store  *acl.Store
	reg    *metrics.Registry
	status StatusFunc
	log    *slog.Logger
	http   *http.Server
	ln     net.Listener
}

// New builds an Admin server. Call Start to listen.
func New(cfg Config, store *acl.Store, reg *metrics.Registry, status StatusFunc, log *slog.Logger) (*Server, error) {
	if strings.TrimSpace(cfg.Listen) == "" {
		return nil, fmt.Errorf("admin listen is empty")
	}
	if strings.TrimSpace(cfg.Token) == "" {
		return nil, fmt.Errorf("admin token is required")
	}
	if store == nil {
		return nil, fmt.Errorf("nil allowlist store")
	}
	if log == nil {
		log = slog.Default()
	}
	if reg == nil {
		reg = &metrics.Registry{}
	}
	if status == nil {
		status = reg.Snapshot
	}
	s := &Server{cfg: cfg, store: store, reg: reg, status: status, log: log}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/allowlist", s.handleAllowlist)
	mux.HandleFunc("/v1/allowlist/self", s.handleAllowSelf)
	mux.HandleFunc("/v1/denylist", s.handleDenylist)
	mux.HandleFunc("/v1/status", s.handleStatus)
	if cfg.Metrics {
		mux.HandleFunc("/metrics", s.handleMetrics)
	}
	s.http = &http.Server{
		Handler:           s.auth(mux),
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 16,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelDebug),
	}
	return s, nil
}

// Start binds the listen address and serves in the background.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("admin listen %s: %w", s.cfg.Listen, err)
	}
	s.ln = ln
	scheme := "http"
	if s.cfg.TLS != nil {
		ln = tls.NewListener(ln, s.cfg.TLS)
		s.ln = ln
		scheme = "https"
	}
	s.log.Info("admin listen", "addr", ln.Addr().String(), "metrics", s.cfg.Metrics, "tls", s.cfg.TLS != nil, "scheme", scheme)
	go func() {
		if err := s.http.Serve(ln); err != nil && err != http.ErrServerClosed {
			s.log.Debug("admin serve end", "err", err)
		}
	}()
	return nil
}

// Addr returns the bound address.
func (s *Server) Addr() string {
	if s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

// Shutdown stops the Admin HTTP server.
func (s *Server) Shutdown() error {
	if s.http == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.http.Shutdown(ctx)
}

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := netutil.IPFromAddr(r.RemoteAddr)
		if !bearerOK(r.Header.Get("Authorization"), s.cfg.Token) {
			if s.cfg.Bans != nil && s.cfg.Bans.Blocked(ip) {
				s.log.Debug("admin blocked banned ip", "remote", r.RemoteAddr, "path", r.URL.Path)
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			s.log.Warn("admin auth failed", "remote", r.RemoteAddr, "path", r.URL.Path)
			if s.cfg.Bans != nil {
				s.cfg.Bans.ObserveInvalid(ip, "admin")
			}
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func bearerOK(hdr, token string) bool {
	const p = "Bearer "
	if !strings.HasPrefix(hdr, p) {
		return false
	}
	got := strings.TrimSpace(strings.TrimPrefix(hdr, p))
	if got == "" || token == "" {
		return false
	}
	if len(got) != len(token) {
		// still compare via subtle? keep simple constant-ish via Equal
	}
	return subtleEqual(got, token)
}

func subtleEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

type allowlistDTO struct {
	CIDRs []string `json:"cidrs"`
	CIDR  string   `json:"cidr,omitempty"`
}

func (s *Server) handleAllowlist(w http.ResponseWriter, r *http.Request) {
	actor := actorFrom(r)
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, allowlistDTO{CIDRs: s.store.Entries()})
	case http.MethodPut:
		body, err := readDTO(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.store.Replace(body.CIDRs, actor); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.unbanListed(body.CIDRs, actor)
		writeJSON(w, http.StatusOK, allowlistDTO{CIDRs: s.store.Entries()})
	case http.MethodPost:
		body, err := readDTO(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		cidrs := body.CIDRs
		if body.CIDR != "" {
			cidrs = append(cidrs, body.CIDR)
		}
		if len(cidrs) == 0 {
			http.Error(w, "cidr or cidrs required", http.StatusBadRequest)
			return
		}
		if err := s.store.Add(cidrs, actor); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.unbanListed(cidrs, actor)
		writeJSON(w, http.StatusOK, allowlistDTO{CIDRs: s.store.Entries()})
	case http.MethodDelete:
		cidrs := append([]string(nil), r.URL.Query()["cidr"]...)
		if r.Body != nil && r.ContentLength != 0 {
			body, err := readDTO(r)
			if err == nil {
				cidrs = append(cidrs, body.CIDRs...)
				if body.CIDR != "" {
					cidrs = append(cidrs, body.CIDR)
				}
			} else if len(cidrs) == 0 {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		if len(cidrs) == 0 {
			http.Error(w, "cidr query or body required", http.StatusBadRequest)
			return
		}
		if err := s.store.Remove(cidrs, actor); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, allowlistDTO{CIDRs: s.store.Entries()})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, s.status())
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_ = metrics.WriteStatus(w, s.status())
}

func (s *Server) handleAllowSelf(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := netutil.IPFromAddr(r.RemoteAddr)
	if ip == nil {
		http.Error(w, "cannot parse client ip", http.StatusBadRequest)
		return
	}
	cidr := ip.String() + "/32"
	if ip.To4() == nil {
		cidr = ip.String() + "/128"
	}
	actor := actorFrom(r)
	if err := s.store.Add([]string{cidr}, actor); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.unbanListed([]string{cidr}, actor)
	writeJSON(w, http.StatusOK, allowlistDTO{CIDRs: s.store.Entries(), CIDR: cidr})
}

func (s *Server) handleDenylist(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Bans == nil {
		http.Error(w, "denylist unavailable", http.StatusNotImplemented)
		return
	}
	actor := actorFrom(r)
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"entries": s.cfg.Bans.List()})
	case http.MethodDelete:
		ips := append([]string(nil), r.URL.Query()["ip"]...)
		if r.Body != nil && r.ContentLength != 0 {
			var body struct {
				IPs []string `json:"ips"`
				IP  string   `json:"ip"`
			}
			data, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
			if err == nil && len(strings.TrimSpace(string(data))) > 0 {
				if err := json.Unmarshal(data, &body); err != nil {
					http.Error(w, "json: "+err.Error(), http.StatusBadRequest)
					return
				}
				ips = append(ips, body.IPs...)
				if body.IP != "" {
					ips = append(ips, body.IP)
				}
			}
		}
		if len(ips) == 0 {
			http.Error(w, "ip query or body required", http.StatusBadRequest)
			return
		}
		for _, raw := range ips {
			ip := net.ParseIP(strings.TrimSpace(raw))
			if ip == nil {
				http.Error(w, "invalid ip "+raw, http.StatusBadRequest)
				return
			}
			if err := s.cfg.Bans.Unban(ip, actor); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"entries": s.cfg.Bans.List()})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) unbanListed(cidrs []string, actor string) {
	if s.cfg.Bans == nil {
		return
	}
	s.cfg.Bans.UnbanCIDRs(cidrs, actor)
}

func readDTO(r *http.Request) (allowlistDTO, error) {
	defer r.Body.Close()
	data, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if err != nil {
		return allowlistDTO{}, err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return allowlistDTO{}, fmt.Errorf("empty body")
	}
	var dto allowlistDTO
	if err := json.Unmarshal(data, &dto); err != nil {
		return allowlistDTO{}, fmt.Errorf("json: %w", err)
	}
	return dto, nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func actorFrom(r *http.Request) string {
	if a := strings.TrimSpace(r.Header.Get("X-Admin-Actor")); a != "" {
		return a
	}
	return r.RemoteAddr
}
