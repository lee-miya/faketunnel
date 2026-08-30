package ban

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	// InvalidLimit is consecutive invalid events before a ban is issued.
	InvalidLimit = 5
	// TempDuration is how long a first ban lasts.
	TempDuration  = 6 * time.Hour
	KindTemporary = "temporary"
	KindPermanent = "permanent"
)

type record struct {
	Consecutive int       `json:"consecutive"`
	Bans        int       `json:"bans"`
	Until       time.Time `json:"until,omitempty"`
	Permanent   bool      `json:"permanent"`
}

type fileDTO struct {
	Records map[string]record `json:"records"`
}

// Store tracks consecutive invalid events per IP and persists bans.
type Store struct {
	mu    sync.Mutex
	path  string
	log   *slog.Logger
	now   func() time.Time
	ttl   time.Duration
	limit int
	byIP  map[string]*record
}

// New loads denylist from path (missing file is empty). Empty path is memory-only.
func New(path string, log *slog.Logger) *Store {
	if log == nil {
		log = slog.Default()
	}
	s := &Store{
		path:  path,
		log:   log,
		now:   time.Now,
		ttl:   TempDuration,
		limit: InvalidLimit,
		byIP:  make(map[string]*record),
	}
	if err := s.load(); err != nil {
		log.Warn("denylist not loaded", "path", path, "err", err)
	}
	return s
}

// Blocked reports whether ip is currently temp or permanently banned.
func (s *Store) Blocked(ip net.IP) bool {
	if s == nil {
		return false
	}
	key := ipKey(ip)
	if key == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.blockedLocked(key, s.now())
}

func (s *Store) blockedLocked(key string, now time.Time) bool {
	r := s.byIP[key]
	if r == nil {
		return false
	}
	if r.Permanent {
		return true
	}
	if !r.Until.IsZero() && now.Before(r.Until) {
		return true
	}
	return false
}

// Kind returns "temporary", "permanent", or "".
func (s *Store) Kind(ip net.IP) string {
	if s == nil {
		return ""
	}
	key := ipKey(ip)
	if key == "" {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.byIP[key]
	if r == nil {
		return ""
	}
	if r.Permanent {
		return KindPermanent
	}
	if !r.Until.IsZero() && s.now().Before(r.Until) {
		return KindTemporary
	}
	return ""
}

// ObserveInvalid records an invalid event. Already-banned IPs are ignored.
// On the 5th consecutive invalid, a temp (6h) or permanent ban is issued.
func (s *Store) ObserveInvalid(ip net.IP, reason string) {
	if s == nil {
		return
	}
	key := ipKey(ip)
	if key == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if s.blockedLocked(key, now) {
		return
	}
	r := s.byIP[key]
	if r == nil {
		r = &record{}
		s.byIP[key] = r
	}
	if !r.Until.IsZero() && !now.Before(r.Until) {
		r.Until = time.Time{}
		r.Consecutive = 0
	}
	r.Consecutive++
	if r.Consecutive < s.limit {
		return
	}
	r.Consecutive = 0
	r.Bans++
	if r.Bans >= 2 {
		r.Permanent = true
		r.Until = time.Time{}
		s.log.Warn("ip permanently banned", "ip", key, "reason", reason, "bans", r.Bans)
	} else {
		r.Until = now.Add(s.ttl)
		s.log.Warn("ip temp banned", "ip", key, "reason", reason, "until", r.Until.UTC().Format(time.RFC3339), "duration", s.ttl.String())
	}
	_ = s.persistLocked()
}

// ObserveValid resets the consecutive invalid counter (does not clear bans).
func (s *Store) ObserveValid(ip net.IP) {
	if s == nil {
		return
	}
	key := ipKey(ip)
	if key == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.byIP[key]
	if r == nil || r.Consecutive == 0 {
		return
	}
	r.Consecutive = 0
}

// Unban removes all ban state for ip.
func (s *Store) Unban(ip net.IP, actor string) error {
	if s == nil {
		return nil
	}
	key := ipKey(ip)
	if key == "" {
		return fmt.Errorf("invalid ip")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byIP[key]; !ok {
		return nil
	}
	delete(s.byIP, key)
	if actor == "" {
		actor = "unknown"
	}
	s.log.Info("ip unbanned", "ip", key, "actor", actor)
	return s.persistLocked()
}

// UnbanCIDRs unbans recorded IPs contained in any of the CIDRs.
func (s *Store) UnbanCIDRs(cidrs []string, actor string) {
	if s == nil {
		return
	}
	var nets []*net.IPNet
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			ip := net.ParseIP(c)
			if ip == nil {
				continue
			}
			if v4 := ip.To4(); v4 != nil {
				n = &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}
			} else {
				n = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
			}
		}
		nets = append(nets, n)
	}
	if len(nets) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := make([]string, 0)
	for key := range s.byIP {
		ip := net.ParseIP(key)
		if ip == nil {
			continue
		}
		for _, n := range nets {
			if n.Contains(ip) {
				delete(s.byIP, key)
				removed = append(removed, key)
				break
			}
		}
	}
	if len(removed) == 0 {
		return
	}
	if actor == "" {
		actor = "unknown"
	}
	s.log.Info("ips unbanned via allowlist", "actor", actor, "ips", removed)
	_ = s.persistLocked()
}

// Entry is one denylist row for Admin/CLI.
type Entry struct {
	IP          string `json:"ip"`
	Kind        string `json:"kind"`
	Until       string `json:"until,omitempty"`
	Bans        int    `json:"bans"`
	Consecutive int    `json:"consecutive,omitempty"`
}

// List returns currently banned IPs plus records that have a prior temp ban
// (so the next streak becomes permanent).
func (s *Store) List() []Entry {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	out := make([]Entry, 0, len(s.byIP))
	for ip, r := range s.byIP {
		kind := ""
		until := ""
		if r.Permanent {
			kind = KindPermanent
		} else if !r.Until.IsZero() && now.Before(r.Until) {
			kind = KindTemporary
			until = r.Until.UTC().Format(time.RFC3339)
		} else if r.Bans == 0 && r.Consecutive == 0 {
			continue
		}
		out = append(out, Entry{
			IP:          ip,
			Kind:        kind,
			Until:       until,
			Bans:        r.Bans,
			Consecutive: r.Consecutive,
		})
	}
	return out
}

// Counts returns active temp and permanent ban totals.
func (s *Store) Counts() (temp, permanent int) {
	if s == nil {
		return 0, 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for _, r := range s.byIP {
		if r.Permanent {
			permanent++
			continue
		}
		if !r.Until.IsZero() && now.Before(r.Until) {
			temp++
		}
	}
	return temp, permanent
}

func (s *Store) load() error {
	if s.path == "" {
		return nil
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var dto fileDTO
	if err := json.Unmarshal(data, &dto); err != nil {
		return fmt.Errorf("parse %s: %w", s.path, err)
	}
	s.byIP = make(map[string]*record)
	for ip, rec := range dto.Records {
		key := ipKey(net.ParseIP(ip))
		if key == "" {
			continue
		}
		r := rec
		s.byIP[key] = &r
	}
	return nil
}

func (s *Store) persistLocked() error {
	if s.path == "" {
		return nil
	}
	dto := fileDTO{Records: make(map[string]record, len(s.byIP))}
	for ip, r := range s.byIP {
		if r.Bans == 0 && r.Consecutive == 0 && r.Until.IsZero() && !r.Permanent {
			continue
		}
		dto.Records[ip] = *r
	}
	body, err := json.MarshalIndent(dto, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".denylist.*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func ipKey(ip net.IP) string {
	if ip == nil || ip.IsUnspecified() {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}
