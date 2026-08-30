package acl

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
)

// Store wraps List with atomic file persistence and audit logging.
// Concurrent mutations are serialized; List.Allow remains lock-free for readers
// relative to Replace.
type Store struct {
	mu   sync.Mutex
	list *List
	path string
	log  *slog.Logger
}

// NewStore binds an existing list to an optional JSON path.
// Empty path disables persistence (memory-only updates).
func NewStore(list *List, path string, log *slog.Logger) *Store {
	if list == nil {
		list, _ = New(nil)
	}
	if log == nil {
		log = slog.Default()
	}
	return &Store{list: list, path: strings.TrimSpace(path), log: log}
}

// List returns the live allowlist (safe for concurrent Allow).
func (s *Store) List() *List { return s.list }

// Path returns the persistence file path (may be empty).
func (s *Store) Path() string { return s.path }

// Allow reports whether ip is permitted.
func (s *Store) Allow(ip net.IP) bool { return s.list.Allow(ip) }

// Entries returns a copy of configured CIDR/IP strings.
func (s *Store) Entries() []string { return s.list.Entries() }

// Len returns the number of entries.
func (s *Store) Len() int { return s.list.Len() }

// Replace swaps the full set, persists, and audits.
func (s *Store) Replace(cidrs []string, actor string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.list.Replace(cidrs); err != nil {
		return err
	}
	if err := s.persistLocked(); err != nil {
		return err
	}
	s.audit("replace", actor, s.list.Entries())
	return nil
}

// Add appends CIDRs that are not already present (string-normalized).
func (s *Store) Add(cidrs []string, actor string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.list.Entries()
	seen := make(map[string]struct{}, len(cur))
	for _, e := range cur {
		key, err := normalizeKey(e)
		if err != nil {
			return err
		}
		seen[key] = struct{}{}
	}
	out := append([]string(nil), cur...)
	added := make([]string, 0, len(cidrs))
	for _, raw := range cidrs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		key, err := normalizeKey(raw)
		if err != nil {
			return fmt.Errorf("add %q: %w", raw, err)
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, raw)
		added = append(added, raw)
	}
	if len(added) == 0 {
		return nil
	}
	if err := s.list.Replace(out); err != nil {
		return err
	}
	if err := s.persistLocked(); err != nil {
		return err
	}
	s.audit("add", actor, added)
	return nil
}

// Remove deletes matching CIDRs (by normalized network key).
func (s *Store) Remove(cidrs []string, actor string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	drop := make(map[string]struct{})
	for _, raw := range cidrs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		key, err := normalizeKey(raw)
		if err != nil {
			return fmt.Errorf("remove %q: %w", raw, err)
		}
		drop[key] = struct{}{}
	}
	if len(drop) == 0 {
		return nil
	}
	cur := s.list.Entries()
	out := make([]string, 0, len(cur))
	removed := make([]string, 0)
	for _, e := range cur {
		key, err := normalizeKey(e)
		if err != nil {
			return err
		}
		if _, ok := drop[key]; ok {
			removed = append(removed, e)
			continue
		}
		out = append(out, e)
	}
	if len(removed) == 0 {
		return nil
	}
	if err := s.list.Replace(out); err != nil {
		return err
	}
	if err := s.persistLocked(); err != nil {
		return err
	}
	s.audit("remove", actor, removed)
	return nil
}

func (s *Store) persistLocked() error {
	if s.path == "" {
		return nil
	}
	return SaveFile(s.path, s.list.Entries())
}

func (s *Store) audit(action, actor string, cidrs []string) {
	if actor == "" {
		actor = "unknown"
	}
	s.log.Info("allowlist updated",
		"action", action,
		"actor", actor,
		"cidrs", cidrs,
		"entries", s.list.Len(),
		"path", s.path,
	)
}

func normalizeKey(s string) (string, error) {
	n, err := ParseCIDR(s)
	if err != nil {
		return "", err
	}
	ones, bits := n.Mask.Size()
	if bits == 0 {
		return "", fmt.Errorf("invalid mask")
	}
	return fmt.Sprintf("%s/%d", n.IP.String(), ones), nil
}
