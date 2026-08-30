package ban

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFiveInvalidTempBanThenPermanent(t *testing.T) {
	t.Parallel()
	s := New("", nil)
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	s.ttl = time.Hour

	ip := net.ParseIP("203.0.113.50")
	for i := 0; i < 4; i++ {
		s.ObserveInvalid(ip, "acl")
		if s.Blocked(ip) {
			t.Fatalf("blocked too early at %d", i+1)
		}
	}
	s.ObserveInvalid(ip, "acl")
	if !s.Blocked(ip) || s.Kind(ip) != KindTemporary {
		t.Fatalf("want temp ban, kind=%q blocked=%v", s.Kind(ip), s.Blocked(ip))
	}

	// Further invalid while banned must not escalate.
	s.ObserveInvalid(ip, "acl")
	if s.Kind(ip) != KindTemporary {
		t.Fatalf("escalated while banned: %q", s.Kind(ip))
	}

	now = now.Add(time.Hour + time.Second)
	if s.Blocked(ip) {
		t.Fatal("temp ban should have expired")
	}

	for i := 0; i < 5; i++ {
		s.ObserveInvalid(ip, "acl")
	}
	if s.Kind(ip) != KindPermanent || !s.Blocked(ip) {
		t.Fatalf("want permanent, kind=%q", s.Kind(ip))
	}
}

func TestValidResetsConsecutive(t *testing.T) {
	t.Parallel()
	s := New("", nil)
	ip := net.ParseIP("198.51.100.9")
	for i := 0; i < 4; i++ {
		s.ObserveInvalid(ip, "acl")
	}
	s.ObserveValid(ip)
	for i := 0; i < 4; i++ {
		s.ObserveInvalid(ip, "acl")
		if s.Blocked(ip) {
			t.Fatal("valid should have reset the streak")
		}
	}
}

func TestPersistAndUnban(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "denylist.json")
	s := New(path, nil)
	ip := net.ParseIP("192.0.2.8")
	for i := 0; i < 5; i++ {
		s.ObserveInvalid(ip, "acl")
	}
	if !s.Blocked(ip) {
		t.Fatal("want temp ban")
	}

	s2 := New(path, nil)
	if !s2.Blocked(ip) || s2.Kind(ip) != KindTemporary {
		t.Fatalf("reload lost ban kind=%q", s2.Kind(ip))
	}

	if err := s2.Unban(ip, "test"); err != nil {
		t.Fatal(err)
	}
	if s2.Blocked(ip) {
		t.Fatal("still banned after unban")
	}
	s3 := New(path, nil)
	if s3.Blocked(ip) {
		t.Fatal("unban not persisted")
	}
}

func TestUnbanCIDRs(t *testing.T) {
	t.Parallel()
	s := New("", nil)
	ip := net.ParseIP("10.1.2.3")
	for i := 0; i < 5; i++ {
		s.ObserveInvalid(ip, "acl")
	}
	s.UnbanCIDRs([]string{"10.0.0.0/8"}, "ops")
	if s.Blocked(ip) {
		t.Fatal("cidr unban failed")
	}
}

func TestNilAndBadIP(t *testing.T) {
	t.Parallel()
	var s *Store
	s.ObserveInvalid(net.ParseIP("1.2.3.4"), "acl")
	if s.Blocked(net.ParseIP("1.2.3.4")) {
		t.Fatal("nil store")
	}
	s = New("", nil)
	s.ObserveInvalid(nil, "acl")
	s.ObserveValid(nil)
	if err := s.Unban(nil, "x"); err == nil {
		t.Fatal("want invalid ip")
	}
}

func TestFileRoundTripPermanent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "denylist.json")
	s := New(path, nil)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	s.ttl = time.Minute
	ip := net.ParseIP("2001:db8::1")
	for i := 0; i < 5; i++ {
		s.ObserveInvalid(ip, "admin")
	}
	now = now.Add(2 * time.Minute)
	for i := 0; i < 5; i++ {
		s.ObserveInvalid(ip, "admin")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var dto fileDTO
	if err := json.Unmarshal(data, &dto); err != nil {
		t.Fatal(err)
	}
	rec, ok := dto.Records["2001:db8::1"]
	if !ok || !rec.Permanent {
		t.Fatalf("file=%s rec=%v ok=%v", data, rec, ok)
	}
}

func TestIPv4Mapped(t *testing.T) {
	t.Parallel()
	s := New("", nil)
	v4 := net.ParseIP("203.0.113.9")
	mapped := net.ParseIP("::ffff:203.0.113.9")
	for i := 0; i < 5; i++ {
		s.ObserveInvalid(mapped, "acl")
	}
	if !s.Blocked(v4) {
		t.Fatal("mapped v6 should ban v4")
	}
}
