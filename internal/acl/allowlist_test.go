package acl

import (
	"net"
	"path/filepath"
	"testing"
)

func TestAllowDefaultDeny(t *testing.T) {
	t.Parallel()
	l, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	if l.Allow(net.ParseIP("127.0.0.1")) {
		t.Fatal("empty list must deny")
	}
	if l.Allow(nil) {
		t.Fatal("nil ip must deny")
	}
}

func TestAllowCIDRAndBareIP(t *testing.T) {
	t.Parallel()
	l, err := New([]string{
		"203.0.113.10/32",
		"198.51.100.0/24",
		"10.0.0.5",
		"::1",
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		ip    string
		allow bool
	}{
		{"203.0.113.10", true},
		{"203.0.113.11", false},
		{"198.51.100.1", true},
		{"198.51.100.255", true},
		{"198.51.101.1", false},
		{"10.0.0.5", true},
		{"10.0.0.6", false},
		{"127.0.0.1", false},
		{"::1", true},
		{"::2", false},
	}
	for _, tc := range cases {
		ip := net.ParseIP(tc.ip)
		if got := l.Allow(ip); got != tc.allow {
			t.Errorf("Allow(%s)=%v want %v", tc.ip, got, tc.allow)
		}
	}
}

func TestAllowIPv4Mapped(t *testing.T) {
	t.Parallel()
	l, err := New([]string{"127.0.0.1/32"})
	if err != nil {
		t.Fatal(err)
	}
	mapped := net.ParseIP("::ffff:127.0.0.1")
	if !l.Allow(mapped) {
		t.Fatal("IPv4-mapped loopback should match 127.0.0.1/32")
	}
}

func TestReplaceKeepsOldOnError(t *testing.T) {
	t.Parallel()
	l, err := New([]string{"127.0.0.1/32"})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Replace([]string{"not-an-ip"}); err == nil {
		t.Fatal("expected error")
	}
	if !l.Allow(net.ParseIP("127.0.0.1")) {
		t.Fatal("previous entries must remain after failed Replace")
	}
}

func TestParseCIDRRejectsGarbage(t *testing.T) {
	t.Parallel()
	if _, err := ParseCIDR("999.0.0.1"); err == nil {
		t.Fatal("expected error")
	}
	if _, err := ParseCIDR(""); err == nil {
		t.Fatal("expected error")
	}
}

func TestFileRoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "allowlist.json")
	want := []string{"127.0.0.1/32", "10.0.0.0/8"}
	if err := SaveFile(path, want); err != nil {
		t.Fatal(err)
	}
	l, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !l.Allow(net.ParseIP("127.0.0.1")) || !l.Allow(net.ParseIP("10.1.2.3")) {
		t.Fatal("loaded allowlist mismatch")
	}
}

func TestParseJSONArray(t *testing.T) {
	t.Parallel()
	cidrs, err := ParseJSON([]byte(`["192.168.1.1/32"]`))
	if err != nil {
		t.Fatal(err)
	}
	l, err := New(cidrs)
	if err != nil {
		t.Fatal(err)
	}
	if !l.Allow(net.ParseIP("192.168.1.1")) {
		t.Fatal("array form not loaded")
	}
}

func TestNewRejectsInvalidEntry(t *testing.T) {
	t.Parallel()
	if _, err := New([]string{"127.0.0.1", "bad"}); err == nil {
		t.Fatal("expected error")
	}
}
