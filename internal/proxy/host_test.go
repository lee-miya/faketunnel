package proxy

import "testing"

func TestNormalizeHost(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"Example.COM", "example.com"},
		{"example.com:443", "example.com"},
		{"[::1]:8080", "::1"},
		{"[::1]", "::1"},
		{"  Host.Test  ", "host.test"},
	}
	for _, tc := range cases {
		if got := NormalizeHost(tc.in); got != tc.want {
			t.Fatalf("NormalizeHost(%q)=%q want %q", tc.in, got, tc.want)
		}
	}
}

func TestMatchHost(t *testing.T) {
	t.Parallel()
	byHost := map[string]string{
		"a.example": "tun-a",
		"b.example": "tun-b",
	}
	name, ok := MatchHost("A.Example:80", byHost, "default")
	if !ok || name != "tun-a" {
		t.Fatalf("got %q %v", name, ok)
	}
	name, ok = MatchHost("other.example", byHost, "default")
	if !ok || name != "default" {
		t.Fatalf("catch-all got %q %v", name, ok)
	}
	_, ok = MatchHost("other.example", byHost, "")
	if ok {
		t.Fatal("expected miss without catch-all")
	}
}
