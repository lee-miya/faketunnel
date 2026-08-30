package main

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"faketunnel/internal/acl"
	"faketunnel/internal/admin"
	"faketunnel/internal/metrics"
)

func TestCLIVersion(t *testing.T) {
	out := captureStdout(t, func() {
		if code := run([]string{"version"}); code != 0 {
			t.Fatalf("version exit=%d", code)
		}
	})
	if strings.TrimSpace(out) != version {
		t.Fatalf("version=%q", out)
	}
	out = captureStdout(t, func() {
		if code := run([]string{"--version"}); code != 0 {
			t.Fatalf("--version exit=%d", code)
		}
	})
	if strings.TrimSpace(out) != version {
		t.Fatalf("--version=%q", out)
	}
}

func TestCLIHelpAndUnknown(t *testing.T) {
	if code := run(nil); code != 2 {
		t.Fatalf("no args exit=%d want 2", code)
	}
	if code := run([]string{"help"}); code != 0 {
		t.Fatalf("help exit=%d", code)
	}
	if code := run([]string{"not-a-command"}); code != 2 {
		t.Fatalf("unknown exit=%d want 2", code)
	}
}

func TestCLIMissingToken(t *testing.T) {
	t.Setenv("FAKETUNNEL_TOKEN", "")
	t.Setenv("FAKETUNNEL_ADMIN", "")
	err := runAllowlist([]string{"list", "-admin", "http://127.0.0.1:9"})
	if err == nil || !strings.Contains(err.Error(), "admin token required") {
		t.Fatalf("want token error, got %v", err)
	}
}

func TestCLIAllowlistCRUDAndStatus(t *testing.T) {
	t.Setenv("FAKETUNNEL_TOKEN", "")
	base, store, reg := startAdmin(t)
	tok := "secret"

	out := captureStdout(t, func() {
		if err := runAllowlist([]string{"list", "-admin", base, "-token", tok}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "127.0.0.1/32") {
		t.Fatalf("list=%q", out)
	}

	out = captureStdout(t, func() {
		if err := runAllowlist([]string{"add", "-admin", base, "-token", tok, "-actor", "cli-test", "203.0.113.10/32"}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "203.0.113.10/32") {
		t.Fatalf("add output=%q", out)
	}
	if !store.Allow(mustParseIP("203.0.113.10")) {
		t.Fatal("add not applied")
	}

	out = captureStdout(t, func() {
		if err := runAllowlist([]string{"rm", "-admin", base, "-token", tok, "203.0.113.10/32"}); err != nil {
			t.Fatal(err)
		}
	})
	if strings.Contains(out, "203.0.113.10/32") {
		t.Fatalf("rm still listed: %q", out)
	}
	if store.Allow(mustParseIP("203.0.113.10")) {
		t.Fatal("rm not applied")
	}

	out = captureStdout(t, func() {
		if err := runAllowlist([]string{"set", "-admin", base, "-token", tok, "10.0.0.0/8", "::1/128"}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "10.0.0.0/8") || !strings.Contains(out, "::1/128") {
		t.Fatalf("set output=%q", out)
	}
	if store.Len() != 2 {
		t.Fatalf("set len=%d", store.Len())
	}

	reg.SetAgentConnected(true)
	reg.AddSessions(3)
	out = captureStdout(t, func() {
		if err := runStatus([]string{"-admin", base, "-token", tok}); err != nil {
			t.Fatal(err)
		}
	})
	var st map[string]any
	if err := json.Unmarshal([]byte(out), &st); err != nil {
		t.Fatalf("status json: %v body=%s", err, out)
	}
	if st["agent_connected"] != true {
		t.Fatalf("status=%v", st)
	}
	if st["active_sessions"] != float64(3) {
		t.Fatalf("active_sessions=%v", st["active_sessions"])
	}
}

func TestCLITokenFileAndEnv(t *testing.T) {
	base, _, _ := startAdmin(t)
	tokFile := filepath.Join(t.TempDir(), "admin.token")
	if err := os.WriteFile(tokFile, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		if err := runAllowlist([]string{"list", "-admin", base, "-token-file", tokFile}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "127.0.0.1/32") {
		t.Fatalf("token-file list=%q", out)
	}

	t.Setenv("FAKETUNNEL_TOKEN", "secret")
	t.Setenv("FAKETUNNEL_ADMIN", base)
	out = captureStdout(t, func() {
		if err := runAllowlist([]string{"list"}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "127.0.0.1/32") {
		t.Fatalf("env list=%q", out)
	}

	out = captureStdout(t, func() {
		if code := run([]string{"status"}); code != 0 {
			t.Fatalf("status via env exit=%d", code)
		}
	})
	if !strings.Contains(out, "agent_connected") {
		t.Fatalf("status via env=%q", out)
	}
}

func TestCLIRunDispatchREADME(t *testing.T) {
	t.Setenv("FAKETUNNEL_TOKEN", "secret")
	base, _, _ := startAdmin(t)

	out := captureStdout(t, func() {
		if code := run([]string{"allowlist", "list", "-admin", base}); code != 0 {
			t.Fatalf("list exit=%d", code)
		}
	})
	if !strings.Contains(out, "127.0.0.1/32") {
		t.Fatalf("run list=%q", out)
	}

	out = captureStdout(t, func() {
		if code := run([]string{"allowlist", "add", "-admin", base, "203.0.113.10/32"}); code != 0 {
			t.Fatalf("add exit=%d", code)
		}
	})
	if !strings.Contains(out, "203.0.113.10/32") {
		t.Fatalf("run add=%q", out)
	}
}

func TestCLIErrors(t *testing.T) {
	t.Setenv("FAKETUNNEL_TOKEN", "secret")
	base, _, _ := startAdmin(t)

	if err := runAllowlist(nil); err == nil || !strings.Contains(err.Error(), "subcommand") {
		t.Fatalf("empty allowlist: %v", err)
	}
	if err := runAllowlist([]string{"nope", "-admin", base, "-token", "secret"}); err == nil {
		t.Fatal("unknown subcommand")
	}
	if err := runAllowlist([]string{"add", "-admin", base, "-token", "secret"}); err == nil {
		t.Fatal("add without cidr")
	}
	if err := runAllowlist([]string{"list", "-admin", base, "-token", "wrong"}); err == nil || !strings.Contains(err.Error(), "unauthorized") {
		t.Fatalf("want unauthorized, got %v", err)
	}
	if err := runAllowlist([]string{"add", "-admin", base, "-token", "secret", "not-a-cidr"}); err == nil {
		t.Fatal("want invalid cidr error")
	}
}

func startAdmin(t *testing.T) (string, *acl.Store, *metrics.Registry) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "allowlist.json")
	list, err := acl.New([]string{"127.0.0.1/32"})
	if err != nil {
		t.Fatal(err)
	}
	store := acl.NewStore(list, path, nil)
	reg := &metrics.Registry{}
	srv, err := admin.New(admin.Config{Listen: "127.0.0.1:0", Token: "secret", Metrics: true}, store, reg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Shutdown() })
	return "http://" + srv.Addr(), store, reg
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = old }()
	fn()
	_ = w.Close()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func mustParseIP(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		panic("invalid ip " + s)
	}
	return ip
}
