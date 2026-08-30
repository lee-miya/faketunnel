package admin

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"faketunnel/internal/acl"
	"faketunnel/internal/ban"
	"faketunnel/internal/metrics"
	"faketunnel/internal/tlsutil"
)

func TestAllowlistCRUD(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "allowlist.json")
	list, err := acl.New([]string{"127.0.0.1/32"})
	if err != nil {
		t.Fatal(err)
	}
	store := acl.NewStore(list, path, nil)
	reg := &metrics.Registry{}
	srv, err := New(Config{Listen: "127.0.0.1:0", Token: "secret", Metrics: true}, store, reg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Shutdown()

	base := "http://" + srv.Addr()
	do := func(method, path string, body any) (*http.Response, []byte) {
		t.Helper()
		var rdr io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rdr = bytes.NewReader(b)
		}
		req, err := http.NewRequest(method, base+path, rdr)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer secret")
		req.Header.Set("X-Admin-Actor", "test")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		return resp, data
	}

	resp, _ := do(http.MethodGet, "/v1/allowlist", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("GET status=%d", resp.StatusCode)
	}

	resp, data := do(http.MethodPost, "/v1/allowlist", map[string]any{"cidr": "10.0.0.0/8"})
	if resp.StatusCode != 200 {
		t.Fatalf("POST status=%d body=%s", resp.StatusCode, data)
	}
	if !store.Allow(mustIP("10.1.1.1")) {
		t.Fatal("add not applied")
	}

	resp, data = do(http.MethodDelete, "/v1/allowlist?cidr=10.0.0.0/8", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("DELETE status=%d body=%s", resp.StatusCode, data)
	}
	if store.Allow(mustIP("10.1.1.1")) {
		t.Fatal("remove not applied")
	}

	resp, data = do(http.MethodPut, "/v1/allowlist", map[string]any{"cidrs": []string{"::1"}})
	if resp.StatusCode != 200 {
		t.Fatalf("PUT status=%d body=%s", resp.StatusCode, data)
	}
	if store.Len() != 1 || !store.Allow(mustIP("::1")) {
		t.Fatal("put mismatch")
	}

	req, err := http.NewRequest(http.MethodGet, base+"/v1/status", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer secret")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d", resp.StatusCode)
	}

	req, err = http.NewRequest(http.MethodGet, base+"/metrics", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer secret")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !bytes.Contains(body, []byte("faketunnel_acl_denies_total")) {
		t.Fatalf("metrics=%s", body)
	}

	req, err = http.NewRequest(http.MethodGet, base+"/v1/allowlist", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401 got %d", resp.StatusCode)
	}
}

func TestAdminAuthBanAddSelfAndDenylist(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "allowlist.json")
	list, err := acl.New([]string{"127.0.0.1/32"})
	if err != nil {
		t.Fatal(err)
	}
	store := acl.NewStore(list, path, nil)
	bans := ban.New("", nil)
	srv, err := New(Config{Listen: "127.0.0.1:0", Token: "secret", Metrics: true, Bans: bans}, store, &metrics.Registry{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Shutdown()
	base := "http://" + srv.Addr()

	wrong := func() int {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, base+"/v1/status", nil)
		req.Header.Set("Authorization", "Bearer wrong-token")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	for i := 0; i < 4; i++ {
		if code := wrong(); code != http.StatusUnauthorized {
			t.Fatalf("try %d: want 401 got %d", i+1, code)
		}
	}
	if code := wrong(); code != http.StatusUnauthorized {
		t.Fatalf("5th want 401 got %d", code)
	}
	if code := wrong(); code != http.StatusForbidden {
		t.Fatalf("banned want 403 got %d", code)
	}

	req, _ := http.NewRequest(http.MethodGet, base+"/v1/denylist", nil)
	req.Header.Set("Authorization", "Bearer secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !bytes.Contains(data, []byte("temporary")) {
		t.Fatalf("denylist=%s status=%d", data, resp.StatusCode)
	}

	req, _ = http.NewRequest(http.MethodPost, base+"/v1/allowlist/self", bytes.NewReader([]byte("{}")))
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("add-self status=%d", resp.StatusCode)
	}
	if bans.Blocked(net.ParseIP("127.0.0.1")) && bans.Blocked(net.ParseIP("::1")) {
		t.Fatal("add-self should unban loopback")
	}
}

func TestAdminHTTPS(t *testing.T) {
	t.Parallel()
	cert, err := tlsutil.LoadOrGenerate("", "", true, []string{"localhost", "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	list, _ := acl.New([]string{"127.0.0.1/32"})
	store := acl.NewStore(list, filepath.Join(t.TempDir(), "a.json"), nil)
	srv, err := New(Config{
		Listen: "127.0.0.1:0",
		Token:  "secret",
		TLS:    tlsutil.HTTPSConfig(cert),
	}, store, &metrics.Registry{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Shutdown()

	cli := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}
	req, _ := http.NewRequest(http.MethodGet, "https://"+srv.Addr()+"/v1/status", nil)
	req.Header.Set("Authorization", "Bearer secret")
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("https status=%d", resp.StatusCode)
	}
}

func mustIP(s string) net.IP {
	return net.ParseIP(s)
}
