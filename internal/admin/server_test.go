package admin

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"

	"faketunnel/internal/acl"
	"faketunnel/internal/metrics"
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

func mustIP(s string) net.IP {
	return net.ParseIP(s)
}
