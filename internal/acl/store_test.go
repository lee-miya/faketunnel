package acl

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestStoreAddRemovePersist(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "allowlist.json")
	list, err := New([]string{"127.0.0.1/32"})
	if err != nil {
		t.Fatal(err)
	}
	st := NewStore(list, path, nil)
	if err := st.Add([]string{"10.0.0.0/8", "127.0.0.1"}, "tester"); err != nil {
		t.Fatal(err)
	}
	if st.Len() != 2 {
		t.Fatalf("len=%d want 2 (dup skipped)", st.Len())
	}
	if !st.Allow(net.ParseIP("10.1.2.3")) {
		t.Fatal("10.1.2.3 should be allowed")
	}
	if err := st.Remove([]string{"10.0.0.0/8"}, "tester"); err != nil {
		t.Fatal(err)
	}
	if st.Allow(net.ParseIP("10.1.2.3")) {
		t.Fatal("removed cidr still allowed")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cidrs, err := ParseJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(cidrs) != 1 || cidrs[0] != "127.0.0.1/32" {
		t.Fatalf("persisted=%v", cidrs)
	}
}

func TestStoreReplaceAtomic(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "allowlist.json")
	list, err := New([]string{"127.0.0.1/32"})
	if err != nil {
		t.Fatal(err)
	}
	st := NewStore(list, path, nil)
	if err := st.Replace([]string{"not-a-cidr"}, "x"); err == nil {
		t.Fatal("expected error")
	}
	if !st.Allow(net.ParseIP("127.0.0.1")) {
		t.Fatal("failed replace must keep old set")
	}
	if err := st.Replace([]string{"::1"}, "x"); err != nil {
		t.Fatal(err)
	}
	if st.Allow(net.ParseIP("127.0.0.1")) || !st.Allow(net.ParseIP("::1")) {
		t.Fatal("replace mismatch")
	}
}
