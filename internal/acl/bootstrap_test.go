package acl

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFromConfigCreatesFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "allowlist.json")
	l, err := FromConfig(path, []string{"127.0.0.1/32"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if l.Len() != 1 {
		t.Fatal(l.Len())
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	l2, err := FromConfig(path, []string{"10.0.0.1/32"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if l2.Len() != 1 {
		t.Fatal("file should win over yaml")
	}
}

func TestFromConfigEmptyDenyAll(t *testing.T) {
	t.Parallel()
	l, err := FromConfig("", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if l.Len() != 0 {
		t.Fatal("expected empty")
	}
}
