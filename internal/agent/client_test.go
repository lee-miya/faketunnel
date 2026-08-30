package agent

import (
	"testing"
	"time"

	"faketunnel/internal/config"
	"faketunnel/internal/tunnel"
)

func TestNextBackoff(t *testing.T) {
	t.Parallel()
	d := nextBackoff(0)
	if d < minBackoff || d > minBackoff+400*time.Millisecond {
		t.Fatalf("first backoff %s", d)
	}
	d = nextBackoff(minBackoff)
	if d < 2*minBackoff {
		t.Fatalf("grew too slowly: %s", d)
	}
	d = nextBackoff(maxBackoff)
	if d < maxBackoff || d > maxBackoff+400*time.Millisecond {
		t.Fatalf("capped backoff %s", d)
	}
}

func TestResolveLocal(t *testing.T) {
	t.Parallel()
	meta := tunnel.OpenMeta{Name: "web", Local: "127.0.0.1:3000"}
	c := &Client{cfg: &config.File{}}
	got, err := c.resolveLocal(meta)
	if err != nil || got != meta.Local {
		t.Fatalf("empty tunnels: got=%q err=%v", got, err)
	}
	c.cfg.Tunnels = []config.Tunnel{{Name: "web", Local: "127.0.0.1:4000"}}
	got, err = c.resolveLocal(meta)
	if err != nil || got != "127.0.0.1:4000" {
		t.Fatalf("override: got=%q err=%v", got, err)
	}
	c.cfg.Tunnels[0].Local = ""
	got, err = c.resolveLocal(meta)
	if err != nil || got != meta.Local {
		t.Fatalf("agent local empty: got=%q err=%v", got, err)
	}
	if _, err := c.resolveLocal(tunnel.OpenMeta{Name: "other", Local: "127.0.0.1:1"}); err == nil {
		t.Fatal("unknown tunnel")
	}
}
