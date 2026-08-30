package agent

import (
	"testing"
	"time"
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
