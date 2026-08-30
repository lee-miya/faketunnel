package metrics

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestRegistryPrometheus(t *testing.T) {
	t.Parallel()
	r := &Registry{}
	r.IncDeny()
	r.IncDeny()
	r.AddSessions(3)
	r.SetAgentConnected(true)
	r.ObserveRTT(12 * time.Millisecond)

	var buf bytes.Buffer
	if err := r.WritePrometheus(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"mytunnel_acl_denies_total 2",
		"mytunnel_active_sessions 3",
		"mytunnel_agent_connected 1",
		"mytunnel_tunnel_rtt_seconds",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	st := r.Snapshot()
	if !st.HasRTT || st.TunnelRTTMs < 11 || st.TunnelRTTMs > 13 {
		t.Fatalf("rtt snapshot=%+v", st)
	}
}
