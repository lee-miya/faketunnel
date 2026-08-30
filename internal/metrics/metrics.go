package metrics

import (
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Registry holds Edge runtime counters exposed as Prometheus text and JSON status.
type Registry struct {
	denies         atomic.Uint64
	activeSessions atomic.Int64
	agentConnected atomic.Bool
	rttNanos       atomic.Int64
	rttSamples     atomic.Uint64
	mu             sync.Mutex
	lastDenyAt     time.Time
	lastRTTAt      time.Time
}

// IncDeny increments the ACL reject counter.
func (r *Registry) IncDeny() {
	r.denies.Add(1)
	r.mu.Lock()
	r.lastDenyAt = time.Now()
	r.mu.Unlock()
}

// Denies returns the total deny count.
func (r *Registry) Denies() uint64 { return r.denies.Load() }

// AddSessions adjusts the active session gauge (TCP/HTTP streams and UDP assocs).
func (r *Registry) AddSessions(delta int64) {
	for {
		cur := r.activeSessions.Load()
		next := cur + delta
		if next < 0 {
			next = 0
		}
		if r.activeSessions.CompareAndSwap(cur, next) {
			return
		}
	}
}

// ActiveSessions returns the current session gauge.
func (r *Registry) ActiveSessions() int64 { return r.activeSessions.Load() }

// SetAgentConnected records whether an Agent yamux session is live.
func (r *Registry) SetAgentConnected(ok bool) { r.agentConnected.Store(ok) }

// AgentConnected reports Agent presence.
func (r *Registry) AgentConnected() bool { return r.agentConnected.Load() }

// ObserveRTT records the latest tunnel control-channel RTT sample.
func (r *Registry) ObserveRTT(d time.Duration) {
	if d < 0 {
		return
	}
	r.rttNanos.Store(d.Nanoseconds())
	r.rttSamples.Add(1)
	r.mu.Lock()
	r.lastRTTAt = time.Now()
	r.mu.Unlock()
}

// LastRTT returns the most recent RTT and whether any sample exists.
func (r *Registry) LastRTT() (time.Duration, bool) {
	n := r.rttSamples.Load()
	if n == 0 {
		return 0, false
	}
	return time.Duration(r.rttNanos.Load()), true
}

// Status is a JSON-friendly snapshot.
type Status struct {
	AgentConnected bool    `json:"agent_connected"`
	ActiveSessions int64   `json:"active_sessions"`
	ACLDenies      uint64  `json:"acl_denies"`
	TunnelRTTMs    float64 `json:"tunnel_rtt_ms,omitempty"`
	HasRTT         bool    `json:"has_rtt"`
}

// Snapshot returns current values.
func (r *Registry) Snapshot() Status {
	st := Status{
		AgentConnected: r.AgentConnected(),
		ActiveSessions: r.ActiveSessions(),
		ACLDenies:      r.Denies(),
	}
	if d, ok := r.LastRTT(); ok {
		st.HasRTT = true
		st.TunnelRTTMs = float64(d) / float64(time.Millisecond)
	}
	return st
}

// WritePrometheus writes Prometheus exposition format to w.
func (r *Registry) WritePrometheus(w io.Writer) error {
	st := r.Snapshot()
	agent := 0
	if st.AgentConnected {
		agent = 1
	}
	_, err := fmt.Fprintf(w, `# HELP mytunnel_agent_connected Whether an Agent is connected (1/0).
# TYPE mytunnel_agent_connected gauge
mytunnel_agent_connected %d
# HELP mytunnel_active_sessions Active TCP/HTTP sessions and UDP associations.
# TYPE mytunnel_active_sessions gauge
mytunnel_active_sessions %d
# HELP mytunnel_acl_denies_total Total public connections rejected by allowlist.
# TYPE mytunnel_acl_denies_total counter
mytunnel_acl_denies_total %d
`, agent, st.ActiveSessions, st.ACLDenies)
	if err != nil {
		return err
	}
	if st.HasRTT {
		_, err = fmt.Fprintf(w, `# HELP mytunnel_tunnel_rtt_seconds Last measured control-channel RTT.
# TYPE mytunnel_tunnel_rtt_seconds gauge
mytunnel_tunnel_rtt_seconds %g
`, st.TunnelRTTMs/1000)
	}
	return err
}

// Handler serves GET /metrics in Prometheus text format.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_ = r.WritePrometheus(w)
	})
}
