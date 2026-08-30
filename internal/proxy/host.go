package proxy

import (
	"net"
	"strings"
)

// NormalizeHost strips an optional port and lowercases the hostname for matching.
// Returns empty string when host is empty after trimming.
func NormalizeHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	// strip brackets around IPv6 literals before SplitHostPort
	h := host
	if strings.HasPrefix(h, "[") {
		if end := strings.IndexByte(h, ']'); end > 0 {
			inner := h[1:end]
			rest := h[end+1:]
			if rest == "" {
				return strings.ToLower(inner)
			}
			if strings.HasPrefix(rest, ":") {
				return strings.ToLower(inner)
			}
		}
	}
	if strings.Contains(h, ":") {
		if nh, _, err := net.SplitHostPort(h); err == nil {
			return strings.ToLower(nh)
		}
	}
	return strings.ToLower(h)
}

// MatchHost picks a tunnel name from host→name map. emptyKey is the catch-all
// (config host omitted). Exact match wins over catch-all.
func MatchHost(host string, byHost map[string]string, emptyKey string) (name string, ok bool) {
	key := NormalizeHost(host)
	if key != "" {
		if name, ok = byHost[key]; ok {
			return name, true
		}
	}
	if emptyKey != "" {
		return emptyKey, true
	}
	return "", false
}
