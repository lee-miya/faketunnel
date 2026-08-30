package config

import (
	"os"
	"path/filepath"
	"strings"
)

// Find locates a YAML config for role "edge" or "agent".
// Order: FAKETUNNEL_CONFIG, ./<role>.yaml, ./configs/<role>.yaml,
// /opt/faketunnel/configs/<role>.yaml, /etc/faketunnel/<role>.yaml.
func Find(role string) string {
	if p := strings.TrimSpace(os.Getenv("FAKETUNNEL_CONFIG")); p != "" {
		return p
	}
	names := []string{role + ".yaml", role + ".yml"}
	var candidates []string
	for _, n := range names {
		candidates = append(candidates, n, filepath.Join("configs", n))
	}
	candidates = append(candidates,
		filepath.Join("/opt/faketunnel/configs", role+".yaml"),
		filepath.Join("/etc/faketunnel", role+".yaml"),
	)
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c
		}
	}
	return ""
}

// DiscoverAdminToken looks for an Admin Bearer token when CLI flags/env are empty.
func DiscoverAdminToken() string {
	if v := strings.TrimSpace(os.Getenv("FAKETUNNEL_TOKEN")); v != "" {
		return v
	}
	var paths []string
	if cfg := strings.TrimSpace(os.Getenv("FAKETUNNEL_CONFIG")); cfg != "" {
		paths = append(paths, filepath.Join(filepath.Dir(cfg), DefaultAdminToken))
	}
	paths = append(paths,
		DefaultAdminToken,
		filepath.Join("configs", DefaultAdminToken),
		"/opt/faketunnel/configs/"+DefaultAdminToken,
		"/etc/faketunnel/"+DefaultAdminToken,
	)
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if t := strings.TrimSpace(string(data)); t != "" {
			return t
		}
	}
	return ""
}
