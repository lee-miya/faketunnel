package acl

import (
	"log/slog"
	"os"
)

// FromConfig loads the file allowlist if present; otherwise uses YAML entries
// (and writes the file when a path is configured). Empty result is deny-all.
func FromConfig(filePath string, yamlEntries []string, log *slog.Logger) (*List, error) {
	if log == nil {
		log = slog.Default()
	}
	if filePath != "" {
		_, err := os.Stat(filePath)
		if err == nil {
			l, err := LoadFile(filePath)
			if err != nil {
				return nil, err
			}
			log.Info("allowlist loaded", "path", filePath, "entries", l.Len())
			return l, nil
		}
		if !os.IsNotExist(err) {
			return nil, err
		}
	}
	l, err := New(yamlEntries)
	if err != nil {
		return nil, err
	}
	if filePath != "" && len(yamlEntries) > 0 {
		if err := SaveFile(filePath, yamlEntries); err != nil {
			log.Warn("allowlist file not written", "path", filePath, "err", err)
		} else {
			log.Info("allowlist file created from yaml", "path", filePath, "entries", l.Len())
		}
	}
	if l.Len() == 0 {
		log.Warn("allowlist is empty; all public connections will be denied")
	} else {
		log.Info("allowlist loaded from yaml", "entries", l.Len())
	}
	return l, nil
}
