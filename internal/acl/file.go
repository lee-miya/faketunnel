package acl

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type fileDTO struct {
	CIDRs []string `json:"cidrs"`
}

// LoadFile reads allowlist.json. Object form {"cidrs":[...]} and a raw JSON
// array of strings are both accepted. Missing file is an error.
func LoadFile(path string) (*List, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cidrs, err := ParseJSON(data)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return New(cidrs)
}

// ParseJSON parses allowlist JSON (object or array).
func ParseJSON(data []byte) ([]string, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, fmt.Errorf("empty allowlist document")
	}
	if data[0] == '[' {
		var arr []string
		if err := json.Unmarshal(data, &arr); err != nil {
			return nil, err
		}
		return arr, nil
	}
	var dto fileDTO
	if err := json.Unmarshal(data, &dto); err != nil {
		return nil, err
	}
	return dto.CIDRs, nil
}

// SaveFile writes CIDRs as {"cidrs":[...]} using a temp file + rename.
func SaveFile(path string, cidrs []string) error {
	if path == "" {
		return fmt.Errorf("empty allowlist path")
	}
	body, err := json.MarshalIndent(fileDTO{CIDRs: cidrs}, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".allowlist.*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}
