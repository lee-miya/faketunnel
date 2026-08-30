package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// RandomToken returns a 32-byte hex string suitable as a tunnel or admin token.
func RandomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (c *File) ensureAdminToken() error {
	if !c.AdminEnabled() {
		return nil
	}
	if strings.TrimSpace(c.Admin.Token) != "" {
		return nil
	}
	path := c.Admin.TokenFile
	if path == "" {
		return fmt.Errorf("admin.token is required when admin is enabled")
	}
	tok, err := RandomToken()
	if err != nil {
		return fmt.Errorf("generate admin token: %w", err)
	}
	if err := WriteSecretFile(path, tok); err != nil {
		return fmt.Errorf("write admin token: %w", err)
	}
	c.Admin.Token = tok
	return nil
}

// WriteSecretFile writes contents plus a trailing newline with mode 0600.
func WriteSecretFile(path, contents string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(contents+"\n"), 0o600)
}
