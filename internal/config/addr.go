package config

import (
	"fmt"
	"strconv"

	"gopkg.in/yaml.v3"
)

// UnmarshalYAML accepts public/local as a string or a bare integer port (8080).
func (t *Tunnel) UnmarshalYAML(value *yaml.Node) error {
	var aux struct {
		Name        string    `yaml:"name"`
		Type        string    `yaml:"type"`
		Public      yaml.Node `yaml:"public"`
		TLS         bool      `yaml:"tls"`
		Passthrough bool      `yaml:"passthrough"`
		HTTP2       bool      `yaml:"http2"`
		Local       yaml.Node `yaml:"local"`
		Host        string    `yaml:"host"`
		Cert        string    `yaml:"cert"`
		Key         string    `yaml:"key"`
	}
	if err := value.Decode(&aux); err != nil {
		return err
	}
	pub, err := yamlNodeAddr(&aux.Public)
	if err != nil {
		return fmt.Errorf("public: %w", err)
	}
	loc, err := yamlNodeAddr(&aux.Local)
	if err != nil {
		return fmt.Errorf("local: %w", err)
	}
	t.Name = aux.Name
	t.Type = aux.Type
	t.Public = pub
	t.TLS = aux.TLS
	t.Passthrough = aux.Passthrough
	t.HTTP2 = aux.HTTP2
	t.Local = loc
	t.Host = aux.Host
	t.Cert = aux.Cert
	t.Key = aux.Key
	return nil
}

func yamlNodeAddr(n *yaml.Node) (string, error) {
	if n == nil || n.Kind == 0 || n.ShortTag() == "!!null" {
		return "", nil
	}
	var v any
	if err := n.Decode(&v); err != nil {
		return "", err
	}
	switch x := v.(type) {
	case nil:
		return "", nil
	case string:
		return x, nil
	case int:
		return strconv.Itoa(x), nil
	case int64:
		return strconv.FormatInt(x, 10), nil
	case uint64:
		return strconv.FormatUint(x, 10), nil
	case float64:
		if x == float64(int64(x)) {
			return strconv.FormatInt(int64(x), 10), nil
		}
		return "", fmt.Errorf("invalid address")
	default:
		return "", fmt.Errorf("invalid address")
	}
}
