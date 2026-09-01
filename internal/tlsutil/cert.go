package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

const ALPN = "faketunnel/1"
const LegacyALPN = "mytunnel/1"

// GenerateSelfSigned returns PEM-encoded cert and key for the given hosts
// (DNS names or IP addresses).
func GenerateSelfSigned(hosts []string, validFor time.Duration) (certPEM, keyPEM []byte, err error) {
	if validFor <= 0 {
		validFor = 365 * 24 * time.Hour
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{"fakeTunnel"}, CommonName: "faketunnel-edge"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(validFor),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if len(hosts) == 0 {
		hosts = []string{"localhost", "127.0.0.1", "::1"}
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	return certPEM, keyPEM, nil
}

// LoadOrGenerate loads cert/key files, or generates a self-signed pair.
// If auto is true and files are missing, they are created when paths are set;
// empty paths keep the material in memory only.
func LoadOrGenerate(certPath, keyPath string, auto bool, hosts []string) (tls.Certificate, error) {
	if certPath != "" && keyPath != "" {
		_, cerr := os.Stat(certPath)
		_, kerr := os.Stat(keyPath)
		switch {
		case cerr == nil && kerr == nil:
			cert, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err != nil {
				return tls.Certificate{}, fmt.Errorf("load tls cert: %w", err)
			}
			return cert, nil
		case os.IsNotExist(cerr) && os.IsNotExist(kerr) && auto:
			// generate below
		case !auto:
			if os.IsNotExist(cerr) || os.IsNotExist(kerr) {
				return tls.Certificate{}, fmt.Errorf("tls cert/key not found")
			}
			return tls.Certificate{}, fmt.Errorf("stat tls cert: %v, %v", cerr, kerr)
		default:
			if (cerr == nil) != (kerr == nil) {
				return tls.Certificate{}, fmt.Errorf("tls cert/key incomplete")
			}
			return tls.Certificate{}, fmt.Errorf("stat tls cert: %v, %v", cerr, kerr)
		}
	} else if !auto {
		return tls.Certificate{}, fmt.Errorf("tls.cert and tls.key are required")
	}
	certPEM, keyPEM, err := GenerateSelfSigned(hosts, 0)
	if err != nil {
		return tls.Certificate{}, err
	}
	if certPath != "" && keyPath != "" {
		if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
			return tls.Certificate{}, err
		}
		if err := os.MkdirAll(filepath.Dir(keyPath), 0o755); err != nil {
			return tls.Certificate{}, err
		}
		if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
			return tls.Certificate{}, err
		}
		if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
			return tls.Certificate{}, err
		}
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

// ServerConfig builds a TLS 1.2+ server config.
// NextProtos is advertised so old Agents that send ALPN still match; a client
// that sends no ALPN also succeeds (crypto/tls skips negotiation).
func ServerConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{ALPN, LegacyALPN},
	}
}

// HTTPSConfig builds TLS 1.2+ for the Admin HTTP API (no tunnel ALPN).
func HTTPSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	}
}

// ClientConfig builds a TLS 1.2+ client config.
//
// The client does not advertise ALPN. If both sides send NextProtos and they
// do not overlap, crypto/tls aborts the handshake (often as EOF). Token auth
// identifies the tunnel after TLS, so ALPN is not required on the client.
func ClientConfig(caPath, serverName string, insecure bool) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: insecure,
		ServerName:         serverName,
	}
	if caPath != "" {
		pemBytes, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("read ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("no certificates in ca file")
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}
