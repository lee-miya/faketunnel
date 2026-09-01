package tlsutil

import (
	"crypto/tls"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerateAndHandshake(t *testing.T) {
	t.Parallel()
	certPEM, keyPEM, err := GenerateSelfSigned([]string{"localhost", "127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	clientCfg, err := ClientConfig(caPath, "localhost", false)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", ServerConfig(cert))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	errc := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		defer c.Close()
		buf := make([]byte, 4)
		_, err = c.Read(buf)
		errc <- err
	}()

	d := &tls.Dialer{Config: clientCfg}
	c, err := d.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errc:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server hung")
	}
}

func TestLoadOrGenerateMemory(t *testing.T) {
	t.Parallel()
	cert, err := LoadOrGenerate("", "", true, []string{"localhost"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("empty cert")
	}
}

func TestLoadOrGenerateWritesFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "k.pem")
	if _, err := LoadOrGenerate(certPath, keyPath, true, []string{"localhost"}); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrGenerate(certPath, keyPath, false, nil); err != nil {
		t.Fatal(err)
	}
}

func TestClientConfigOmitsALPN(t *testing.T) {
	t.Parallel()
	cfg, err := ClientConfig("", "localhost", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.NextProtos) != 0 {
		t.Fatalf("client ALPN %v; want none (avoids handshake EOF against old Edge)", cfg.NextProtos)
	}
}

func TestHandshakeClientWithoutALPN(t *testing.T) {
	t.Parallel()
	cert := mustSelfSigned(t)
	mustHandshake(t, ServerConfig(cert), &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
		ServerName:         "localhost",
	})
}

func TestHandshakeLegacyAgentToNewEdge(t *testing.T) {
	t.Parallel()
	cert := mustSelfSigned(t)
	mustHandshake(t, ServerConfig(cert), &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
		ServerName:         "localhost",
		NextProtos:         []string{LegacyALPN},
	})
}

func TestHandshakeNewAgentToLegacyEdge(t *testing.T) {
	t.Parallel()
	cert := mustSelfSigned(t)
	clientCfg, err := ClientConfig("", "localhost", true)
	if err != nil {
		t.Fatal(err)
	}
	mustHandshake(t, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{LegacyALPN},
	}, clientCfg)
}

func TestHandshakeMismatchedALPNFails(t *testing.T) {
	t.Parallel()
	cert := mustSelfSigned(t)
	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{LegacyALPN},
	}
	clientCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
		ServerName:         "localhost",
		NextProtos:         []string{ALPN},
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		if tc, ok := c.(*tls.Conn); ok {
			_ = tc.Handshake()
		}
	}()
	d := &tls.Dialer{Config: clientCfg}
	c, err := d.Dial("tcp", ln.Addr().String())
	if err == nil {
		c.Close()
		t.Fatal("expected ALPN mismatch to fail handshake")
	}
}

func mustSelfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	certPEM, keyPEM, err := GenerateSelfSigned([]string{"localhost", "127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func mustHandshake(t *testing.T, serverCfg, clientCfg *tls.Config) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	errc := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		defer c.Close()
		tc, ok := c.(*tls.Conn)
		if !ok {
			errc <- errors.New("accept did not return tls.Conn")
			return
		}
		if err := tc.Handshake(); err != nil {
			errc <- err
			return
		}
		buf := make([]byte, 4)
		_, err = io.ReadFull(tc, buf)
		errc <- err
	}()

	d := &tls.Dialer{Config: clientCfg}
	c, err := d.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errc:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server hung")
	}
}
