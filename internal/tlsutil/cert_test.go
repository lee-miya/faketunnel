package tlsutil

import (
	"crypto/tls"
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
