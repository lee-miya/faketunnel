package proxy

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestRelayEcho(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	c, d := net.Pipe()
	defer a.Close()
	defer d.Close()

	done := make(chan error, 1)
	go func() { done <- Relay(b, c, 0) }()

	msg := []byte("hello-tcp")
	if _, err := a.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(d, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("got %q", got)
	}
	// reverse
	if _, err := d.Write(msg); err != nil {
		t.Fatal(err)
	}
	got = make([]byte, len(msg))
	if _, err := io.ReadFull(a, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("reverse got %q", got)
	}
	a.Close()
	d.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not exit")
	}
}

func TestValidateLocal(t *testing.T) {
	t.Parallel()
	if err := ValidateLocal("127.0.0.1:8080", true); err != nil {
		t.Fatal(err)
	}
	if err := ValidateLocal("10.1.2.3:22", true); err != nil {
		t.Fatal(err)
	}
	if err := ValidateLocal("192.168.0.9:1", true); err != nil {
		t.Fatal(err)
	}
	if err := ValidateLocal("172.16.0.1:1", true); err != nil {
		t.Fatal(err)
	}
	if err := ValidateLocal("[::1]:8080", true); err != nil {
		t.Fatal(err)
	}
	if err := ValidateLocal("8.8.8.8:53", true); err == nil {
		t.Fatal("public ip must be rejected")
	}
	if err := ValidateLocal("0.0.0.0:80", true); err == nil {
		t.Fatal("unspecified must be rejected")
	}
	if err := ValidateLocal("8.8.8.8:53", false); err != nil {
		t.Fatal(err)
	}
	if err := ValidateLocal("not-an-addr", true); err == nil {
		t.Fatal("expected error")
	}
}
