package proxy

import (
	"net"
	"testing"
)

func TestDialUDPLocalLoopback(t *testing.T) {
	t.Parallel()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	conn, err := DialUDPLocal(pc.LocalAddr().String(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	msg := []byte("ping")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != string(msg) {
		t.Fatalf("got %q", buf[:n])
	}
}

func TestDialUDPLocalRejectsPublic(t *testing.T) {
	t.Parallel()
	if _, err := DialUDPLocal("8.8.8.8:53", true); err == nil {
		t.Fatal("expected reject")
	}
}
