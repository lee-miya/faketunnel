package netutil

import (
	"bufio"
	"net"
	"strings"
	"testing"
)

func TestParseProxyV1(t *testing.T) {
	t.Parallel()
	ip, port, err := parseProxyV1("PROXY TCP4 203.0.113.10 192.0.2.1 12345 443\r\n")
	if err != nil {
		t.Fatal(err)
	}
	if ip.String() != "203.0.113.10" || port != 12345 {
		t.Fatalf("ip=%s port=%d", ip, port)
	}
	if _, _, err := parseProxyV1("GET / HTTP/1.1\r\n"); err == nil {
		t.Fatal("expected error")
	}
	if _, _, err := parseProxyV1("PROXY UNKNOWN\r\n"); err == nil {
		t.Fatal("UNKNOWN must fail closed")
	}
}

func TestMaybeProxy(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	defer b.Close()
	errc := make(chan error, 1)
	go func() {
		_, err := b.Write([]byte("PROXY TCP4 198.51.100.7 10.0.0.1 9 80\r\nhello"))
		errc <- err
	}()
	wrapped, err := MaybeProxy(a, true)
	if err != nil {
		t.Fatal(err)
	}
	defer wrapped.Close()
	if wrapped.RemoteAddr().(*net.TCPAddr).IP.String() != "198.51.100.7" {
		t.Fatalf("remote=%s", wrapped.RemoteAddr())
	}
	buf := make([]byte, 5)
	n, err := wrapped.Read(buf)
	if err != nil || string(buf[:n]) != "hello" {
		t.Fatalf("leftover %q %v", buf[:n], err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

func TestMaybeProxyDisabled(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	c, err := MaybeProxy(a, false)
	if err != nil || c != a {
		t.Fatal("expected original conn")
	}
}

func TestReadLineLimit(t *testing.T) {
	t.Parallel()
	r := bufio.NewReader(strings.NewReader(strings.Repeat("x", 20)))
	if _, err := readLineLimit(r, 8); err == nil {
		t.Fatal("expected too long")
	}
}

func TestListenHostIsLoopback(t *testing.T) {
	t.Parallel()
	if !ListenHostIsLoopback("127.0.0.1:9090") || !ListenHostIsLoopback("[::1]:9090") || !ListenHostIsLoopback("localhost:9090") {
		t.Fatal("expected loopback")
	}
	if ListenHostIsLoopback("0.0.0.0:9090") || ListenHostIsLoopback(":9090") || ListenHostIsLoopback("not-an-addr") {
		t.Fatal("expected non-loopback")
	}
}
