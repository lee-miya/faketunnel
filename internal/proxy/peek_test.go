package proxy

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"testing"

	"golang.org/x/net/http2/hpack"
)

func TestWithPrefixReplaysThenReads(t *testing.T) {
	t.Parallel()
	c, s := net.Pipe()
	t.Cleanup(func() { _ = c.Close(); _ = s.Close() })
	go func() {
		_, _ = s.Write([]byte("world"))
		_ = s.Close()
	}()
	pc := WithPrefix(c, []byte("hello"))
	got, err := io.ReadAll(pc)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "helloworld" {
		t.Fatalf("got %q", got)
	}
}

func TestPeekHTTP1HostPath(t *testing.T) {
	t.Parallel()
	raw := "GET /healthz?x=1 HTTP/1.1\r\nHost: A.Example:80\r\nAccept: */*\r\n\r\nbody"
	head, err := PeekHTTP(bytes.NewReader([]byte(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if head.HTTP2 {
		t.Fatal("expected http/1")
	}
	if head.Host != "A.Example:80" || head.Path != "/healthz" {
		t.Fatalf("host=%q path=%q", head.Host, head.Path)
	}
	if string(head.Raw) != raw {
		t.Fatalf("did not preserve extra body bytes")
	}
}

func TestPeekHTTP2AuthorityPath(t *testing.T) {
	t.Parallel()
	var block bytes.Buffer
	enc := hpack.NewEncoder(&block)
	fields := []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "h2.example"},
		{Name: ":path", Value: "/ping?q=1"},
	}
	for _, f := range fields {
		if err := enc.WriteField(f); err != nil {
			t.Fatal(err)
		}
	}
	frag := block.Bytes()
	frame := make([]byte, 9+len(frag))
	frame[0] = byte(len(frag) >> 16)
	frame[1] = byte(len(frag) >> 8)
	frame[2] = byte(len(frag))
	frame[3] = frameHeaders
	frame[4] = flagEndHeaders
	// stream id 1
	frame[8] = 1
	copy(frame[9:], frag)

	raw := append([]byte(HTTP2ClientPreface), frame...)
	head, err := PeekHTTP(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if !head.HTTP2 {
		t.Fatal("expected http2")
	}
	if head.Host != "h2.example" || head.Path != "/ping" {
		t.Fatalf("host=%q path=%q", head.Host, head.Path)
	}
	if !bytes.Equal(head.Raw, raw) {
		t.Fatal("raw mismatch")
	}
}

func TestPeekClientHelloSNI(t *testing.T) {
	t.Parallel()
	c, s := net.Pipe()
	t.Cleanup(func() { _ = c.Close(); _ = s.Close() })
	errc := make(chan error, 1)
	go func() {
		cli := tls.Client(c, &tls.Config{
			ServerName:         "sni.example",
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		})
		errc <- cli.Handshake()
	}()
	sni, raw, err := PeekClientHello(s)
	if err != nil {
		t.Fatal(err)
	}
	if sni != "sni.example" {
		t.Fatalf("sni=%q", sni)
	}
	if len(raw) < 10 || raw[0] != 0x16 {
		t.Fatalf("unexpected hello len=%d", len(raw))
	}
	// Completing handshake is optional; close so client unblocks.
	_ = s.Close()
	<-errc
}
