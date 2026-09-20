package tunnel

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
)

func TestMuxConfigDoesNotKillTunnelOnSlowWrites(t *testing.T) {
	t.Parallel()
	c := muxConfig()
	if c.EnableKeepAlive {
		t.Fatal("yamux keepalive must be disabled: ping timeout closes the whole tunnel during large HTTP bodies")
	}
	if c.StreamOpenTimeout != 0 {
		t.Fatalf("StreamOpenTimeout=%s; must be 0 so one pending stream cannot close the session", c.StreamOpenTimeout)
	}
	if c.ConnectionWriteTimeout < time.Minute {
		t.Fatalf("ConnectionWriteTimeout=%s; too short for git/LFS over a slow uplink", c.ConnectionWriteTimeout)
	}
}

func TestFastCloseUnblocksPipeWrite(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	defer b.Close()
	wrapped := prepareMuxConn(a)

	started := make(chan struct{})
	errc := make(chan error, 1)
	go func() {
		close(started)
		buf := make([]byte, 32*1024)
		_, err := wrapped.Write(buf)
		errc <- err
	}()
	<-started
	time.Sleep(20 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		_ = wrapped.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("fastCloseConn.Close blocked")
	}
	select {
	case <-errc:
	case <-time.After(2 * time.Second):
		t.Fatal("write was not unblocked by Close")
	}
}

func TestYamuxOpenData(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	srv, err := ServerSession(a, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	cli, err := ClientSession(b, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	errc := make(chan error, 1)
	go func() {
		stream, meta, err := cli.AcceptData()
		if err != nil {
			errc <- err
			return
		}
		defer stream.Close()
		if meta.Name != "echo" || meta.Proto != ProtoTCP {
			errc <- errMismatch{meta}
			return
		}
		if err := AckData(stream, true, "ok"); err != nil {
			errc <- err
			return
		}
		buf := make([]byte, 4)
		if _, err := io.ReadFull(stream, buf); err != nil {
			errc <- err
			return
		}
		_, err = stream.Write(buf)
		errc <- err
	}()

	stream, err := srv.OpenData(OpenMeta{Name: "echo", Local: "127.0.0.1:9", ClientAddr: "127.0.0.1:1", Proto: ProtoTCP})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if _, err := stream.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 4)
	if err := stream.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(stream, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("ping")) {
		t.Fatalf("got %q", got)
	}
	select {
	case err := <-errc:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("agent side hung")
	}
}

type errMismatch struct{ meta OpenMeta }

func (e errMismatch) Error() string { return "meta mismatch: " + e.meta.Name }

func TestAckReject(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	srv, err := ServerSession(a, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	cli, err := ClientSession(b, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	go func() {
		stream, _, err := cli.AcceptData()
		if err != nil {
			return
		}
		_ = AckData(stream, false, "nope")
		_ = stream.Close()
	}()
	_, err = srv.OpenData(OpenMeta{Name: "x", Local: "127.0.0.1:1", Proto: ProtoTCP})
	if err == nil {
		t.Fatal("expected reject")
	}
}
