package tunnel

import (
	"fmt"
	"net"
	"testing"
	"time"
)

func TestHandshakeOK(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	errc := make(chan error, 2)
	var agentID string
	go func() {
		id, err := ServerHandshake(a, "secret-token", time.Second)
		agentID = id
		errc <- err
	}()
	go func() {
		errc <- ClientHandshake(b, "secret-token", "agent-1", time.Second)
	}()
	for i := 0; i < 2; i++ {
		if err := <-errc; err != nil {
			t.Fatal(err)
		}
	}
	if agentID != "agent-1" {
		t.Fatalf("agent id=%q", agentID)
	}
}

func TestHandshakeBadToken(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	errc := make(chan error, 2)
	go func() {
		_, err := ServerHandshake(a, "secret-token", time.Second)
		errc <- err
	}()
	go func() {
		errc <- ClientHandshake(b, "wrong", "agent-1", time.Second)
	}()
	sErr := <-errc
	cErr := <-errc
	if sErr == nil || cErr == nil {
		t.Fatalf("expected both sides to fail, server=%v client=%v", sErr, cErr)
	}
}

func TestHandshakeTimeout(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() { time.Sleep(50 * time.Millisecond); b.Close() }()
	_, err := ServerHandshake(a, "t", 80*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout or eof")
	}
}

func TestTokenValid(t *testing.T) {
	t.Parallel()
	if !tokenValid("abc", "abc") {
		t.Fatal("same token")
	}
	if tokenValid("abc", "abd") {
		t.Fatal("different token")
	}
	if tokenValid("abc", "abcd") {
		t.Fatal("length mismatch")
	}
}

func TestHandshakeWrongFrame(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	errc := make(chan error, 1)
	go func() {
		_, err := ServerHandshake(a, "t", time.Second)
		errc <- err
	}()
	if err := WriteFrame(b, TypePing, nil); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; err == nil {
		t.Fatal("expected error")
	}
}

func ExampleType_String() {
	fmt.Print(TypeAuthRequest)
	// Output: AuthRequest
}
