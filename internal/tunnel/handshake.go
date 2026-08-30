package tunnel

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"net"
	"time"
)

const HandshakeTimeout = 10 * time.Second

// ServerHandshake authenticates an inbound TLS connection. It always writes an
// AuthResponse so the client can distinguish auth failure from network errors.
func ServerHandshake(conn net.Conn, token string, timeout time.Duration) (agentID string, err error) {
	if timeout <= 0 {
		timeout = HandshakeTimeout
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	fr, err := ReadFrame(conn)
	if err != nil {
		return "", fmt.Errorf("read auth: %w", err)
	}
	if fr.Type != TypeAuthRequest {
		_ = writeAuth(conn, false, "unauthorized")
		return "", fmt.Errorf("expected AuthRequest, got %s", fr.Type)
	}
	req, err := ParseAuthRequest(fr.Payload)
	if err != nil {
		_ = writeAuth(conn, false, "unauthorized")
		return "", err
	}
	if !tokenValid(req.Token, token) {
		_ = writeAuth(conn, false, "unauthorized")
		return "", fmt.Errorf("unauthorized")
	}
	if err := writeAuth(conn, true, "ok"); err != nil {
		return "", err
	}
	return req.AgentID, nil
}

// ClientHandshake sends the tunnel token and waits for AuthResponse.
func ClientHandshake(conn net.Conn, token, agentID string, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = HandshakeTimeout
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	payload, err := (AuthRequest{Token: token, AgentID: agentID}).Marshal()
	if err != nil {
		return err
	}
	if err := WriteFrame(conn, TypeAuthRequest, payload); err != nil {
		return err
	}
	fr, err := ReadFrame(conn)
	if err != nil {
		return fmt.Errorf("read auth response: %w", err)
	}
	if fr.Type != TypeAuthResponse {
		return fmt.Errorf("expected AuthResponse, got %s", fr.Type)
	}
	resp, err := ParseAuthResponse(fr.Payload)
	if err != nil {
		return err
	}
	if !resp.OK {
		if resp.Message == "" {
			return fmt.Errorf("unauthorized")
		}
		return fmt.Errorf("auth rejected: %s", resp.Message)
	}
	return nil
}

func writeAuth(conn net.Conn, ok bool, msg string) error {
	payload, err := (AuthResponse{OK: ok, Message: msg}).Marshal()
	if err != nil {
		return err
	}
	return WriteFrame(conn, TypeAuthResponse, payload)
}

func tokenValid(got, want string) bool {
	gh := sha256.Sum256([]byte(got))
	wh := sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(gh[:], wh[:]) == 1
}
