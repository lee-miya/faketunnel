package tunnel

import (
	"bytes"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	t.Parallel()
	payloads := [][]byte{nil, {}, []byte("hello"), bytes.Repeat([]byte("x"), 1024)}
	for _, p := range payloads {
		var buf bytes.Buffer
		if err := WriteFrame(&buf, TypePing, p); err != nil {
			t.Fatal(err)
		}
		fr, err := ReadFrame(&buf)
		if err != nil {
			t.Fatal(err)
		}
		if fr.Type != TypePing {
			t.Fatalf("type=%s", fr.Type)
		}
		if !bytes.Equal(fr.Payload, p) && !(len(p) == 0 && len(fr.Payload) == 0) {
			t.Fatalf("payload mismatch %q vs %q", p, fr.Payload)
		}
	}
}

func TestFrameRejectsBadVersion(t *testing.T) {
	t.Parallel()
	raw := []byte{99, byte(TypePing), 0, 0, 0, 0, 0, 0}
	if _, err := ReadFrame(bytes.NewReader(raw)); err == nil {
		t.Fatal("expected version error")
	}
}

func TestFrameRejectsHugePayload(t *testing.T) {
	t.Parallel()
	if err := WriteFrame(ioDiscard{}, TypePing, make([]byte, MaxPayloadSize+1)); err == nil {
		t.Fatal("expected too large")
	}
	hdr := []byte{Version, byte(TypePing), 0, 0, 0, 1, 0, 0} // 65536
	if _, err := ReadFrame(bytes.NewReader(hdr)); err == nil {
		t.Fatal("expected too large")
	}
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) { return len(p), nil }

func TestAuthOpenPingCodec(t *testing.T) {
	t.Parallel()
	ar := AuthRequest{Token: "tok", AgentID: "a1"}
	b, err := ar.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseAuthRequest(b)
	if err != nil || got != ar {
		t.Fatalf("auth req %v %v", got, err)
	}

	resp := AuthResponse{OK: true, Message: "ok"}
	b, err = resp.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	gr, err := ParseAuthResponse(b)
	if err != nil || gr != resp {
		t.Fatalf("auth resp %v %v", gr, err)
	}

	meta := OpenMeta{Name: "ssh", Local: "127.0.0.1:22", ClientAddr: "203.0.113.10:9", Proto: ProtoTCP}
	b, err = meta.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	gm, err := ParseOpenMeta(b)
	if err != nil || gm != meta {
		t.Fatalf("open %v %v", gm, err)
	}

	ack := OpenAck{OK: false, Message: "dial"}
	b, err = ack.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	ga, err := ParseOpenAck(b)
	if err != nil || ga != ack {
		t.Fatalf("ack %v %v", ga, err)
	}

	nsec := int64(123456789)
	p := PingPayload(nsec)
	n, err := ParsePing(p)
	if err != nil || n != nsec {
		t.Fatalf("ping %d %v", n, err)
	}

	oa := OpenAssoc{ID: 42, ClientAddr: "203.0.113.10:9"}
	b, err = oa.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	goa, err := ParseOpenAssoc(b)
	if err != nil || goa != oa {
		t.Fatalf("open assoc %v %v", goa, err)
	}

	oack := OpenAssocAck{ID: 42, OK: true, Message: "ok"}
	b, err = oack.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	goack, err := ParseOpenAssocAck(b)
	if err != nil || goack != oack {
		t.Fatalf("assoc ack %v %v", goack, err)
	}

	dg := Datagram{ID: 7, Payload: []byte("udp-payload")}
	b, err = dg.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	gdg, err := ParseDatagram(b)
	if err != nil || gdg.ID != dg.ID || string(gdg.Payload) != string(dg.Payload) {
		t.Fatalf("datagram %v %v", gdg, err)
	}

	ca := CloseAssoc{ID: 7}
	b, err = ca.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	gca, err := ParseCloseAssoc(b)
	if err != nil || gca != ca {
		t.Fatalf("close assoc %v %v", gca, err)
	}

	if _, err := (Datagram{ID: 1, Payload: make([]byte, MaxDatagramPayload+1)}).Marshal(); err == nil {
		t.Fatal("expected datagram too large")
	}
}

func TestParseTruncated(t *testing.T) {
	t.Parallel()
	if _, err := ParseAuthRequest([]byte{0}); err == nil {
		t.Fatal("expected error")
	}
	if _, err := ParseOpenMeta(nil); err == nil {
		t.Fatal("expected error")
	}
}
