package tunnel

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	Version        = 1
	headerSize     = 8
	MaxPayloadSize = 64 * 1024
)

// Type is a control/handshake frame type. Data bytes after OpenStreamAck are raw.
type Type uint8

const (
	TypeAuthRequest Type = iota + 1
	TypeAuthResponse
	TypeOpenStream
	TypeOpenStreamAck
	TypeCloseStream
	TypePing
	TypePong
	TypeConfigPush
	TypeOpenAssoc
	TypeOpenAssocAck
	TypeDatagram
	TypeCloseAssoc
)

func (t Type) String() string {
	switch t {
	case TypeAuthRequest:
		return "AuthRequest"
	case TypeAuthResponse:
		return "AuthResponse"
	case TypeOpenStream:
		return "OpenStream"
	case TypeOpenStreamAck:
		return "OpenStreamAck"
	case TypeCloseStream:
		return "CloseStream"
	case TypePing:
		return "Ping"
	case TypePong:
		return "Pong"
	case TypeConfigPush:
		return "ConfigPush"
	case TypeOpenAssoc:
		return "OpenAssoc"
	case TypeOpenAssocAck:
		return "OpenAssocAck"
	case TypeDatagram:
		return "Datagram"
	case TypeCloseAssoc:
		return "CloseAssoc"
	default:
		return fmt.Sprintf("Type(%d)", t)
	}
}

// AssocIDSize is the on-wire size of a UDP association id.
const AssocIDSize = 4

// MaxDatagramPayload is the max UDP payload bytes in a Datagram frame
// (assoc id consumes AssocIDSize of MaxPayloadSize).
const MaxDatagramPayload = MaxPayloadSize - AssocIDSize

const (
	ProtoTCP  uint8 = 1
	ProtoHTTP uint8 = 2
	ProtoUDP  uint8 = 3
)

// Frame is a versioned length-prefixed control message.
type Frame struct {
	Type    Type
	Flags   uint8
	Payload []byte
}

// WriteFrame writes one frame to w.
func WriteFrame(w io.Writer, typ Type, payload []byte) error {
	if len(payload) > MaxPayloadSize {
		return fmt.Errorf("payload too large: %d", len(payload))
	}
	var hdr [headerSize]byte
	hdr[0] = Version
	hdr[1] = byte(typ)
	binary.BigEndian.PutUint32(hdr[4:8], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	_, err := w.Write(payload)
	return err
}

// ReadFrame reads one frame from r.
func ReadFrame(r io.Reader) (*Frame, error) {
	var hdr [headerSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != Version {
		return nil, fmt.Errorf("unsupported protocol version %d", hdr[0])
	}
	n := binary.BigEndian.Uint32(hdr[4:8])
	if n > MaxPayloadSize {
		return nil, fmt.Errorf("payload too large: %d", n)
	}
	fr := &Frame{Type: Type(hdr[1]), Flags: hdr[2]}
	if n == 0 {
		return fr, nil
	}
	fr.Payload = make([]byte, n)
	if _, err := io.ReadFull(r, fr.Payload); err != nil {
		return nil, err
	}
	return fr, nil
}

func putString(buf []byte, s string) ([]byte, error) {
	if len(s) > 65535 {
		return nil, fmt.Errorf("string too long")
	}
	var n [2]byte
	binary.BigEndian.PutUint16(n[:], uint16(len(s)))
	buf = append(buf, n[:]...)
	buf = append(buf, s...)
	return buf, nil
}

func getString(b []byte) (string, []byte, error) {
	if len(b) < 2 {
		return "", nil, fmt.Errorf("truncated string")
	}
	n := int(binary.BigEndian.Uint16(b[:2]))
	b = b[2:]
	if len(b) < n {
		return "", nil, fmt.Errorf("truncated string body")
	}
	return string(b[:n]), b[n:], nil
}

// AuthRequest is sent by the agent before yamux starts.
type AuthRequest struct {
	Token   string
	AgentID string
}

func (a AuthRequest) Marshal() ([]byte, error) {
	buf := make([]byte, 0, 4+len(a.Token)+len(a.AgentID))
	var err error
	buf, err = putString(buf, a.Token)
	if err != nil {
		return nil, err
	}
	return putString(buf, a.AgentID)
}

func ParseAuthRequest(p []byte) (AuthRequest, error) {
	var a AuthRequest
	s, rest, err := getString(p)
	if err != nil {
		return a, err
	}
	a.Token = s
	s, rest, err = getString(rest)
	if err != nil {
		return a, err
	}
	a.AgentID = s
	if len(rest) != 0 {
		return a, fmt.Errorf("trailing bytes")
	}
	return a, nil
}

// AuthResponse is the edge reply to AuthRequest.
type AuthResponse struct {
	OK      bool
	Message string
}

func (a AuthResponse) Marshal() ([]byte, error) {
	buf := []byte{0}
	if a.OK {
		buf[0] = 1
	}
	return putString(buf, a.Message)
}

func ParseAuthResponse(p []byte) (AuthResponse, error) {
	var a AuthResponse
	if len(p) < 1 {
		return a, fmt.Errorf("truncated auth response")
	}
	a.OK = p[0] == 1
	s, rest, err := getString(p[1:])
	if err != nil {
		return a, err
	}
	a.Message = s
	if len(rest) != 0 {
		return a, fmt.Errorf("trailing bytes")
	}
	return a, nil
}

// OpenMeta is sent as the first frame on a yamux data stream.
type OpenMeta struct {
	Name       string
	Local      string
	ClientAddr string
	Proto      uint8
}

func (o OpenMeta) Marshal() ([]byte, error) {
	buf := []byte{o.Proto}
	var err error
	buf, err = putString(buf, o.Name)
	if err != nil {
		return nil, err
	}
	buf, err = putString(buf, o.Local)
	if err != nil {
		return nil, err
	}
	return putString(buf, o.ClientAddr)
}

func ParseOpenMeta(p []byte) (OpenMeta, error) {
	var o OpenMeta
	if len(p) < 1 {
		return o, fmt.Errorf("truncated open")
	}
	o.Proto = p[0]
	s, rest, err := getString(p[1:])
	if err != nil {
		return o, err
	}
	o.Name = s
	s, rest, err = getString(rest)
	if err != nil {
		return o, err
	}
	o.Local = s
	s, rest, err = getString(rest)
	if err != nil {
		return o, err
	}
	o.ClientAddr = s
	if len(rest) != 0 {
		return o, fmt.Errorf("trailing bytes")
	}
	return o, nil
}

// OpenAck is the agent reply before raw bytes flow.
type OpenAck struct {
	OK      bool
	Message string
}

func (a OpenAck) Marshal() ([]byte, error) {
	buf := []byte{0}
	if a.OK {
		buf[0] = 1
	}
	return putString(buf, a.Message)
}

func ParseOpenAck(p []byte) (OpenAck, error) {
	var a OpenAck
	if len(p) < 1 {
		return a, fmt.Errorf("truncated ack")
	}
	a.OK = p[0] == 1
	s, rest, err := getString(p[1:])
	if err != nil {
		return a, err
	}
	a.Message = s
	if len(rest) != 0 {
		return a, fmt.Errorf("trailing bytes")
	}
	return a, nil
}

func putU64(n uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], n)
	return b[:]
}

func getU64(p []byte) (uint64, error) {
	if len(p) != 8 {
		return 0, fmt.Errorf("ping payload must be 8 bytes")
	}
	return binary.BigEndian.Uint64(p), nil
}

// PingPayload is unix nanoseconds.
func PingPayload(nsec int64) []byte {
	return putU64(uint64(nsec))
}

func ParsePing(p []byte) (int64, error) {
	n, err := getU64(p)
	return int64(n), err
}

func putU32(n uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], n)
	return b[:]
}

func getU32(p []byte) (uint32, []byte, error) {
	if len(p) < 4 {
		return 0, nil, fmt.Errorf("truncated u32")
	}
	return binary.BigEndian.Uint32(p[:4]), p[4:], nil
}

// OpenAssoc opens a UDP association on a ProtoUDP yamux stream.
type OpenAssoc struct {
	ID         uint32
	ClientAddr string
}

func (o OpenAssoc) Marshal() ([]byte, error) {
	buf := putU32(o.ID)
	return putString(buf, o.ClientAddr)
}

func ParseOpenAssoc(p []byte) (OpenAssoc, error) {
	var o OpenAssoc
	id, rest, err := getU32(p)
	if err != nil {
		return o, err
	}
	o.ID = id
	s, rest, err := getString(rest)
	if err != nil {
		return o, err
	}
	o.ClientAddr = s
	if len(rest) != 0 {
		return o, fmt.Errorf("trailing bytes")
	}
	return o, nil
}

// OpenAssocAck is the agent reply to OpenAssoc.
type OpenAssocAck struct {
	ID      uint32
	OK      bool
	Message string
}

func (a OpenAssocAck) Marshal() ([]byte, error) {
	buf := putU32(a.ID)
	ok := byte(0)
	if a.OK {
		ok = 1
	}
	buf = append(buf, ok)
	return putString(buf, a.Message)
}

func ParseOpenAssocAck(p []byte) (OpenAssocAck, error) {
	var a OpenAssocAck
	id, rest, err := getU32(p)
	if err != nil {
		return a, err
	}
	a.ID = id
	if len(rest) < 1 {
		return a, fmt.Errorf("truncated assoc ack")
	}
	a.OK = rest[0] == 1
	s, rest, err := getString(rest[1:])
	if err != nil {
		return a, err
	}
	a.Message = s
	if len(rest) != 0 {
		return a, fmt.Errorf("trailing bytes")
	}
	return a, nil
}

// Datagram carries one UDP payload for an association.
type Datagram struct {
	ID      uint32
	Payload []byte
}

func (d Datagram) Marshal() ([]byte, error) {
	if len(d.Payload) > MaxDatagramPayload {
		return nil, fmt.Errorf("datagram too large: %d", len(d.Payload))
	}
	buf := putU32(d.ID)
	return append(buf, d.Payload...), nil
}

func ParseDatagram(p []byte) (Datagram, error) {
	var d Datagram
	id, rest, err := getU32(p)
	if err != nil {
		return d, err
	}
	d.ID = id
	d.Payload = rest
	return d, nil
}

// CloseAssoc tears down a UDP association.
type CloseAssoc struct {
	ID uint32
}

func (c CloseAssoc) Marshal() ([]byte, error) {
	return putU32(c.ID), nil
}

func ParseCloseAssoc(p []byte) (CloseAssoc, error) {
	var c CloseAssoc
	id, rest, err := getU32(p)
	if err != nil {
		return c, err
	}
	c.ID = id
	if len(rest) != 0 {
		return c, fmt.Errorf("trailing bytes")
	}
	return c, nil
}
