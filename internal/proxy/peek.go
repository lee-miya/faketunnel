package proxy

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"golang.org/x/net/http2/hpack"
)

const (
	maxPeekBytes       = 64 * 1024
	tlsRecordHeaderLen = 5
	tlsMaxRecord       = 16384
	http2PrefaceLen    = 24
	http2FrameHeader   = 9
)

// HTTP2ClientPreface is the RFC 9113 client connection preface.
const HTTP2ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

const (
	frameHeaders      = 0x1
	frameContinuation = 0x9
	flagEndHeaders    = 0x4
	flagPadded        = 0x8
	flagPriority      = 0x20
)

// HTTPHead is the routing metadata extracted from the first HTTP request
// (HTTP/1.x or HTTP/2) without consuming bytes from the caller's perspective
// when replayed via WithPrefix.
type HTTPHead struct {
	Host  string
	Path  string
	HTTP2 bool
	Raw   []byte
}

// PeekClientHello reads a TLS ClientHello and returns the SNI plus every byte
// consumed (record headers included) so the handshake can be replayed.
func PeekClientHello(r io.Reader) (sni string, raw []byte, err error) {
	var handshake []byte
	for {
		rec, err := readTLSRecord(r)
		raw = append(raw, rec...)
		if err != nil {
			return "", raw, err
		}
		if len(raw) > maxPeekBytes {
			return "", raw, fmt.Errorf("tls client hello too large")
		}
		if rec[0] != 0x16 {
			return "", raw, fmt.Errorf("not a tls handshake record")
		}
		handshake = append(handshake, rec[tlsRecordHeaderLen:]...)
		if len(handshake) < 4 {
			continue
		}
		if handshake[0] != 0x01 {
			return "", raw, fmt.Errorf("not a tls client hello")
		}
		hsLen := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
		if len(handshake) < 4+hsLen {
			continue
		}
		sni, err = parseHelloSNI(handshake[4 : 4+hsLen])
		return sni, raw, err
	}
}

func readTLSRecord(r io.Reader) ([]byte, error) {
	hdr := make([]byte, tlsRecordHeaderLen)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return hdr[:0], err
	}
	n := int(binary.BigEndian.Uint16(hdr[3:5]))
	if n == 0 || n > tlsMaxRecord {
		return hdr, fmt.Errorf("invalid tls record length %d", n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return append(hdr, body...), err
	}
	return append(hdr, body...), nil
}

func parseHelloSNI(body []byte) (string, error) {
	// version(2) + random(32) + session_id
	if len(body) < 34 {
		return "", fmt.Errorf("truncated client hello")
	}
	off := 34
	if off >= len(body) {
		return "", fmt.Errorf("truncated session id")
	}
	sidLen := int(body[off])
	off++
	off += sidLen
	if off+2 > len(body) {
		return "", fmt.Errorf("truncated cipher suites")
	}
	csLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2 + csLen
	if off >= len(body) {
		return "", fmt.Errorf("truncated compression")
	}
	compLen := int(body[off])
	off++
	off += compLen
	if off == len(body) {
		return "", nil // no extensions
	}
	if off+2 > len(body) {
		return "", fmt.Errorf("truncated extensions length")
	}
	extLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	end := off + extLen
	if end > len(body) {
		return "", fmt.Errorf("truncated extensions")
	}
	for off+4 <= end {
		typ := binary.BigEndian.Uint16(body[off : off+2])
		n := int(binary.BigEndian.Uint16(body[off+2 : off+4]))
		off += 4
		if off+n > end {
			return "", fmt.Errorf("truncated extension")
		}
		data := body[off : off+n]
		off += n
		if typ != 0 {
			continue
		}
		sni, err := parseSNIExtension(data)
		if err != nil {
			return "", err
		}
		return sni, nil
	}
	return "", nil
}

func parseSNIExtension(data []byte) (string, error) {
	if len(data) < 2 {
		return "", fmt.Errorf("truncated sni list")
	}
	listLen := int(binary.BigEndian.Uint16(data[:2]))
	off := 2
	if 2+listLen > len(data) {
		return "", fmt.Errorf("truncated sni list body")
	}
	for off+3 <= 2+listLen {
		nameType := data[off]
		n := int(binary.BigEndian.Uint16(data[off+1 : off+3]))
		off += 3
		if off+n > 2+listLen {
			return "", fmt.Errorf("truncated sni name")
		}
		name := data[off : off+n]
		off += n
		if nameType == 0 {
			return string(name), nil
		}
	}
	return "", nil
}

// PeekHTTP reads enough of the first request to get Host / :authority and path.
func PeekHTTP(r io.Reader) (HTTPHead, error) {
	var head HTTPHead
	buf := make([]byte, 0, 512)
	tmp := make([]byte, 512)
	for len(buf) < http2PrefaceLen {
		n, err := r.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			head.Raw = buf
			if len(buf) == 0 {
				return head, err
			}
			break
		}
		if len(buf) > maxPeekBytes {
			head.Raw = buf
			return head, fmt.Errorf("http peek too large")
		}
	}
	if len(buf) >= http2PrefaceLen && string(buf[:http2PrefaceLen]) == HTTP2ClientPreface {
		return peekHTTP2(r, buf)
	}
	return peekHTTP1(r, buf)
}

func peekHTTP1(r io.Reader, buf []byte) (HTTPHead, error) {
	head := HTTPHead{Raw: buf}
	tmp := make([]byte, 1024)
	for {
		if i := bytes.Index(head.Raw, []byte("\r\n\r\n")); i >= 0 {
			if err := parseHTTP1Head(head.Raw[:i], &head); err != nil {
				return head, err
			}
			return head, nil
		}
		if len(head.Raw) > maxPeekBytes {
			return head, fmt.Errorf("http/1 headers too large")
		}
		n, err := r.Read(tmp)
		if n > 0 {
			head.Raw = append(head.Raw, tmp[:n]...)
		}
		if err != nil {
			if len(head.Raw) == 0 {
				return head, err
			}
			return head, fmt.Errorf("incomplete http/1 headers: %w", err)
		}
	}
}

func parseHTTP1Head(hdr []byte, head *HTTPHead) error {
	lines := bytes.Split(hdr, []byte("\r\n"))
	if len(lines) == 0 {
		return fmt.Errorf("empty http/1 request")
	}
	req := strings.SplitN(string(lines[0]), " ", 3)
	if len(req) < 2 {
		return fmt.Errorf("bad http/1 request line")
	}
	head.Path = pathOnly(req[1])
	for _, line := range lines[1:] {
		if len(line) == 0 {
			continue
		}
		name, val, ok := bytes.Cut(line, []byte(":"))
		if !ok {
			continue
		}
		if strings.EqualFold(string(name), "Host") {
			head.Host = string(bytes.TrimSpace(val))
			return nil
		}
	}
	return nil
}

func peekHTTP2(r io.Reader, buf []byte) (HTTPHead, error) {
	head := HTTPHead{HTTP2: true, Raw: buf}
	off := http2PrefaceLen
	var block []byte
	inHeaders := false
	tmp := make([]byte, 2048)
	for {
		for off+http2FrameHeader <= len(head.Raw) {
			length := int(head.Raw[off])<<16 | int(head.Raw[off+1])<<8 | int(head.Raw[off+2])
			end := off + http2FrameHeader + length
			if end > len(head.Raw) {
				break
			}
			ftype := head.Raw[off+3]
			flags := head.Raw[off+4]
			payload := head.Raw[off+http2FrameHeader : end]
			off = end
			switch ftype {
			case frameHeaders:
				if inHeaders {
					return head, fmt.Errorf("nested http2 headers")
				}
				frag, err := headersFragment(payload, flags)
				if err != nil {
					return head, err
				}
				block = append(block, frag...)
				inHeaders = true
				if flags&flagEndHeaders != 0 {
					if err := decodeHPACK(block, &head); err != nil {
						return head, err
					}
					return head, nil
				}
			case frameContinuation:
				if !inHeaders {
					return head, fmt.Errorf("http2 continuation without headers")
				}
				block = append(block, payload...)
				if flags&flagEndHeaders != 0 {
					if err := decodeHPACK(block, &head); err != nil {
						return head, err
					}
					return head, nil
				}
			default:
				if inHeaders {
					return head, fmt.Errorf("http2 frame %d during headers", ftype)
				}
			}
		}
		if len(head.Raw) > maxPeekBytes {
			return head, fmt.Errorf("http2 peek too large")
		}
		n, err := r.Read(tmp)
		if n > 0 {
			head.Raw = append(head.Raw, tmp[:n]...)
		}
		if err != nil {
			return head, fmt.Errorf("incomplete http2 preface: %w", err)
		}
	}
}

func headersFragment(payload []byte, flags byte) ([]byte, error) {
	if flags&flagPadded != 0 {
		if len(payload) < 1 {
			return nil, fmt.Errorf("short padded headers")
		}
		pad := int(payload[0])
		payload = payload[1:]
		if pad > len(payload) {
			return nil, fmt.Errorf("headers padding too long")
		}
		payload = payload[:len(payload)-pad]
	}
	if flags&flagPriority != 0 {
		if len(payload) < 5 {
			return nil, fmt.Errorf("short priority headers")
		}
		payload = payload[5:]
	}
	return payload, nil
}

func decodeHPACK(block []byte, head *HTTPHead) error {
	dec := hpack.NewDecoder(4096, nil)
	fields, err := dec.DecodeFull(block)
	if err != nil {
		return fmt.Errorf("hpack: %w", err)
	}
	for _, f := range fields {
		switch f.Name {
		case ":authority":
			head.Host = f.Value
		case ":path":
			head.Path = pathOnly(f.Value)
		}
	}
	return nil
}

func pathOnly(p string) string {
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	if p == "" {
		return "/"
	}
	return p
}
