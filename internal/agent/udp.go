package agent

import (
	"fmt"
	"net"
	"sync"
	"time"

	"faketunnel/internal/proxy"
	"faketunnel/internal/safe"
	"faketunnel/internal/tunnel"
)

type udpStream struct {
	c      *Client
	stream net.Conn
	meta   tunnel.OpenMeta
	local  string
	idle   time.Duration

	writeMu sync.Mutex

	mu     sync.Mutex
	assocs map[uint32]*udpLocalAssoc
	closed bool
	doneCh chan struct{}
}

type udpLocalAssoc struct {
	id     uint32
	conn   *net.UDPConn
	cancel chan struct{}

	mu   sync.Mutex
	last time.Time
}

func (c *Client) handleUDPStream(stream net.Conn, meta tunnel.OpenMeta) {
	defer stream.Close()
	local, err := c.resolveLocal(meta)
	if err != nil {
		c.log.Warn("unknown tunnel", "name", meta.Name, "err", err)
		_ = tunnel.AckData(stream, false, err.Error())
		return
	}
	if err := proxy.ValidateLocal(local, c.cfg.PrivateOnly()); err != nil {
		c.log.Warn("local target rejected", "tunnel", meta.Name, "err", err)
		_ = tunnel.AckData(stream, false, err.Error())
		return
	}
	if err := tunnel.AckData(stream, true, "ok"); err != nil {
		return
	}
	c.log.Info("udp hub ready", "tunnel", meta.Name, "local", local)

	h := &udpStream{
		c:      c,
		stream: stream,
		meta:   meta,
		local:  local,
		idle:   c.cfg.UDPIdleOrDefault(),
		assocs: make(map[uint32]*udpLocalAssoc),
		doneCh: make(chan struct{}),
	}
	defer h.closeAll()
	safe.Go(c.log, "udp-reap-"+meta.Name, func() { h.reapLoop() })
	h.readLoop()
}

func (h *udpStream) readLoop() {
	for {
		_ = h.stream.SetReadDeadline(time.Now().Add(h.idle + time.Minute))
		fr, err := tunnel.ReadFrame(h.stream)
		if err != nil {
			return
		}
		switch fr.Type {
		case tunnel.TypeOpenAssoc:
			oa, err := tunnel.ParseOpenAssoc(fr.Payload)
			if err != nil {
				h.c.log.Debug("open assoc parse", "err", err)
				continue
			}
			h.openAssoc(oa)
		case tunnel.TypeDatagram:
			dg, err := tunnel.ParseDatagram(fr.Payload)
			if err != nil {
				continue
			}
			h.writeLocal(dg.ID, dg.Payload)
		case tunnel.TypeCloseAssoc:
			ca, err := tunnel.ParseCloseAssoc(fr.Payload)
			if err != nil {
				continue
			}
			h.closeAssoc(ca.ID, false)
		default:
			h.c.log.Debug("udp unexpected frame", "type", fr.Type.String())
		}
	}
}

func (h *udpStream) openAssoc(oa tunnel.OpenAssoc) {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		_ = h.writeAck(oa.ID, false, "hub closed")
		return
	}
	if _, exists := h.assocs[oa.ID]; exists {
		h.mu.Unlock()
		_ = h.writeAck(oa.ID, true, "ok")
		return
	}
	if len(h.assocs) >= h.c.cfg.MaxSessionsOrDefault() {
		h.mu.Unlock()
		_ = h.writeAck(oa.ID, false, "max associations")
		return
	}
	h.mu.Unlock()

	conn, err := proxy.DialUDPLocal(h.local, h.c.cfg.PrivateOnly())
	if err != nil {
		h.c.log.Warn("udp dial", "tunnel", h.meta.Name, "local", h.local, "err", err)
		_ = h.writeAck(oa.ID, false, "dial failed")
		return
	}
	a := &udpLocalAssoc{
		id:     oa.ID,
		conn:   conn,
		last:   time.Now(),
		cancel: make(chan struct{}),
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		_ = conn.Close()
		_ = h.writeAck(oa.ID, false, "hub closed")
		return
	}
	h.assocs[oa.ID] = a
	h.mu.Unlock()

	if err := h.writeAck(oa.ID, true, "ok"); err != nil {
		h.closeAssoc(oa.ID, false)
		return
	}
	h.c.log.Info("udp assoc open", "tunnel", h.meta.Name, "id", oa.ID, "client", oa.ClientAddr)
	safe.Go(h.c.log, fmt.Sprintf("udp-local-%d", oa.ID), func() { h.readLocal(a) })
}

func (h *udpStream) writeAck(id uint32, ok bool, msg string) error {
	payload, err := (tunnel.OpenAssocAck{ID: id, OK: ok, Message: msg}).Marshal()
	if err != nil {
		return err
	}
	return h.writeFrame(tunnel.TypeOpenAssocAck, payload)
}

func (a *udpLocalAssoc) touch() {
	a.mu.Lock()
	a.last = time.Now()
	a.mu.Unlock()
}

func (a *udpLocalAssoc) idleBefore(cutoff time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.last.Before(cutoff)
}

func (h *udpStream) writeLocal(id uint32, payload []byte) {
	h.mu.Lock()
	a := h.assocs[id]
	h.mu.Unlock()
	if a == nil {
		return
	}
	a.touch()
	if _, err := a.conn.Write(payload); err != nil {
		h.c.log.Debug("udp write local", "id", id, "err", err)
		h.closeAssoc(id, true)
	}
}

func (h *udpStream) readLocal(a *udpLocalAssoc) {
	buf := make([]byte, proxy.MaxUDPPayload)
	for {
		select {
		case <-a.cancel:
			return
		case <-h.doneCh:
			return
		default:
		}
		_ = a.conn.SetReadDeadline(time.Now().Add(h.idle))
		n, err := a.conn.Read(buf)
		if err != nil {
			select {
			case <-a.cancel:
				return
			case <-h.doneCh:
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				// idle checked by reapLoop; keep reading
				continue
			}
			h.closeAssoc(a.id, true)
			return
		}
		if n == 0 {
			continue
		}
		a.touch()
		payload := make([]byte, n)
		copy(payload, buf[:n])
		dg, err := (tunnel.Datagram{ID: a.id, Payload: payload}).Marshal()
		if err != nil {
			h.c.log.Debug("udp datagram too large", "n", n)
			continue
		}
		if err := h.writeFrame(tunnel.TypeDatagram, dg); err != nil {
			h.closeAssoc(a.id, false)
			return
		}
	}
}

func (h *udpStream) closeAssoc(id uint32, notify bool) {
	h.mu.Lock()
	a := h.assocs[id]
	if a == nil {
		h.mu.Unlock()
		return
	}
	delete(h.assocs, id)
	h.mu.Unlock()
	select {
	case <-a.cancel:
	default:
		close(a.cancel)
	}
	_ = a.conn.Close()
	if notify {
		ca, _ := (tunnel.CloseAssoc{ID: id}).Marshal()
		_ = h.writeFrame(tunnel.TypeCloseAssoc, ca)
	}
}

func (h *udpStream) reapLoop() {
	interval := h.idle / 2
	if interval < time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			h.reapIdle()
		case <-h.doneCh:
			return
		}
	}
}

func (h *udpStream) reapIdle() {
	cutoff := time.Now().Add(-h.idle)
	var stale []uint32
	h.mu.Lock()
	for id, a := range h.assocs {
		if a.idleBefore(cutoff) {
			stale = append(stale, id)
		}
	}
	h.mu.Unlock()
	for _, id := range stale {
		h.c.log.Debug("udp assoc idle close", "tunnel", h.meta.Name, "id", id)
		h.closeAssoc(id, true)
	}
}

func (h *udpStream) writeFrame(typ tunnel.Type, payload []byte) error {
	h.writeMu.Lock()
	defer h.writeMu.Unlock()
	if h.closed {
		return fmt.Errorf("closed")
	}
	_ = h.stream.SetWriteDeadline(time.Now().Add(10 * time.Second))
	err := tunnel.WriteFrame(h.stream, typ, payload)
	_ = h.stream.SetWriteDeadline(time.Time{})
	return err
}

func (h *udpStream) closeAll() {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	h.closed = true
	close(h.doneCh)
	ids := make([]uint32, 0, len(h.assocs))
	for id := range h.assocs {
		ids = append(ids, id)
	}
	h.mu.Unlock()
	for _, id := range ids {
		h.closeAssoc(id, false)
	}
}
