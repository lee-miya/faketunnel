package edge

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"faketunnel/internal/config"
	"faketunnel/internal/proxy"
	"faketunnel/internal/safe"
	"faketunnel/internal/tunnel"
)

type udpHub struct {
	s      *Server
	tun    config.Tunnel
	pc     net.PacketConn
	stream net.Conn
	idle   time.Duration

	writeMu sync.Mutex

	mu     sync.Mutex
	byID   map[uint32]*udpAssoc
	byAddr map[string]*udpAssoc
	nextID uint32
	closed bool
	doneCh chan struct{}
}

type udpAssoc struct {
	id     uint32
	client *net.UDPAddr

	mu         sync.Mutex
	lastActive time.Time

	ready chan struct{}
	err   error
}

func (s *Server) startUDP(ctx context.Context) error {
	s.udpHubs = make(map[string]*udpHub)
	s.udpPC = make(map[string]net.PacketConn)
	for _, t := range s.cfg.UDPTunnels() {
		pc, err := net.ListenPacket("udp", t.Public)
		if err != nil {
			_ = s.closeListeners()
			return fmt.Errorf("listen udp %s: %w", t.Public, err)
		}
		s.udpPC[t.Name] = pc
		s.log.Info("udp listen", "tunnel", t.Name, "addr", pc.LocalAddr().String(), "local", t.Local)
		tun := t
		s.wg.Add(1)
		safe.Go(s.log, "udp-"+tun.Name, func() {
			defer s.wg.Done()
			s.serveUDP(ctx, tun, pc)
		})
	}
	return nil
}

func (s *Server) serveUDP(ctx context.Context, tun config.Tunnel, pc net.PacketConn) {
	buf := make([]byte, proxy.MaxUDPPayload)
	for {
		_ = pc.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			s.log.Debug("udp read", "tunnel", tun.Name, "err", err)
			return
		}
		if n == 0 {
			continue
		}
		if n > proxy.MaxUDPPayload {
			s.log.Warn("udp packet too large", "tunnel", tun.Name, "n", n)
			continue
		}
		payload := make([]byte, n)
		copy(payload, buf[:n])
		ua, ok := addr.(*net.UDPAddr)
		if !ok || ua == nil {
			continue
		}
		if !s.publicAllowed(ua.IP, "udp", tun.Name) {
			continue
		}
		hub, err := s.getOrOpenUDPHub(tun, pc)
		if err != nil {
			s.log.Warn("udp hub", "tunnel", tun.Name, "err", err)
			continue
		}
		if err := hub.forward(ua, payload); err != nil {
			s.log.Debug("udp forward", "tunnel", tun.Name, "err", err)
		}
	}
}

func (s *Server) getOrOpenUDPHub(tun config.Tunnel, pc net.PacketConn) (*udpHub, error) {
	s.udpMu.Lock()
	defer s.udpMu.Unlock()
	if h, ok := s.udpHubs[tun.Name]; ok && h != nil && !h.closed {
		return h, nil
	}
	sess := s.getSession()
	if sess == nil {
		return nil, fmt.Errorf("no agent connected")
	}
	stream, err := sess.OpenData(tunnel.OpenMeta{
		Name:  tun.Name,
		Local: tun.Local,
		Proto: tunnel.ProtoUDP,
	})
	if err != nil {
		return nil, err
	}
	h := &udpHub{
		s:      s,
		tun:    tun,
		pc:     pc,
		stream: stream,
		idle:   s.cfg.UDPIdleOrDefault(),
		byID:   make(map[uint32]*udpAssoc),
		byAddr: make(map[string]*udpAssoc),
		nextID: 1,
		doneCh: make(chan struct{}),
	}
	s.udpHubs[tun.Name] = h
	s.log.Info("udp hub open", "tunnel", tun.Name)
	safe.Go(s.log, "udp-hub-read-"+tun.Name, func() { h.readLoop() })
	safe.Go(s.log, "udp-hub-reap-"+tun.Name, func() { h.reapLoop() })
	return h, nil
}

func (s *Server) closeUDPHubs() {
	s.udpMu.Lock()
	hubs := make([]*udpHub, 0, len(s.udpHubs))
	for _, h := range s.udpHubs {
		hubs = append(hubs, h)
	}
	s.udpHubs = make(map[string]*udpHub)
	s.udpMu.Unlock()
	for _, h := range hubs {
		if h != nil {
			h.close()
		}
	}
}

func (h *udpHub) forward(client *net.UDPAddr, payload []byte) error {
	a, err := h.ensureAssoc(client)
	if err != nil {
		return err
	}
	a.touch()
	dg, err := (tunnel.Datagram{ID: a.id, Payload: payload}).Marshal()
	if err != nil {
		return err
	}
	return h.writeFrame(tunnel.TypeDatagram, dg)
}

func (h *udpHub) ensureAssoc(client *net.UDPAddr) (*udpAssoc, error) {
	key := client.String()
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil, fmt.Errorf("hub closed")
	}
	if a, ok := h.byAddr[key]; ok {
		h.mu.Unlock()
		<-a.ready
		if a.err != nil {
			return nil, a.err
		}
		return a, nil
	}
	if len(h.byID) >= h.s.cfg.MaxSessionsOrDefault() {
		h.mu.Unlock()
		return nil, fmt.Errorf("max udp associations reached")
	}
	id := h.nextID
	h.nextID++
	a := &udpAssoc{
		id:         id,
		client:     cloneUDPAddr(client),
		lastActive: time.Now(),
		ready:      make(chan struct{}),
	}
	h.byID[id] = a
	h.byAddr[key] = a
	h.mu.Unlock()

	payload, err := (tunnel.OpenAssoc{ID: id, ClientAddr: key}).Marshal()
	if err != nil {
		h.failAssoc(a, err)
		return nil, err
	}
	if err := h.writeFrame(tunnel.TypeOpenAssoc, payload); err != nil {
		h.failAssoc(a, err)
		return nil, err
	}

	timer := time.NewTimer(tunnel.OpenTimeout)
	defer timer.Stop()
	select {
	case <-a.ready:
	case <-timer.C:
		// Prefer success if ack raced the timer.
		select {
		case <-a.ready:
		default:
			err := fmt.Errorf("open assoc timeout")
			h.failAssoc(a, err)
			ca, _ := (tunnel.CloseAssoc{ID: id}).Marshal()
			_ = h.writeFrame(tunnel.TypeCloseAssoc, ca)
			return nil, err
		}
	}
	if a.err != nil {
		return nil, a.err
	}
	return a, nil
}

func (h *udpHub) failAssoc(a *udpAssoc, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	a.err = err
	select {
	case <-a.ready:
	default:
		close(a.ready)
	}
	delete(h.byID, a.id)
	if a.client != nil {
		delete(h.byAddr, a.client.String())
	}
}

func (a *udpAssoc) touch() {
	a.mu.Lock()
	a.lastActive = time.Now()
	a.mu.Unlock()
}

func (a *udpAssoc) idleBefore(cutoff time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lastActive.Before(cutoff)
}

func (h *udpHub) markReady(id uint32, ok bool, msg string) {
	h.mu.Lock()
	a := h.byID[id]
	if a == nil {
		h.mu.Unlock()
		return
	}
	if !ok {
		h.mu.Unlock()
		if msg == "" {
			msg = "agent rejected assoc"
		}
		h.failAssoc(a, fmt.Errorf("%s", msg))
		return
	}
	select {
	case <-a.ready:
		h.mu.Unlock()
		return
	default:
		a.err = nil
		close(a.ready)
	}
	h.mu.Unlock()
	h.s.reg.AddSessions(1)
}

func (h *udpHub) readLoop() {
	defer h.close()
	for {
		_ = h.stream.SetReadDeadline(time.Now().Add(h.idle + time.Minute))
		fr, err := tunnel.ReadFrame(h.stream)
		if err != nil {
			return
		}
		switch fr.Type {
		case tunnel.TypeOpenAssocAck:
			ack, err := tunnel.ParseOpenAssocAck(fr.Payload)
			if err != nil {
				h.s.log.Debug("udp assoc ack", "err", err)
				continue
			}
			h.markReady(ack.ID, ack.OK, ack.Message)
		case tunnel.TypeDatagram:
			dg, err := tunnel.ParseDatagram(fr.Payload)
			if err != nil {
				continue
			}
			h.deliver(dg.ID, dg.Payload)
		case tunnel.TypeCloseAssoc:
			ca, err := tunnel.ParseCloseAssoc(fr.Payload)
			if err != nil {
				continue
			}
			h.removeAssoc(ca.ID, false)
		default:
			h.s.log.Debug("udp hub unexpected frame", "type", fr.Type.String())
		}
	}
}

func (h *udpHub) deliver(id uint32, payload []byte) {
	h.mu.Lock()
	a := h.byID[id]
	h.mu.Unlock()
	if a == nil || a.client == nil {
		return
	}
	a.touch()
	if _, err := h.pc.WriteTo(payload, a.client); err != nil {
		h.s.log.Debug("udp write to client", "err", err)
	}
}

func (h *udpHub) removeAssoc(id uint32, notify bool) {
	h.mu.Lock()
	a := h.byID[id]
	if a == nil {
		h.mu.Unlock()
		return
	}
	delete(h.byID, id)
	if a.client != nil {
		delete(h.byAddr, a.client.String())
	}
	wasReady := false
	select {
	case <-a.ready:
		wasReady = a.err == nil
	default:
		a.err = fmt.Errorf("assoc closed")
		close(a.ready)
	}
	h.mu.Unlock()
	if wasReady {
		h.s.reg.AddSessions(-1)
	}
	if notify {
		ca, _ := (tunnel.CloseAssoc{ID: id}).Marshal()
		_ = h.writeFrame(tunnel.TypeCloseAssoc, ca)
	}
}

func (h *udpHub) reapLoop() {
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

func (h *udpHub) reapIdle() {
	cutoff := time.Now().Add(-h.idle)
	var stale []uint32
	h.mu.Lock()
	for id, a := range h.byID {
		select {
		case <-a.ready:
			if a.err == nil && a.idleBefore(cutoff) {
				stale = append(stale, id)
			}
		default:
		}
	}
	h.mu.Unlock()
	for _, id := range stale {
		h.s.log.Debug("udp assoc idle close", "tunnel", h.tun.Name, "id", id)
		h.removeAssoc(id, true)
	}
}

func (h *udpHub) writeFrame(typ tunnel.Type, payload []byte) error {
	h.writeMu.Lock()
	defer h.writeMu.Unlock()
	if h.closed {
		return fmt.Errorf("hub closed")
	}
	_ = h.stream.SetWriteDeadline(time.Now().Add(10 * time.Second))
	err := tunnel.WriteFrame(h.stream, typ, payload)
	_ = h.stream.SetWriteDeadline(time.Time{})
	return err
}

func (h *udpHub) close() {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	h.closed = true
	close(h.doneCh)
	var live int64
	for id, a := range h.byID {
		select {
		case <-a.ready:
			if a.err == nil {
				live++
			}
		default:
			a.err = fmt.Errorf("hub closed")
			close(a.ready)
		}
		delete(h.byID, id)
		if a.client != nil {
			delete(h.byAddr, a.client.String())
		}
	}
	h.mu.Unlock()
	if live > 0 {
		h.s.reg.AddSessions(-live)
	}
	_ = h.stream.Close()
	h.s.udpMu.Lock()
	if h.s.udpHubs[h.tun.Name] == h {
		delete(h.s.udpHubs, h.tun.Name)
	}
	h.s.udpMu.Unlock()
}

func cloneUDPAddr(a *net.UDPAddr) *net.UDPAddr {
	if a == nil {
		return nil
	}
	out := *a
	if a.IP != nil {
		out.IP = append(net.IP(nil), a.IP...)
	}
	return &out
}
