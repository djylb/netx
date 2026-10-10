package socks5

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/djylb/netx"
)

// PacketConn is the outbound side of a UDP association: it sends the client's
// datagrams to their destinations and receives the replies. Implementations
// may forward the datagrams elsewhere, such as through a tunnel; Addr keeps
// domain names unresolved for that purpose.
type PacketConn interface {
	// WriteTo sends p to dst. It must not retain p, which the caller reuses
	// once WriteTo returns.
	WriteTo(p []byte, dst Addr) (int, error)
	// ReadFrom reads the next reply and returns its source.
	ReadFrom(p []byte) (n int, src Addr, err error)
	// Close ends the association's outbound side and unblocks ReadFrom.
	Close() error
}

// How long NewPacketConn reuses a resolved name, and a failed lookup, so
// that datagrams to a name that does not resolve do not each wait for DNS.
const (
	dnsCacheTTL   = time.Minute
	dnsFailureTTL = 5 * time.Second
)

// NewPacketConn returns a PacketConn that sends and receives through c,
// resolving domain names with net.DefaultResolver and caching the results for
// a minute, and failed lookups for five seconds. Close ends the lookups in
// progress. Replies from any source are delivered, as with a full-cone NAT.
func NewPacketConn(c *net.UDPConn) PacketConn {
	ctx, cancel := context.WithCancel(context.Background())
	return &udpPacketConn{c: c, resolver: net.DefaultResolver, ctx: ctx, cancel: cancel, names: make(map[string]dnsEntry)}
}

type dnsEntry struct {
	ip      netip.Addr
	err     error
	expires time.Time
}

type udpPacketConn struct {
	c        *net.UDPConn
	resolver *net.Resolver
	ctx      context.Context // canceled by Close, ending lookups
	cancel   context.CancelFunc
	mu       sync.Mutex
	names    map[string]dnsEntry
}

func (u *udpPacketConn) WriteTo(p []byte, dst Addr) (int, error) {
	ip := dst.IP
	if !ip.IsValid() {
		var err error
		if ip, err = u.resolve(dst.Name); err != nil {
			return 0, err
		}
	}
	return u.c.WriteToUDPAddrPort(p, netip.AddrPortFrom(ip, dst.Port))
}

func (u *udpPacketConn) resolve(name string) (netip.Addr, error) {
	if name == "" {
		return netip.IPv4Unspecified(), nil
	}
	u.mu.Lock()
	entry, ok := u.names[name]
	u.mu.Unlock()
	if ok && time.Now().Before(entry.expires) {
		return entry.ip, entry.err
	}
	ip, err := u.lookup(name)
	if u.ctx.Err() != nil {
		return netip.Addr{}, net.ErrClosed
	}
	ttl := dnsCacheTTL
	if err != nil {
		ttl = dnsFailureTTL
	}
	u.mu.Lock()
	if len(u.names) >= 1024 {
		clear(u.names)
	}
	// The lookup may have taken seconds; the entry lasts from its end.
	u.names[name] = dnsEntry{ip: ip, err: err, expires: time.Now().Add(ttl)}
	u.mu.Unlock()
	return ip, err
}

func (u *udpPacketConn) lookup(name string) (netip.Addr, error) {
	ctx, cancel := context.WithTimeout(u.ctx, DefaultDialTimeout)
	defer cancel()
	ips, err := u.resolver.LookupNetIP(ctx, "ip", name)
	if err != nil {
		return netip.Addr{}, err
	}
	if len(ips) == 0 {
		return netip.Addr{}, &net.DNSError{Err: "no suitable address", Name: name, IsNotFound: true}
	}
	ip := ips[0]
	for _, candidate := range ips {
		if candidate.Is4() { // reachable from both IPv4 and dual-stack sockets
			ip = candidate
			break
		}
	}
	return ip.Unmap(), nil
}

func (u *udpPacketConn) ReadFrom(p []byte) (int, Addr, error) {
	n, ap, err := u.c.ReadFromUDPAddrPort(p)
	if err != nil {
		return n, Addr{}, err
	}
	return n, Addr{IP: ap.Addr().Unmap(), Port: ap.Port()}, nil
}

func (u *udpPacketConn) Close() error {
	u.cancel()
	return u.c.Close()
}

// udpRelay routes the datagrams arriving on one socket to the associations of
// their clients.
type udpRelay struct {
	l       *netx.PacketListener
	mu      sync.Mutex
	pending map[netip.Addr][]*association // by client IP, until the first datagram
	anyPeer *association                  // takes the first source, on its own socket
	closed  bool
}

func (s *Server) newUDPRelay(pc net.PacketConn) *udpRelay {
	r := &udpRelay{pending: make(map[netip.Addr][]*association)}
	queue := s.UDPQueue
	if queue <= 0 {
		queue = 128
	}
	r.l = netx.NewPacketListener(pc,
		netx.WithAcceptFilter(r.expects),
		netx.WithPacketQueue(queue),
		netx.WithIdleTimeout(positive(s.UDPIdleTimeout, DefaultUDPIdleTimeout)),
	)
	go r.acceptLoop()
	return r
}

// sharedRelay returns the relay of PacketConn, starting it on first use.
func (s *Server) sharedRelay() (*udpRelay, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrServerClosed
	}
	if s.shared == nil {
		s.shared = s.newUDPRelay(s.PacketConn)
	}
	return s.shared, nil
}

// expects reports whether an association waits for datagrams from peer's IP.
func (r *udpRelay) expects(peer net.Addr) bool {
	ap := peerAddrPort(peer)
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.anyPeer != nil || len(r.pending[ap.Addr()]) > 0
}

func (r *udpRelay) acceptLoop() {
	for {
		c, err := r.l.Accept()
		if err != nil {
			return
		}
		if a := r.match(peerAddrPort(c.RemoteAddr())); a != nil {
			a.bind(c)
		} else {
			_ = c.Close()
		}
	}
}

// match takes the association for a new client source: the one that
// announced it, the only one pending for its IP address, or the one that
// takes any source.
func (r *udpRelay) match(src netip.AddrPort) *association {
	r.mu.Lock()
	defer r.mu.Unlock()
	if a := r.anyPeer; a != nil {
		r.anyPeer = nil
		return a
	}
	list := r.pending[src.Addr()]
	for _, a := range list {
		if a.announced == src {
			r.removeLocked(a)
			return a
		}
	}
	if len(list) == 1 {
		a := list[0]
		r.removeLocked(a)
		return a
	}
	return nil
}

// add makes a pending, unless the relay is closed or a has already ended:
// its first-datagram timer may fire before it is added.
func (r *udpRelay) add(a *association) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || isDone(a.done) {
		return false
	}
	if a.key.IsValid() {
		r.pending[a.key] = append(r.pending[a.key], a)
	} else {
		r.anyPeer = a
	}
	return true
}

func (r *udpRelay) remove(a *association) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.removeLocked(a)
}

func (r *udpRelay) removeLocked(a *association) {
	if r.anyPeer == a {
		r.anyPeer = nil
	}
	list := r.pending[a.key]
	if i := slices.Index(list, a); i >= 0 {
		list = slices.Delete(list, i, i+1) // clears the vacated slot
	}
	if len(list) == 0 {
		delete(r.pending, a.key)
	} else {
		r.pending[a.key] = list
	}
}

func (r *udpRelay) close() error {
	r.mu.Lock()
	r.closed = true
	r.mu.Unlock()
	return r.l.Close()
}

// peerAddrPort returns a peer's address with an unmapped IP, or the zero
// AddrPort for addresses that are not IP addresses.
func peerAddrPort(addr net.Addr) netip.AddrPort {
	var ap netip.AddrPort
	switch a := addr.(type) {
	case *net.UDPAddr:
		ap = a.AddrPort()
	case *net.TCPAddr:
		ap = a.AddrPort()
	case nil:
	default:
		if parsed, err := netip.ParseAddrPort(addr.String()); err == nil {
			ap = parsed
		}
	}
	return netip.AddrPortFrom(ap.Addr().Unmap().WithZone(""), ap.Port())
}

// association is one UDP ASSOCIATE request.
type association struct {
	s         *Server
	req       *Request
	relay     *udpRelay
	ownsRelay bool
	out       PacketConn
	announced netip.AddrPort // the client's announced source, if specific
	key       netip.Addr     // the client IP address it is pending under, if known

	mu      sync.Mutex
	pending *time.Timer // ends an association that never receives a datagram
	conn    net.Conn    // the client's datagram stream once bound
	done    chan struct{}
	once    sync.Once
}

func (s *Server) associate(ctx context.Context, req *Request) error {
	key, announced := clientSource(req)
	if !key.IsValid() && s.PacketConn != nil {
		_ = s.reply(req, ReplyGeneralFailure, Addr{})
		return errNoClientIP
	}
	relay, owns, err := s.relayFor(ctx, req)
	if err != nil {
		_ = s.reply(req, ReplyFor(err), Addr{})
		return err
	}
	out, err := s.dialPacket(ctx, req)
	if err != nil {
		if owns {
			_ = relay.close()
		}
		_ = s.reply(req, ReplyFor(err), Addr{})
		return err
	}
	a := &association{s: s, req: req, relay: relay, ownsRelay: owns, out: out, key: key, announced: announced, done: make(chan struct{})}
	a.mu.Lock()
	a.pending = time.AfterFunc(positive(s.UDPIdleTimeout, DefaultUDPIdleTimeout), a.close)
	a.mu.Unlock()
	if !relay.add(a) {
		a.close()
		_ = s.reply(req, ReplyGeneralFailure, Addr{})
		return ErrServerClosed
	}
	defer a.close()

	bound := s.udpAddr(req, relay.l.Addr())
	if err := s.reply(req, ReplySucceeded, bound); err != nil {
		return err
	}
	// The association lasts while the control connection is open; it ending
	// first closes the control connection, which also ends the read below
	// on connections without deadline support.
	go func() {
		<-a.done
		_ = req.Conn.Close()
	}()
	_, err = io.Copy(io.Discard, req.Conn)
	if isDone(a.done) {
		err = nil // the association ended and closed the connection
	}
	if s.UDPOutlivesControl {
		select {
		case <-a.done:
		case <-ctx.Done(): // Close
		}
	}
	return err
}

// errNoClientIP refuses a UDP association on the shared socket to a client
// whose IP address is unknown.
var errNoClientIP = errors.New("socks5: UDP ASSOCIATE: client IP address neither known from the control connection nor announced")

// clientSource returns the IP address that may send an association's
// datagrams, invalid when unknown, and the exact source the client announced,
// if specific.
func clientSource(req *Request) (key netip.Addr, announced netip.AddrPort) {
	client := peerAddrPort(req.Conn.RemoteAddr()).Addr()
	ip := req.Dst.IP.Unmap().WithZone("")
	switch {
	case client.IsValid():
		// Only the control connection's IP address may send: honoring an
		// announcement of another address would let a client claim the
		// datagrams of others. A client that does not know its address
		// announces its port with 0.0.0.0, as RFC 1928 says, or a name.
		if req.Dst.Port != 0 && (ip == client || !ip.IsValid() || ip.IsUnspecified()) {
			announced = netip.AddrPortFrom(client, req.Dst.Port)
		}
		return client, announced
	case ip.IsValid() && !ip.IsUnspecified():
		// A control connection without an IP address, such as a tunneled
		// stream, can only rely on the announcement.
		if req.Dst.Port != 0 {
			announced = netip.AddrPortFrom(ip, req.Dst.Port)
		}
		return ip, announced
	}
	// Neither is known: only a socket of the association's own can take the
	// first source that sends.
	return netip.Addr{}, netip.AddrPort{}
}

// relayFor returns the relay serving req: the shared one, or a new one that
// the association owns.
func (s *Server) relayFor(ctx context.Context, req *Request) (*udpRelay, bool, error) {
	if s.PacketConn != nil {
		r, err := s.sharedRelay()
		return r, false, err
	}
	pc, err := s.ListenUDP(ctx, req)
	if err != nil {
		return nil, false, err
	}
	return s.newUDPRelay(pc), true, nil
}

func (s *Server) dialPacket(ctx context.Context, req *Request) (PacketConn, error) {
	if s.DialPacket != nil {
		return s.DialPacket(ctx, req)
	}
	c, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	return NewPacketConn(c), nil
}

func (s *Server) udpAddr(req *Request, socket net.Addr) Addr {
	if s.UDPAddr != nil {
		return s.UDPAddr(req, socket)
	}
	addr := AddrFromNetAddr(socket)
	if !addr.IP.IsValid() || addr.IP.IsUnspecified() {
		if local := AddrFromNetAddr(req.Conn.LocalAddr()); local.IP.IsValid() {
			addr.IP = local.IP
		}
	}
	return addr
}

func isDone(done chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}

// bind attaches the client's datagram stream and starts relaying.
func (a *association) bind(c net.Conn) {
	a.mu.Lock()
	select {
	case <-a.done:
		a.mu.Unlock()
		_ = c.Close()
		return
	default:
	}
	a.conn = c
	a.pending.Stop()
	a.mu.Unlock()
	go a.clientToTarget(c)
	go a.targetToClient(c)
}

func (a *association) clientToTarget(c net.Conn) {
	defer a.close()
	buf := make([]byte, 65535)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return
		}
		dst, payload, err := ParseDatagram(buf[:n])
		if err != nil || a.s.AllowPacket != nil && !a.s.AllowPacket(a.req, dst) {
			continue
		}
		if _, err := a.out.WriteTo(payload, dst); err != nil {
			if netx.IsClosed(err) {
				return
			}
			a.s.onError(a.req.Conn, fmt.Errorf("socks5: udp send to %v: %w", dst, err))
		}
	}
}

func (a *association) targetToClient(c net.Conn) {
	defer a.close()
	// Replies are read in place after room for the longest header, which is
	// then written just before the payload, so they are not copied.
	packet := make([]byte, MaxDatagramHeaderLen+65535)
	payload := packet[MaxDatagramHeaderLen:]
	var hdr [MaxDatagramHeaderLen]byte
	for {
		n, src, err := a.out.ReadFrom(payload)
		if err != nil {
			if !netx.IsClosed(err) && !errors.Is(err, io.EOF) {
				a.s.onError(a.req.Conn, fmt.Errorf("socks5: udp receive: %w", err))
			}
			return
		}
		h, err := AppendDatagram(hdr[:0], src, nil)
		if err != nil {
			continue
		}
		start := MaxDatagramHeaderLen - len(h)
		copy(packet[start:], h)
		if _, err := c.Write(packet[start : MaxDatagramHeaderLen+n]); err != nil {
			if netx.IsClosed(err) || errors.Is(err, os.ErrDeadlineExceeded) {
				return
			}
			// One undeliverable reply, such as one too large once wrapped,
			// does not end the association.
			a.s.onError(a.req.Conn, fmt.Errorf("socks5: udp reply from %v: %w", src, err))
		}
	}
}

func (a *association) close() {
	a.once.Do(func() {
		a.mu.Lock()
		close(a.done)
		a.pending.Stop()
		conn := a.conn
		a.mu.Unlock()
		// After done is closed, so that relay.add refuses a.
		a.relay.remove(a)
		if conn != nil {
			_ = conn.Close()
		}
		_ = a.out.Close()
		if a.ownsRelay {
			_ = a.relay.close()
		}
	})
}
