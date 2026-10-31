package socks5

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"

	"github.com/djylb/netx"
	"github.com/djylb/netx/internal/dgram"
	"github.com/djylb/netx/internal/netutil"

	"github.com/djylb/timeshim"
)

// PacketConn is the outbound side of a UDP association: it sends the client's
// datagrams to their destinations and receives the replies. Implementations
// may forward the datagrams elsewhere, such as through a tunnel; netx.Addr keeps
// domain names unresolved for that purpose.
type PacketConn interface {
	// WriteTo sends p to dst. It must not retain p, which the caller reuses
	// once WriteTo returns.
	WriteTo(p []byte, dst netx.Addr) (int, error)
	// ReadFrom reads the next reply and returns its source.
	ReadFrom(p []byte) (n int, src netx.Addr, err error)
	// Close ends the association's outbound side and unblocks ReadFrom.
	Close() error
}

// ErrLookupBusy drops a datagram to a name that a PacketConn of
// NewPacketConn is looking up, or is to look up, while it holds as many
// datagrams, or runs as many lookups, as it may.
var ErrLookupBusy = errors.New("socks5: too many datagrams wait for name lookups")

// NewPacketConn returns a PacketConn that sends and receives through c,
// resolving domain names with net.DefaultResolver and caching the results for
// a minute, and failed lookups for five seconds. Close ends the lookups in
// progress. Replies from any source are delivered, as with a full-cone NAT.
//
// WriteTo does not wait for a lookup: a datagram to a name that is not
// cached is copied and held until the name resolves, and then sent, in
// order with the later datagrams to the name, or dropped if it does not
// resolve; WriteTo reports the cached failure for the datagrams that follow.
// The lookups of up to 64 names run at once, each holding up to 16
// datagrams, and up to 256 KiB of datagrams are held in all; WriteTo fails
// with ErrLookupBusy for a datagram beyond these bounds, which drops it, as
// a full socket buffer would. Close cancels the lookups, whose goroutines
// then end, each within DefaultDialTimeout also with a resolver that does
// not see the cancellation at once.
func NewPacketConn(c *net.UDPConn) PacketConn {
	u := &udpPacketConn{c: c, resolver: net.DefaultResolver}
	u.names = dgram.NewLookups(DefaultDialTimeout, ErrLookupBusy, u.lookup,
		func(p []byte, _ string, ip netip.Addr, port uint16) {
			_, _ = c.WriteToUDPAddrPort(p, netip.AddrPortFrom(ip, port))
		})
	return u
}

// ipResolver looks up the addresses of a name, as *net.Resolver does.
type ipResolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

type udpPacketConn struct {
	c        *net.UDPConn
	resolver ipResolver
	names    *dgram.Lookups[netip.Addr]
}

func (u *udpPacketConn) WriteTo(p []byte, dst netx.Addr) (int, error) {
	ip := dst.IP
	if !ip.IsValid() && dst.Name == "" {
		ip = netip.IPv4Unspecified()
	} else if !ip.IsValid() {
		var (
			held bool
			err  error
		)
		if ip, held, err = u.names.Route(p, dst.Name, dst.Port); err != nil {
			return 0, err
		} else if held {
			return len(p), nil
		}
	}
	return u.c.WriteToUDPAddrPort(p, netip.AddrPortFrom(ip, dst.Port))
}

// lookup resolves name to one address, IPv4 if it has one.
func (u *udpPacketConn) lookup(ctx context.Context, name string) (netip.Addr, error) {
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

func (u *udpPacketConn) ReadFrom(p []byte) (int, netx.Addr, error) {
	n, ap, err := u.c.ReadFromUDPAddrPort(p)
	if err != nil {
		return n, netx.Addr{}, err
	}
	return n, netx.AddrFromAddrPort(ap), nil
}

func (u *udpPacketConn) Close() error {
	u.names.Close()
	return u.c.Close()
}

// ListenAssociationUDP opens a UDP socket of its own for the association of
// req, on the IP address that the client reached the server at, the local
// address of the control connection, and a port that the system picks. It
// is a ListenUDP for a Server whose clients each get their own socket:
//
//	s := &socks5.Server{ListenUDP: socks5.ListenAssociationUDP}
//
// A control connection without a local IP address, or with an unspecified
// one, gets a socket on all addresses, from netx.ListenEphemeralUDP.
func ListenAssociationUDP(ctx context.Context, req *Request) (net.PacketConn, error) {
	var ap netip.AddrPort
	if a, ok := req.Conn.LocalAddr().(*net.TCPAddr); ok && a != nil {
		ap = a.AddrPort()
	}
	ip := ap.Addr().Unmap()
	if !ip.IsValid() || ip.IsUnspecified() {
		return netx.ListenEphemeralUDP(ctx, nil)
	}
	var lc net.ListenConfig
	return lc.ListenPacket(ctx, "udp", netip.AddrPortFrom(ip, 0).String())
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
		queue = DefaultUDPQueue
	}
	r.l = netx.NewPacketListener(pc,
		netx.WithPacketAcceptFilter(r.expects),
		netx.WithPacketQueue(queue),
		netx.WithPacketIdleTimeout(positive(s.UDPIdleTimeout, DefaultUDPIdleTimeout)),
		netx.WithPacketClock(s.Clock),
	)
	go r.acceptLoop()
	return r
}

// sharedRelay returns the relay of UDPSocket, starting it on first use.
func (s *Server) sharedRelay() (*udpRelay, error) {
	var (
		r   *udpRelay
		err error
	)
	s.life.Locked(func(closed bool) {
		switch {
		case closed:
			err = ErrServerClosed
		case s.shared == nil:
			s.shared = s.newUDPRelay(s.UDPSocket)
		}
		if err == nil && s.shared.stopped() {
			err = errUDPRelayStopped
		}
		r = s.shared
	})
	if err != nil {
		return nil, err
	}
	return r, nil
}

// errUDPRelayStopped refuses a UDP association whose socket has stopped,
// such as a PacketConn closed by its owner.
var errUDPRelayStopped = errors.New("socks5: UDP ASSOCIATE: the UDP socket is closed")

// errUDPIdleBeforeStart ends an association whose idle timeout passed before
// it was set up.
var errUDPIdleBeforeStart = errors.New("socks5: UDP ASSOCIATE: idle timeout before the association started")

// expects reports whether an association waits for datagrams from peer's IP.
func (r *udpRelay) expects(peer net.Addr, _ []byte) bool {
	ap := netutil.PeerAddrPort(peer)
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.anyPeer != nil || len(r.pending[ap.Addr()]) > 0
}

func (r *udpRelay) acceptLoop() {
	for {
		c, err := r.l.Accept()
		if err != nil {
			r.stop()
			return
		}
		if a := r.match(netutil.PeerAddrPort(c.RemoteAddr())); a != nil {
			a.bind(c)
		} else {
			_ = c.Close()
		}
	}
}

// match takes the association for a new client source: the one that
// announced it, else the only one pending for its IP address that announced
// no port, else the only one pending for its IP address, whose client may be
// behind a NAT that changed the announced port, or the one that takes any
// source. An association whose client announced the control connection's own
// address and a port takes that source alone: no NAT rewrote it, so another
// port of the same IP address is someone else.
func (r *udpRelay) match(src netip.AddrPort) *association {
	r.mu.Lock()
	defer r.mu.Unlock()
	if a := r.anyPeer; a != nil {
		r.anyPeer = nil
		return a
	}
	list := r.pending[src.Addr()]
	var unannounced *association
	n := 0
	for _, a := range list {
		if a.announced == src {
			r.removeLocked(a)
			return a
		}
		if !a.announced.IsValid() {
			unannounced, n = a, n+1
		}
	}
	// The ports that the others announced tell them apart from it.
	if n == 1 {
		r.removeLocked(unannounced)
		return unannounced
	}
	if len(list) == 1 && !list[0].exact {
		a := list[0]
		r.removeLocked(a)
		return a
	}
	return nil
}

// stop marks r closed once its socket has stopped, so that no association is
// added to it, and ends the associations waiting for their first datagram,
// which could never get one.
func (r *udpRelay) stop() {
	r.mu.Lock()
	r.closed = true
	var waiting []*association
	for _, list := range r.pending {
		waiting = append(waiting, list...)
	}
	if r.anyPeer != nil {
		waiting = append(waiting, r.anyPeer)
	}
	r.mu.Unlock()
	for _, a := range waiting {
		a.close()
	}
}

func (r *udpRelay) stopped() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closed
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

// association is one UDP ASSOCIATE request.
type association struct {
	s         *Server
	req       *Request
	relay     *udpRelay
	out       PacketConn
	announced netip.AddrPort // the client's announced source, if specific
	key       netip.Addr     // the client IP address it is pending under, if known
	exact     bool           // announced is the control connection's address: only it matches
	ownsRelay bool

	mu      sync.Mutex
	once    sync.Once      // closes done
	pending timeshim.Timer // ends an association that never receives a datagram
	conn    net.Conn       // the client's datagram stream once bound
	done    chan struct{}
}

func (s *Server) associate(ctx context.Context, req *Request) error {
	key, announced, exact := clientSource(req)
	if !key.IsValid() && s.UDPSocket != nil {
		return refuse(req, ReplyGeneralFailure, errNoClientIP)
	}
	relay, owns, err := s.relayFor(ctx, req)
	if err != nil {
		return refuse(req, ReplyFor(err), err)
	}
	dialCtx, cancel := context.WithTimeout(ctx, positive(s.DialTimeout, DefaultDialTimeout))
	out, err := s.dialPacket(dialCtx, req)
	cancel()
	if err != nil {
		if owns {
			_ = relay.close()
		}
		return refuse(req, ReplyFor(err), err)
	}
	a := &association{s: s, req: req, relay: relay, ownsRelay: owns, out: out, key: key, announced: announced, exact: exact, done: make(chan struct{})}
	a.mu.Lock()
	a.pending = timeshim.Or(s.Clock).AfterFunc(positive(s.UDPIdleTimeout, DefaultUDPIdleTimeout), a.close)
	a.mu.Unlock()
	if !relay.add(a) {
		// The reason, before a.close closes a relay of its own.
		err := errUDPIdleBeforeStart
		switch {
		case ctx.Err() != nil:
			err = ErrServerClosed
		case relay.stopped():
			err = errUDPRelayStopped
		}
		a.close()
		return refuse(req, ReplyGeneralFailure, err)
	}
	defer a.close()

	bound := s.udpAddr(req, relay.l.Addr())
	if err := req.Reply(ReplySucceeded, bound); err != nil {
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
// datagrams, invalid when unknown, the exact source the client announced, if
// specific, and whether that source is the only one to accept: the client
// announced the control connection's own IP address.
func clientSource(req *Request) (key netip.Addr, announced netip.AddrPort, exact bool) {
	client := netutil.PeerAddrPort(req.Conn.RemoteAddr()).Addr()
	ip := req.Dst.IP.Unmap().WithZone("")
	switch {
	case client.IsValid():
		// Only the control connection's IP address may send: honoring an
		// announcement of another address would let a client claim the
		// datagrams of others. Its port still names the source, behind a
		// NAT that keeps ports and for clients that announce 0.0.0.0, as
		// RFC 1928 says, or a name when they do not know their address.
		if req.Dst.Port != 0 {
			announced = netip.AddrPortFrom(client, req.Dst.Port)
			exact = ip == client
		}
		return client, announced, exact
	case ip.IsValid() && !ip.IsUnspecified():
		// A control connection without an IP address, such as a tunneled
		// stream, can only rely on the announcement.
		if req.Dst.Port != 0 {
			announced = netip.AddrPortFrom(ip, req.Dst.Port)
		}
		return ip, announced, false
	}
	// Neither is known: only a socket of the association's own can take the
	// first source that sends.
	return netip.Addr{}, netip.AddrPort{}, false
}

// relayFor returns the relay serving req: the shared one, or a new one that
// the association owns.
func (s *Server) relayFor(ctx context.Context, req *Request) (*udpRelay, bool, error) {
	if s.UDPSocket != nil {
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
	c, err := netx.ListenEphemeralUDP(ctx, nil)
	if err != nil {
		return nil, err
	}
	return NewPacketConn(c), nil
}

func (s *Server) udpAddr(req *Request, socket net.Addr) netx.Addr {
	if s.UDPAddr != nil {
		return s.UDPAddr(req, socket)
	}
	addr := netx.AddrFromNetAddr(socket)
	if !addr.IP.IsValid() || addr.IP.IsUnspecified() {
		if local := netx.AddrFromNetAddr(req.Conn.LocalAddr()); local.IP.IsValid() {
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
	d := &datagramRelay{stream: c, out: a.out}
	if a.s.AllowPacket != nil {
		d.allow = func(dst netx.Addr) bool { return a.s.AllowPacket(a.req, dst) }
	}
	if a.s.OnError != nil {
		d.onError = func(err error) { a.s.onError(a.req.Conn, err) }
	}
	go func() {
		defer a.close()
		_ = d.requests()
	}()
	go func() {
		defer a.close()
		if err := d.replies(); err != nil && d.onError != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
			d.onError(err)
		}
	}()
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
