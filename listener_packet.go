package netx

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/timeshim"

	"github.com/djylb/netx/internal/dgram"
	"github.com/djylb/netx/internal/netutil"
)

// PacketListener accepts datagram flows from a packet connection such as a
// UDP socket. A datagram for a new flow starts a connection that Accept
// returns. Later datagrams for that flow are read from it, and writes on it
// send datagrams to the peer. It is the server side of connection-oriented
// protocols over UDP.
//
// Each Read of a connection returns one datagram, truncated to the buffer like
// a UDP socket. Datagrams that arrive while a connection's queue is full, or
// while too many connections wait for Accept, are dropped. After a connection
// is closed, the next datagram for its flow starts a new one. A connection
// lasts until it is closed, so a server facing untrusted or spoofed peers
// should set WithPacketIdleTimeout or read deadlines, and WithPacketMaxConns.
//
// A flow is keyed by remote address. When every socket is a wildcard
// *net.UDPConn with packet information enabled (Linux, Android, macOS, iOS
// and Windows), the key includes the local unicast destination and, for
// link-local destinations, its interface index. An accepted unicast flow
// reports that destination in LocalAddr and uses it as its reply source.
// If the source is temporarily unavailable, that datagram is retried with
// an OS-selected source. A flow whose source is confirmed as a broadcast
// or multicast address after a write error switches to OS-selected sources
// and reports the socket's address. All broadcast and multicast traffic from
// a remote address shares one flow, separate from its unicast flows, with
// an OS-selected reply source. Datagrams missing packet information are
// dropped in this mode. If any socket cannot enable packet information,
// every socket uses remote-only flow keys and OS-selected reply sources.
// WriteTo always uses the OS-selected source.
//
// Create it with NewPacketListener. The zero value has no packet connection:
// its Accept waits until Close, its Addr is nil, and its Dial and WriteTo
// fail.
type PacketListener struct {
	closeErr   error
	reject     *rejectCache // nil without WithPacketRejectCache
	epoch      *dgram.Epoch // of the idle timeout
	more       []packetSocket
	sock       packetSocket // pc's
	conns      dgram.Table[packetFlow, *packetConn]
	pktinfo    bool // all sockets use destination-aware flow keys
	broadcasts packetBroadcasts
	flowMu     sync.Mutex      // serializes flow registration, binding and removal with packet info
	peerCounts map[peerKey]int // registered connections per remote, under flowMu
	opts       packetListenerOptions
	wg         sync.WaitGroup
	closeOnce  sync.Once
	filtering  atomic.Bool // the read loop is in the accept filter
	closing    atomic.Bool // Close has begun; with filtering, orders the two
}

type packetListenerOptions struct {
	clock  timeshim.Clock
	filter func(peer net.Addr, first []byte) bool
	// beforeFilter, set by tests, runs before the accept filter.
	beforeFilter func(*PacketListener)
	more         []net.PacketConn
	queue        int
	backlog      int
	maxConns     int
	idle         time.Duration
	maxDatagram  int
	batch        int
	rejectSize   int
	rejectTTL    time.Duration
}

// Defaults of NewPacketListener.
const (
	// DefaultPacketQueue is how many datagrams a connection holds until
	// they are read; see WithPacketQueue.
	DefaultPacketQueue = 128
	// DefaultPacketAcceptBacklog is how many new connections wait for
	// Accept; see WithPacketAcceptBacklog.
	DefaultPacketAcceptBacklog = 128
	// DefaultPacketMaxDatagram is the largest datagram delivered in full;
	// see WithPacketMaxDatagram.
	DefaultPacketMaxDatagram = 65535
)

// PacketListenerOption configures NewPacketListener.
type PacketListenerOption func(*packetListenerOptions)

// WithPacketAcceptFilter drops a datagram of a new flow for which filter
// returns false instead of starting a connection for it. filter gets the
// peer and the datagram, which is valid only during the call, so that it can
// check a token or cookie in it before anything is allocated for the peer,
// and reply with WriteTo without state, as a retry does; peers that only
// spoof their source then take no place in the accept backlog or under
// WithPacketMaxConns. It runs on the read loop, so it must be fast. It may
// close the listener or its connections.
func WithPacketAcceptFilter(filter func(peer net.Addr, first []byte) bool) PacketListenerOption {
	return func(o *packetListenerOptions) {
		o.filter = filter
	}
}

// WithPacketQueue sets how many datagrams a connection holds until they are
// read, DefaultPacketQueue by default. A datagram larger than 2 KiB takes the
// room of several in proportion to its size, so a connection holds at most
// n × 2 KiB of queued datagrams, or a single larger one. A connection's
// queue grows with the datagrams waiting in it, a pointer-sized slot each,
// up to n, and gives the room of a burst back once it is read, so the bound
// costs nothing until datagrams pile up.
func WithPacketQueue(n int) PacketListenerOption {
	return func(o *packetListenerOptions) {
		o.queue = n
	}
}

// WithPacketAcceptBacklog sets how many new connections wait for Accept,
// DefaultPacketAcceptBacklog by default.
func WithPacketAcceptBacklog(n int) PacketListenerOption {
	return func(o *packetListenerOptions) {
		o.backlog = n
	}
}

// WithPacketMaxConns sets how many connections the listener holds at once,
// accepted or waiting for Accept, those of Dial included; a non-positive n,
// the default, sets no limit. While it holds n, a datagram for a new flow
// is dropped, before the accept filter runs or anything is allocated for
// the peer, and Dial returns ErrPacketConnLimit. Each connection holds its
// queued datagrams, so the limit bounds the listener's memory with
// WithPacketQueue. Peers that spoof their source can take every place, and
// keep it while they send, until an idle timeout or the application closes
// their connections: pair the limit with WithPacketIdleTimeout, and with an
// accept filter that checks a token, which spoofed sources cannot echo, to
// keep the places for real peers.
func WithPacketMaxConns(n int) PacketListenerOption {
	return func(o *packetListenerOptions) {
		o.maxConns = n
	}
}

// WithPacketIdleTimeout closes a connection that has neither received nor
// sent a datagram for d since Accept returned it. Its pending and later Reads
// return io.EOF. Connections waiting for Accept are kept with their
// datagrams. A non-positive d, the default, keeps idle connections.
func WithPacketIdleTimeout(d time.Duration) PacketListenerOption {
	return func(o *packetListenerOptions) {
		o.idle = d
	}
}

// WithPacketClock sets the clock for idle timeouts, peer rejection expiry
// and broadcast address refresh. The system clock is used by default.
func WithPacketClock(c timeshim.Clock) PacketListenerOption {
	return func(o *packetListenerOptions) {
		o.clock = c
	}
}

// WithPacketMaxDatagram sets the largest datagram that is delivered in full,
// DefaultPacketMaxDatagram bytes by default; longer ones are truncated. The
// packet connection is still read with a buffer of at least 65535 bytes,
// since Windows drops a datagram that does not fit, and reports neither its
// sender nor its data.
func WithPacketMaxDatagram(n int) PacketListenerOption {
	return func(o *packetListenerOptions) {
		o.maxDatagram = n
	}
}

// WithPacketConns adds more packet connections to the listener, which reads
// each with a read loop of its own into the same connections, so that peers
// are read on several cores: sockets bound to the same address with
// SO_REUSEPORT, as ListenUDPReusePort makes them, among which the kernel
// spreads peers by their address, so that the datagrams of one peer keep
// their order. An accepted connection writes from the packet connection that
// its flow first came through, and Dial and WriteTo from pc. The listener owns them
// as it owns pc.
func WithPacketConns(more ...net.PacketConn) PacketListenerOption {
	return func(o *packetListenerOptions) {
		o.more = append(o.more, more...)
	}
}

// WithPacketReadBatch reads up to n datagrams with one system call, where the
// platform has one for it (recvmmsg on Linux and Android) and the packet
// connection is a *net.UDPConn; elsewhere a datagram is read at a time. Each
// read loop then holds n buffers of the WithPacketMaxDatagram size, so lower
// that to what the protocol sends. A non-positive or single n, the default,
// reads a datagram at a time.
func WithPacketReadBatch(n int) PacketListenerOption {
	return func(o *packetListenerOptions) {
		o.batch = n
	}
}

// WithPacketRejectCache remembers up to size peers given to RejectPeer, for
// ttl each, and drops the datagrams of a new connection from them before
// the accept filter runs, so that a peer that keeps sending costs a lookup.
// The cache grows with the peers it holds; at size, the older half of them
// is forgotten. A non-positive size or ttl, the default, keeps none, and
// RejectPeer then does nothing.
//
// The filter's own rejections are not remembered: a datagram's source can be
// spoofed, and remembering it would let anyone lock a real peer out. Call
// RejectPeer only for a source that the datagram proves, as one that echoes
// a token the listener sent it does.
func WithPacketRejectCache(size int, ttl time.Duration) PacketListenerOption {
	return func(o *packetListenerOptions) {
		o.rejectSize, o.rejectTTL = size, ttl
	}
}

// SetIdleTimeout changes the WithPacketIdleTimeout of a running listener,
// for the connections it holds too: each is checked against d within a
// quarter of d, so one idle for d by then is closed; a non-positive d keeps
// idle connections from now on.
func (l *PacketListener) SetIdleTimeout(d time.Duration) { l.conns.SetIdle(d) }

// NewPacketListener starts reading pc and returns a listener for its peers.
// The listener owns pc and closes it on Close. A read error meaning that pc
// is closed or exhausted (net.ErrClosed, io.EOF) closes the listener; other
// read errors are retried, with a growing delay while they persist, and an
// expired read deadline on pc is cleared.
func NewPacketListener(pc net.PacketConn, opts ...PacketListenerOption) *PacketListener {
	cfg := packetListenerOptions{queue: DefaultPacketQueue, backlog: DefaultPacketAcceptBacklog, maxDatagram: DefaultPacketMaxDatagram}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	cfg.queue = max(cfg.queue, 1)
	cfg.backlog = max(cfg.backlog, 1)
	cfg.maxDatagram = max(cfg.maxDatagram, 1)
	l := &PacketListener{opts: cfg, epoch: dgram.NewEpoch(cfg.clock)}
	l.conns.Init(dgram.TableOptions[*packetConn]{Queue: (*packetConn).queue, Shutdown: (*packetConn).shutdown,
		Epoch: l.epoch, Backlog: cfg.backlog, Limit: cfg.maxConns, Idle: cfg.idle})
	l.sock = newPacketSocket(pc)
	l.pktinfo = pc == nil || l.sock.pktinfo
	if cfg.rejectSize > 0 && cfg.rejectTTL > 0 {
		l.reject = newRejectCache(cfg.rejectSize, cfg.rejectTTL, l.epoch)
	}
	for _, more := range cfg.more {
		if more != nil {
			sock := newPacketSocket(more)
			l.pktinfo = l.pktinfo && sock.pktinfo
			l.more = append(l.more, sock)
		}
	}
	l.pktinfo = l.pktinfo && (pc != nil || len(l.more) != 0)
	if l.pktinfo {
		l.peerCounts = make(map[peerKey]int)
		clock := l.epoch.Clock()
		l.broadcasts.init(clock)
		l.wg.Go(func() { l.broadcasts.run(clock, l.conns.Done()) })
	} else {
		l.sock.pktinfo = false
		for i := range l.more {
			l.more[i].pktinfo = false
		}
	}
	l.opts.more = nil
	if pc != nil {
		l.wg.Go(func() { l.readLoop(&l.sock) })
	}
	for i := range l.more {
		l.wg.Go(func() { l.readLoop(&l.more[i]) })
	}
	return l
}

// Accept waits for the next flow. It returns net.ErrClosed once the listener
// is closed. The idle timeout of a connection starts when it is accepted.
func (l *PacketListener) Accept() (net.Conn, error) {
	c, err := l.conns.Accept()
	if err != nil {
		return nil, err
	}
	return c, nil
}

// Close closes the packet connection and every connection of the listener,
// and waits for the listener's goroutines to stop unless the accept filter,
// which may call Close, is running.
func (l *PacketListener) Close() error {
	l.closeOnce.Do(func() {
		// Nothing here waits for the read loop, which may itself be calling
		// Close from the accept filter. The table refuses peers once it is
		// closed, so the connections it shuts down are all there will be.
		l.closing.Store(true)
		l.conns.Close(net.ErrClosed)
		if l.sock.pc != nil {
			l.closeErr = l.sock.pc.Close()
		}
		for _, sock := range l.more {
			if err := sock.pc.Close(); l.closeErr == nil {
				l.closeErr = err
			}
		}
	})
	// Wait for the read loop to stop, unless the accept filter called Close
	// on it: it cannot wait for itself.
	if !l.filtering.Load() {
		l.wg.Wait()
	}
	return l.closeErr
}

// Addr returns the packet connection's local address.
func (l *PacketListener) Addr() net.Addr {
	if l.sock.pc == nil {
		return nil
	}
	return l.sock.pc.LocalAddr()
}

// errNoPacketConn is returned by the zero PacketListener's Dial and WriteTo.
var errNoPacketConn = errors.New("netx: PacketListener without a packet connection")

// WriteTo sends p to addr from the packet connection, outside any
// connection of the listener, such as a reply that the accept filter sends
// to a peer it does not accept yet.
func (l *PacketListener) WriteTo(p []byte, addr net.Addr) (int, error) {
	switch {
	case l.sock.pc == nil:
		return 0, errNoPacketConn
	case dgram.IsClosed(l.conns.Done()):
		return 0, net.ErrClosed
	}
	if ua, ok := addr.(*net.UDPAddr); ok && ua != nil && l.sock.udp != nil {
		return l.sock.udp.WriteToUDPAddrPort(p, ua.AddrPort())
	}
	return l.sock.pc.WriteTo(p, addr)
}

// RejectPeer drops the datagrams of new flows from peer, before the
// accept filter runs, for the time to live of WithPacketRejectCache; without
// that option it does nothing. It leaves the peer's existing connections alone.
// Call it only for a peer whose source address is proven, never for one
// that a datagram merely claims, as a spoofed source would lock the real
// peer out; the accept filter may call it for a peer it rejects.
func (l *PacketListener) RejectPeer(peer net.Addr) {
	if l.reject == nil || peer == nil || netutil.IsNilPointer(peer) {
		return
	}
	l.reject.add(peerKeyOf(peer))
}

// peerKeyOf returns the key of peer, a *net.UDPAddr by its unmapped address
// and port and others by String.
func peerKeyOf(peer net.Addr) peerKey {
	var k peerKey
	if ua, ok := peer.(*net.UDPAddr); ok {
		k.ap = netutil.UnmapAddrPort(ua.AddrPort())
	}
	if !k.ap.IsValid() {
		k.s = peer.String()
	}
	return k
}

// ErrPacketPeerConnected is returned by PacketListener.Dial for a peer that
// has a connection already.
var ErrPacketPeerConnected = errors.New("netx: packet listener peer already connected")

// ErrPacketConnLimit is returned by PacketListener.Dial while the listener
// holds the connections that WithPacketMaxConns allows.
var ErrPacketConnLimit = errors.New("netx: packet listener connection limit reached")

// Dial returns a connection to peer over the listener's packet connection, as
// if peer had sent a datagram, but without Accept: datagrams from peer are
// read from it, and its writes are sent to peer. It reaches a known peer from
// the socket that also accepts others, as hole punching does. It returns
// ErrPacketPeerConnected if peer has a connection, accepted or not,
// ErrPacketConnLimit at the limit of WithPacketMaxConns, and net.ErrClosed
// once the listener is closed. The idle timeout of the connection starts at
// Dial. With packet information enabled, writes use the OS-selected source
// until the first datagram from peer with a unicast destination at the
// listener's port fixes the local destination and any link-local scope.
// This binding uses the packet's claimed source address. A sender that can
// spoof peer's source may bind the connection first. Later datagrams for
// other local destinations or scopes start separate flows, as for Accept.
func (l *PacketListener) Dial(peer net.Addr) (net.Conn, error) {
	switch {
	case peer == nil || netutil.IsNilPointer(peer):
		return nil, errors.New("netx: nil peer address")
	case l.sock.pc == nil:
		return nil, errNoPacketConn
	}
	k := packetFlow{peer: peerKeyOf(peer), wildcardDial: l.sock.pktinfo}
	if k.peer.ap.IsValid() {
		peer = net.UDPAddrFromAddrPort(k.peer.ap)
	}
	if l.pktinfo {
		l.flowMu.Lock()
		defer l.flowMu.Unlock()
		if dgram.IsClosed(l.conns.Done()) {
			return nil, net.ErrClosed
		}
		if l.peerCounts[k.peer] != 0 {
			return nil, ErrPacketPeerConnected
		}
	}
	c := l.makeConn(k, peer, &l.sock, 0)
	c.q.Accepted()
	switch _, res := l.addConn(c, false); res {
	case dgram.Added:
	case dgram.Exists:
		return nil, ErrPacketPeerConnected
	case dgram.Full:
		return nil, ErrPacketConnLimit
	case dgram.Closed:
		return nil, net.ErrClosed
	}
	return c, nil
}

// packetSocket is a packet connection that a PacketListener reads.
type packetSocket struct {
	pc  net.PacketConn
	udp *net.UDPConn // pc, when it is one: alloc-free reads and writes
	// pktinfo: udp is bound to a wildcard address and reports the
	// destination of each datagram (listener_packet_pktinfo.go).
	pktinfo bool
	port    uint16 // local port on a socket with packet information
}

func newPacketSocket(pc net.PacketConn) packetSocket {
	sock := packetSocket{pc: pc}
	sock.udp, _ = pc.(*net.UDPConn)
	sock.pktinfo = enablePacketInfo(sock.udp)
	if sock.pktinfo {
		sock.port = uint16(sock.udp.LocalAddr().(*net.UDPAddr).Port)
	}
	return sock
}

func (l *PacketListener) readLoop(sock *packetSocket) {
	done := l.conns.Done()
	var backoff dgram.Backoff
	// handle handles a read error and reports whether the loop goes on.
	handle := func(err error) bool {
		if dgram.IsClosed(done) {
			return false
		}
		if IsClosed(err) || errors.Is(err, io.EOF) {
			go func() { _ = l.Close() }()
			return false
		}
		if errors.Is(err, os.ErrDeadlineExceeded) {
			// The listener owns pc's reads; a deadline left on pc would
			// fail every one of them.
			_ = sock.pc.SetReadDeadline(time.Time{})
		}
		// ICMP errors reported on a UDP socket and the like do not end the
		// loop; errors that persist are retried with a growing delay.
		return backoff.Wait(done)
	}
	oobSize := 0
	if sock.pktinfo {
		oobSize = pktinfoOOB
	}
	if b := newBatchReader(sock.udp, l.opts.batch, l.opts.maxDatagram, oobSize); b != nil {
		for {
			n, err := b.read()
			if err != nil {
				if !handle(err) {
					return
				}
				continue
			}
			backoff.Reset()
			for i := range n {
				p, ap, oob := b.datagram(i)
				l.deliver(p, netutil.UnmapAddrPort(ap), nil, sock, oob)
			}
		}
	}
	buf := make([]byte, max(l.opts.maxDatagram, dgram.MaxDatagram))
	oob := make([]byte, oobSize)
	for {
		var (
			n, oobn int
			ap      netip.AddrPort
			addr    net.Addr
			err     error
		)
		switch {
		case sock.pktinfo:
			n, oobn, _, ap, err = sock.udp.ReadMsgUDPAddrPort(buf, oob)
		case sock.udp != nil:
			n, ap, err = sock.udp.ReadFromUDPAddrPort(buf)
		default:
			n, addr, err = sock.pc.ReadFrom(buf)
			if ua, ok := addr.(*net.UDPAddr); ok && ua != nil {
				ap = ua.AddrPort()
				addr = nil // reported from ap
			}
		}
		if err != nil {
			if !handle(err) {
				return
			}
			continue
		}
		backoff.Reset()
		l.deliver(buf[:min(n, l.opts.maxDatagram)], netutil.UnmapAddrPort(ap), addr, sock, oob[:oobn])
	}
}

// deliver queues one datagram on its flow. Decode the destination before
// looking up or publishing a connection.
func (l *PacketListener) deliver(p []byte, ap netip.AddrPort, addr net.Addr, sock *packetSocket, oob []byte) {
	k := packetFlow{peer: peerKey{ap: ap}}
	if !ap.IsValid() {
		if addr == nil {
			return
		}
		k.peer.s = addr.String()
	}
	var ifindex uint32
	if sock.pktinfo {
		var dst netip.Addr
		dst, ifindex = packetDst(oob)
		if !dst.IsValid() || dst.IsUnspecified() {
			return
		}
		k.local.ap = netip.AddrPortFrom(dst, sock.port)
		if dst.IsLinkLocalUnicast() {
			k.local.ifindex = ifindex
		}
	}
	c, ok := l.conns.Get(k)
	if !ok {
		if dst := k.local.ap.Addr(); dst.IsValid() && l.broadcasts.isGroup(dst, l.epoch.Clock()) {
			k.local = packetDestination{}
			c, ok = l.conns.Get(k)
		}
	}
	if !ok {
		if c = l.newConn(p, k, addr, sock, ifindex); c == nil {
			return
		}
	}
	c.q.Enqueue(p)
}

// pendingDial uses the wildcard Dial's primary key as a lock-free index by
// remote address. Only a unicast flow can claim it. Bound Dials keep the
// primary key for lifetime management.
func (l *PacketListener) pendingDial(k packetFlow, sock *packetSocket) *packetConn {
	if !k.local.ap.IsValid() || !l.sock.pktinfo || sock.port != l.sock.port {
		return nil
	}
	c, ok := l.conns.Get(packetFlow{peer: k.peer, wildcardDial: true})
	if !ok || c.from.Load() != nil {
		return nil
	}
	return c
}

// claimDial finds k or delivers it to a pending Dial on the same port. A
// unicast datagram binds the Dial and publishes its formal key. The caller
// holds flowMu, serializing this with additions and removals of connections.
func (l *PacketListener) claimDial(k packetFlow, sock *packetSocket, ifindex uint32) *packetConn {
	c := l.pendingDial(k, sock)
	if c == nil || dgram.IsClosed(l.conns.Done()) {
		return nil
	}
	if c, ok := l.conns.Get(k); ok {
		return c
	}
	// Prepare the reply source before the alias is visible to readers.
	c.setReplySource(k.local, ifindex)
	if !l.conns.AddAlias(k, c) {
		c.from.Store(nil)
		return nil
	}
	return c
}

// newConn starts a connection for a new flow unless the accept filter
// rejects it, the backlog or the connection limit is full or the listener is
// closed, or returns the connection that Dial made for the peer meanwhile.
// Only the read loop and Dial start connections.
func (l *PacketListener) newConn(p []byte, k packetFlow, addr net.Addr, sock *packetSocket, ifindex uint32) *packetConn {
	room := l.conns.Room()
	// A pending Dial already holds a connection slot. Its reply can bind
	// even when accepting a new flow would exceed the limit or backlog.
	if l.pendingDial(k, sock) != nil {
		l.flowMu.Lock()
		c := l.claimDial(k, sock, ifindex)
		l.flowMu.Unlock()
		if c != nil {
			return c
		}
	}
	if !room {
		// A concurrent binding may have published this flow since the
		// first lookup.
		c, _ := l.conns.Get(k)
		return c
	}
	if addr == nil {
		addr = net.UDPAddrFromAddrPort(k.peer.ap)
	}
	// The filter runs without the lock, so it may use the listener. Close
	// sets closing before it looks at filtering, and filtering is set here
	// before closing is looked at, both atomically, so either Close sees
	// the filter running and does not wait for it, or the filter does not
	// run: Close cannot wait for a filter that waits for the caller of Close.
	if l.reject.has(k.peer) {
		return nil
	}
	if l.opts.filter != nil {
		if l.opts.beforeFilter != nil {
			l.opts.beforeFilter(l)
		}
		l.filtering.Store(true)
		ok := !l.closing.Load() && l.opts.filter(addr, p)
		l.filtering.Store(false)
		if !ok {
			return nil
		}
	}
	// Dial, or the filter, may have connected the peer meanwhile.
	if l.pktinfo {
		l.flowMu.Lock()
		defer l.flowMu.Unlock()
		if c := l.claimDial(k, sock, ifindex); c != nil {
			return c
		}
	}
	c, res := l.addConn(l.makeConn(k, addr, sock, ifindex), true)
	if res != dgram.Added && res != dgram.Exists {
		return nil
	}
	return c
}

// makeConn returns a connection to peer under k, which writes from sock.
func (l *PacketListener) makeConn(k packetFlow, peer net.Addr, sock *packetSocket, ifindex uint32) *packetConn {
	c := &packetConn{l: l, key: k, peer: peer, sock: sock, writeDeadline: dgram.MakeDeadline()}
	if k.local.ap.IsValid() {
		c.setReplySource(k.local, ifindex)
	}
	c.q.Init(l.opts.queue, l.epoch)
	return c
}

// addConn registers one connection and updates the peer index. With packet
// information enabled the caller holds flowMu until indexing is complete.
func (l *PacketListener) addConn(c *packetConn, backlog bool) (*packetConn, dgram.Result) {
	stored, result := l.conns.Add(c.key, c, backlog)
	if result == dgram.Added && l.pktinfo {
		c.counted = true
		l.peerCounts[c.key.peer]++
	}
	return stored, result
}

func (l *PacketListener) removeConn(c *packetConn) {
	if l.pktinfo {
		// Close can race with publication in Table.Add. Read counted under
		// the same lock that commits the peer index, and keep removal and
		// its count change atomic with respect to a subsequent Dial.
		l.flowMu.Lock()
		defer l.flowMu.Unlock()
		if c.counted {
			if c.key.wildcardDial {
				if f := c.from.Load(); f != nil {
					l.conns.RemoveAlias(packetFlow{peer: c.key.peer, local: f.destination}, c)
				}
			}
			if l.peerCounts[c.key.peer] == 1 {
				delete(l.peerCounts, c.key.peer)
			} else {
				l.peerCounts[c.key.peer]--
			}
		}
	}
	l.conns.Remove(c.key, c)
}
