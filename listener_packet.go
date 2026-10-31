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

// PacketListener accepts one connection per remote address of a packet
// connection such as a UDP socket. A datagram from a new peer starts a
// connection that Accept returns; later datagrams from that peer are read from
// it, and writes on it send datagrams to the peer. It is the server side of
// connection-oriented protocols over UDP.
//
// Each Read of a connection returns one datagram, truncated to the buffer like
// a UDP socket. Datagrams that arrive while a connection's queue is full, or
// while too many connections wait for Accept, are dropped. After a connection
// is closed, the next datagram from its peer starts a new one. A connection
// lasts until it is closed, so a server facing untrusted or spoofed peers
// should set WithPacketIdleTimeout or read deadlines, and WithPacketMaxConns.
//
// Create it with NewPacketListener. The zero value has no packet connection:
// its Accept waits until Close, its Addr is nil, and its Dial and WriteTo
// fail.
type PacketListener struct {
	pc   net.PacketConn
	udp  *net.UDPConn // pc, when it is one: alloc-free reads and writes
	opts packetListenerOptions

	conns     dgram.Table[peerKey, *packetConn]
	closeOnce sync.Once
	closeErr  error
	wg        sync.WaitGroup
	epoch     *dgram.Epoch // of the idle timeout
	filtering atomic.Bool  // the read loop is in the accept filter
	closing   atomic.Bool  // Close has begun; with filtering, orders the two
}

type packetListenerOptions struct {
	filter      func(peer net.Addr, first []byte) bool
	queue       int
	backlog     int
	maxConns    int
	idle        time.Duration
	clock       timeshim.Clock
	maxDatagram int
	// beforeFilter, set by tests, runs before the accept filter.
	beforeFilter func(*PacketListener)
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

// WithPacketAcceptFilter drops a datagram of a new peer for which filter
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
// n × 2 KiB of queued datagrams, or a single larger one. Each connection also
// takes a pointer-sized slot per datagram up front, when its first datagram
// arrives.
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
// the default, sets no limit. While it holds n, a datagram from a new peer
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

// WithPacketClock makes the listener tell the time of the idle timeout by c
// instead of the system clock, such as a timeshim.Fake in tests.
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
	l := &PacketListener{pc: pc, opts: cfg, epoch: dgram.NewEpoch(cfg.clock)}
	l.conns.Init(cfg.backlog, cfg.maxConns, (*packetConn).queue, (*packetConn).shutdown)
	l.udp, _ = pc.(*net.UDPConn)
	l.wg.Go(l.readLoop)
	if cfg.idle > 0 {
		l.wg.Go(func() { l.conns.Sweep(cfg.idle, l.epoch) })
	}
	return l
}

// Accept waits for the next peer. It returns net.ErrClosed once the listener
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
		if l.pc != nil {
			l.closeErr = l.pc.Close()
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
	if l.pc == nil {
		return nil
	}
	return l.pc.LocalAddr()
}

// errNoPacketConn is returned by the zero PacketListener's Dial and WriteTo.
var errNoPacketConn = errors.New("netx: PacketListener without a packet connection")

// WriteTo sends p to addr from the packet connection, outside any
// connection of the listener, such as a reply that the accept filter sends
// to a peer it does not accept yet.
func (l *PacketListener) WriteTo(p []byte, addr net.Addr) (int, error) {
	switch {
	case l.pc == nil:
		return 0, errNoPacketConn
	case dgram.IsClosed(l.conns.Done()):
		return 0, net.ErrClosed
	}
	if ua, ok := addr.(*net.UDPAddr); ok && ua != nil && l.udp != nil {
		return l.udp.WriteToUDPAddrPort(p, ua.AddrPort())
	}
	return l.pc.WriteTo(p, addr)
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
// Dial.
func (l *PacketListener) Dial(peer net.Addr) (net.Conn, error) {
	switch {
	case peer == nil || netutil.IsNilPointer(peer):
		return nil, errors.New("netx: nil peer address")
	case l.pc == nil:
		return nil, errNoPacketConn
	}
	var k peerKey
	if ua, ok := peer.(*net.UDPAddr); ok {
		k.ap = netutil.UnmapAddrPort(ua.AddrPort())
	}
	if !k.ap.IsValid() {
		k.s = peer.String()
	} else {
		peer = net.UDPAddrFromAddrPort(k.ap)
	}
	c := l.makeConn(k, peer)
	c.q.Accepted()
	switch _, res := l.conns.Add(k, c, false); res {
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

func (l *PacketListener) readLoop() {
	buf := make([]byte, max(l.opts.maxDatagram, dgram.MaxDatagram))
	done := l.conns.Done()
	var backoff dgram.Backoff
	for {
		var (
			n    int
			ap   netip.AddrPort
			addr net.Addr
			err  error
		)
		if l.udp != nil {
			n, ap, err = l.udp.ReadFromUDPAddrPort(buf)
		} else {
			n, addr, err = l.pc.ReadFrom(buf)
			if ua, ok := addr.(*net.UDPAddr); ok && ua != nil {
				ap = ua.AddrPort()
				addr = nil // reported from ap
			}
		}
		if err != nil {
			if dgram.IsClosed(done) {
				return
			}
			if IsClosed(err) || errors.Is(err, io.EOF) {
				go func() { _ = l.Close() }()
				return
			}
			if errors.Is(err, os.ErrDeadlineExceeded) {
				// The listener owns pc's reads; a deadline left on pc would
				// fail every one of them.
				_ = l.pc.SetReadDeadline(time.Time{})
			}
			// ICMP errors reported on a UDP socket and the like do not end the
			// loop; errors that persist are retried with a growing delay.
			if !backoff.Wait(done) {
				return
			}
			continue
		}
		backoff.Reset()
		l.deliver(buf[:min(n, l.opts.maxDatagram)], netutil.UnmapAddrPort(ap), addr)
	}
}

// deliver queues one datagram for its peer's connection.
func (l *PacketListener) deliver(p []byte, ap netip.AddrPort, addr net.Addr) {
	k := peerKey{ap: ap}
	if !ap.IsValid() {
		if addr == nil {
			return
		}
		k.s = addr.String()
	}
	c, ok := l.conns.Get(k)
	if !ok {
		if c = l.newConn(p, k, addr); c == nil {
			return
		}
	}
	c.q.Enqueue(p)
}

// newConn starts a connection for a new peer unless the accept filter
// rejects it, the backlog or the connection limit is full or the listener is
// closed, or returns the connection that Dial made for the peer meanwhile.
// Only the read loop and Dial start connections.
func (l *PacketListener) newConn(p []byte, k peerKey, addr net.Addr) *packetConn {
	// Drop the datagram before anything is allocated for it while Accept
	// falls behind or the limit is reached. Only the read loop adds to the
	// backlog, so a full one stays full until Add checks it again below.
	if !l.conns.Room() {
		return nil
	}
	if addr == nil {
		addr = net.UDPAddrFromAddrPort(k.ap)
	}
	// The filter runs without the lock, so it may use the listener. Close
	// sets closing before it looks at filtering, and filtering is set here
	// before closing is looked at, both atomically, so either Close sees
	// the filter running and does not wait for it, or the filter does not
	// run: Close cannot wait for a filter that waits for the caller of Close.
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
	// Dial, or the filter, may have connected the peer meanwhile; the
	// datagram is then its.
	c, res := l.conns.Add(k, l.makeConn(k, addr), true)
	if res != dgram.Added && res != dgram.Exists {
		return nil
	}
	return c
}

// makeConn returns a connection to peer under k.
func (l *PacketListener) makeConn(k peerKey, peer net.Addr) *packetConn {
	c := &packetConn{l: l, key: k, peer: peer, writeDeadline: dgram.MakeDeadline()}
	c.q.Init(l.opts.queue, l.epoch)
	return c
}

func (l *PacketListener) writeTo(p []byte, c *packetConn) (int, error) {
	if l.udp != nil && c.key.ap.IsValid() {
		return l.udp.WriteToUDPAddrPort(p, c.key.ap)
	}
	return l.pc.WriteTo(p, c.peer)
}
