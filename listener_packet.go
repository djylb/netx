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
// is closed, the next datagram from its peer starts a new one.
type PacketListener struct {
	pc   net.PacketConn
	udp  *net.UDPConn // pc, when it is one: alloc-free reads and writes
	opts packetListenerOptions

	accept    chan *packetConn
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error

	mu    sync.Mutex
	conns map[netip.AddrPort]*packetConn
	other map[string]*packetConn // peers that are not *net.UDPAddr
	wg    sync.WaitGroup
}

type packetListenerOptions struct {
	filter      func(peer net.Addr) bool
	queue       int
	backlog     int
	idle        time.Duration
	maxDatagram int
}

// PacketListenerOption configures NewPacketListener.
type PacketListenerOption func(*packetListenerOptions)

// WithAcceptFilter drops the datagrams of a new peer for which filter returns
// false instead of starting a connection for it. filter runs on the read loop,
// so it must be fast.
func WithAcceptFilter(filter func(peer net.Addr) bool) PacketListenerOption {
	return func(o *packetListenerOptions) {
		o.filter = filter
	}
}

// WithPacketQueue sets how many datagrams a connection holds until they are
// read, 128 by default.
func WithPacketQueue(n int) PacketListenerOption {
	return func(o *packetListenerOptions) {
		o.queue = n
	}
}

// WithAcceptBacklog sets how many new connections wait for Accept, 128 by
// default.
func WithAcceptBacklog(n int) PacketListenerOption {
	return func(o *packetListenerOptions) {
		o.backlog = n
	}
}

// WithIdleTimeout closes a connection that has neither received nor sent a
// datagram for d since Accept returned it. Its pending and later Reads return
// io.EOF. Connections waiting for Accept are kept with their datagrams.
func WithIdleTimeout(d time.Duration) PacketListenerOption {
	return func(o *packetListenerOptions) {
		o.idle = d
	}
}

// WithMaxDatagram sets the largest datagram that is delivered in full, 65535
// bytes by default; longer ones are truncated. The packet connection is still
// read with a buffer of at least 64 KiB, since Windows drops a datagram that
// does not fit, and reports neither its sender nor its data.
func WithMaxDatagram(n int) PacketListenerOption {
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
	cfg := packetListenerOptions{queue: 128, backlog: 128, maxDatagram: 65535}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	cfg.queue = max(cfg.queue, 1)
	cfg.backlog = max(cfg.backlog, 1)
	cfg.maxDatagram = max(cfg.maxDatagram, 1)
	l := &PacketListener{
		pc:     pc,
		opts:   cfg,
		accept: make(chan *packetConn, cfg.backlog),
		done:   make(chan struct{}),
		conns:  make(map[netip.AddrPort]*packetConn),
		other:  make(map[string]*packetConn),
	}
	l.udp, _ = pc.(*net.UDPConn)
	l.wg.Go(l.readLoop)
	if cfg.idle > 0 {
		l.wg.Go(l.sweepLoop)
	}
	return l
}

// Accept waits for the next peer. It returns net.ErrClosed once the listener
// is closed. The idle timeout of a connection starts when it is accepted.
func (l *PacketListener) Accept() (net.Conn, error) {
	for {
		select {
		case <-l.done:
			return nil, net.ErrClosed
		default:
		}
		select {
		case c := <-l.accept:
			if isClosedChan(c.closed) {
				continue
			}
			c.touch()
			c.accepted.Store(true)
			return c, nil
		case <-l.done:
			return nil, net.ErrClosed
		}
	}
}

// Close closes the packet connection and every connection of the listener.
func (l *PacketListener) Close() error {
	l.closeOnce.Do(func() {
		close(l.done)
		l.closeErr = l.pc.Close()
		l.wg.Wait()
		l.mu.Lock()
		conns := make([]*packetConn, 0, len(l.conns)+len(l.other))
		for _, c := range l.conns {
			conns = append(conns, c)
		}
		for _, c := range l.other {
			conns = append(conns, c)
		}
		l.mu.Unlock()
		for _, c := range conns {
			c.shutdown(net.ErrClosed)
		}
		for {
			select {
			case c := <-l.accept:
				c.shutdown(net.ErrClosed)
			default:
				return
			}
		}
	})
	return l.closeErr
}

// Addr returns the packet connection's local address.
func (l *PacketListener) Addr() net.Addr {
	return l.pc.LocalAddr()
}

func (l *PacketListener) readLoop() {
	buf := make([]byte, max(l.opts.maxDatagram, 65535))
	var failures int
	var delay time.Duration
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
			}
		}
		if err != nil {
			select {
			case <-l.done:
				return
			default:
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
			if failures++; failures > 1 {
				delay = min(max(2*delay, time.Millisecond), time.Second)
				if !l.sleep(delay) {
					return
				}
			}
			continue
		}
		failures, delay = 0, 0
		l.deliver(buf[:min(n, l.opts.maxDatagram)], ap, addr)
	}
}

// sleep waits for d and reports false if the listener closed first.
func (l *PacketListener) sleep(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-l.done:
		return false
	}
}

// deliver queues one datagram for its peer's connection.
func (l *PacketListener) deliver(p []byte, ap netip.AddrPort, addr net.Addr) {
	l.mu.Lock()
	var c *packetConn
	if ap.IsValid() {
		c = l.conns[ap]
	} else if addr != nil {
		c = l.other[addr.String()]
	}
	if c == nil {
		c = l.newConnLocked(ap, addr)
		if c == nil {
			l.mu.Unlock()
			return
		}
	}
	l.mu.Unlock()
	c.enqueue(p)
}

func (l *PacketListener) newConnLocked(ap netip.AddrPort, addr net.Addr) *packetConn {
	if addr == nil {
		if !ap.IsValid() {
			return nil
		}
		addr = net.UDPAddrFromAddrPort(ap)
	}
	if l.opts.filter != nil && !l.opts.filter(addr) {
		return nil
	}
	c := &packetConn{
		l:             l,
		ap:            ap,
		peer:          addr,
		queue:         make(chan *[]byte, l.opts.queue),
		closed:        make(chan struct{}),
		readDeadline:  makeDeadline(),
		writeDeadline: makeDeadline(),
	}
	select {
	case l.accept <- c:
	default:
		return nil // backlog full
	}
	if ap.IsValid() {
		l.conns[ap] = c
	} else {
		l.other[addr.String()] = c
	}
	return c
}

func (l *PacketListener) remove(c *packetConn) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if c.ap.IsValid() {
		if l.conns[c.ap] == c {
			delete(l.conns, c.ap)
		}
	} else if key := c.peer.String(); l.other[key] == c {
		delete(l.other, key)
	}
}

func (l *PacketListener) writeTo(p []byte, c *packetConn) (int, error) {
	if l.udp != nil && c.ap.IsValid() {
		return l.udp.WriteToUDPAddrPort(p, c.ap)
	}
	return l.pc.WriteTo(p, c.peer)
}

func (l *PacketListener) sweepLoop() {
	interval := max(l.opts.idle/4, 10*time.Millisecond)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-l.done:
			return
		case now := <-ticker.C:
			l.mu.Lock()
			var idle []*packetConn
			for _, c := range l.conns {
				if c.idleAt(now, l.opts.idle) {
					idle = append(idle, c)
				}
			}
			for _, c := range l.other {
				if c.idleAt(now, l.opts.idle) {
					idle = append(idle, c)
				}
			}
			l.mu.Unlock()
			for _, c := range idle {
				c.shutdown(io.EOF)
			}
		}
	}
}

// packetBufPool holds buffers for queued datagrams of common sizes.
var packetBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 2048)
		return &b
	},
}

// packetConn is one peer of a PacketListener.
type packetConn struct {
	l    *PacketListener
	ap   netip.AddrPort // valid for *net.UDPAddr peers
	peer net.Addr

	queue  chan *[]byte // datagrams, in packetBufPool buffers when they fit
	closed chan struct{}
	once   sync.Once
	err    error // reported by Read after shutdown

	accepted      atomic.Bool  // returned by Accept; the idle sweep skips it until then
	active        atomic.Int64 // clockOffset of the last datagram or of Accept
	readDeadline  deadline
	writeDeadline deadline
}

func (c *packetConn) touch() {
	c.active.Store(clockOffset(time.Now()))
}

// idleAt reports whether the accepted connection has been idle for at least
// d at now. A connection waiting for Accept is not idle: the backlog is
// bounded, and closing it would lose its datagrams.
func (c *packetConn) idleAt(now time.Time, d time.Duration) bool {
	return c.accepted.Load() && clockOffset(now)-c.active.Load() >= int64(d)
}

func (c *packetConn) enqueue(p []byte) {
	var bp *[]byte
	if len(p) <= 2048 {
		bp = packetBufPool.Get().(*[]byte)
		*bp = (*bp)[:len(p)]
	} else {
		b := make([]byte, len(p))
		bp = &b
	}
	copy(*bp, p)
	select {
	case <-c.closed:
		putPacketBuf(bp)
	case c.queue <- bp:
		c.touch()
	default:
		putPacketBuf(bp) // queue full: drop like a socket buffer would
	}
}

// putPacketBuf returns a datagram buffer to packetBufPool if it came from it.
func putPacketBuf(bp *[]byte) {
	if cap(*bp) == 2048 {
		*bp = (*bp)[:0]
		packetBufPool.Put(bp)
	}
}

// Read returns the next datagram from the peer, truncated to len(b).
func (c *packetConn) Read(b []byte) (int, error) {
	select {
	case p := <-c.queue:
		n := copy(b, *p)
		putPacketBuf(p)
		return n, nil
	default:
	}
	select {
	case p := <-c.queue:
		n := copy(b, *p)
		putPacketBuf(p)
		return n, nil
	case <-c.closed:
		return 0, c.err
	case <-c.readDeadline.wait():
		return 0, os.ErrDeadlineExceeded
	}
}

// Write sends b to the peer as one datagram.
func (c *packetConn) Write(b []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	case <-c.writeDeadline.wait():
		return 0, os.ErrDeadlineExceeded
	default:
	}
	n, err := c.l.writeTo(b, c)
	if err == nil {
		c.touch()
	}
	return n, err
}

// Close removes the connection from its listener.
func (c *packetConn) Close() error {
	c.shutdown(net.ErrClosed)
	return nil
}

func (c *packetConn) shutdown(err error) {
	c.once.Do(func() {
		c.err = err
		c.l.remove(c)
		close(c.closed)
		for {
			select {
			case p := <-c.queue:
				putPacketBuf(p)
			default:
				return
			}
		}
	})
}

func (c *packetConn) LocalAddr() net.Addr  { return c.l.pc.LocalAddr() }
func (c *packetConn) RemoteAddr() net.Addr { return c.peer }

func (c *packetConn) SetDeadline(t time.Time) error {
	c.readDeadline.set(t)
	c.writeDeadline.set(t)
	return nil
}

func (c *packetConn) SetReadDeadline(t time.Time) error {
	c.readDeadline.set(t)
	return nil
}

// SetWriteDeadline makes later writes fail once t has passed. A write that is
// already in progress on the shared socket is not interrupted.
func (c *packetConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline.set(t)
	return nil
}

// deadline is a resettable deadline whose expiry closes a channel, as in
// net.Pipe.
type deadline struct {
	mu     sync.Mutex
	timer  *time.Timer
	cancel chan struct{} // closed when the deadline expires; never nil
}

func makeDeadline() deadline {
	return deadline{cancel: make(chan struct{})}
}

func (d *deadline) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil && !d.timer.Stop() {
		<-d.cancel // the timer fired: wait until it closed the channel
	}
	d.timer = nil
	closed := isClosedChan(d.cancel)
	if t.IsZero() {
		if closed {
			d.cancel = make(chan struct{})
		}
		return
	}
	if dur := time.Until(t); dur > 0 {
		if closed {
			d.cancel = make(chan struct{})
		}
		cancel := d.cancel
		d.timer = time.AfterFunc(dur, func() { close(cancel) })
		return
	}
	if !closed {
		close(d.cancel)
	}
}

func (d *deadline) wait() chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cancel
}

func isClosedChan(c chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}
