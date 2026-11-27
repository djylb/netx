package memnet

import (
	"context"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/netx/internal/bufpool"
	"github.com/djylb/netx/internal/netutil"
	"github.com/djylb/timeshim"
)

// Net is an in-process network for tests. Stream connections are pairs of
// bounded byte queues, one per direction, buffered like a socket so that
// both ends may write at once (such as two TLS ends sending close_notify),
// with CloseWrite ending only the sending direction as on TCP; packet
// connections deliver whole datagrams through bounded queues and drop them
// when full, as UDP does. Addresses are host:port strings, and port 0 picks
// a free port. Resolve answers from SetHost, else parses the host as an
// address.
//
// SetLink injects faults per address and direction. Clock and Rand, when
// set before the Net is used, drive the delays and losses; deadlines are
// wall-clock times, as on sockets. All methods are safe for concurrent use.
type Net struct {
	// Clock runs link delays and rates; nil is the system clock.
	Clock timeshim.Clock
	// Rand draws datagram losses; nil draws from math/rand/v2's global
	// source. It is used under a lock of the Net.
	Rand   *rand.Rand
	faults faults

	mu        sync.Mutex
	listeners map[string]*listener
	dialPorts map[string]bool // reserved by live DialFrom clients
	packets   map[string]*packetConn
	hosts     map[string][]netip.Addr
	next      int
}

// New returns an empty network.
func New() *Net {
	return new(Net)
}

// SetHost makes Resolve answer name with addrs; no addrs removes name.
func (n *Net) SetHost(name string, addrs ...netip.Addr) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(addrs) == 0 {
		delete(n.hosts, name)
		return
	}
	if n.hosts == nil {
		n.hosts = make(map[string][]netip.Addr)
	}
	n.hosts[name] = slices.Clone(addrs)
}

const network = "tcp"

// errReset is a connection reset by the peer, as the OS reports it.
var errReset error = &net.OpError{Op: "read", Net: network, Err: os.NewSyscallError("read", errCodeReset)}

// errRefused is a connect to nothing listening, as the OS reports it.
var errRefused error = &net.OpError{Op: "dial", Net: network, Err: os.NewSyscallError("connect", errCodeRefused)}

func (n *Net) bindLocked(addr string, used func(string) bool) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	if port == "0" {
		for range 65535 {
			n.advancePort()
			a := net.JoinHostPort(host, strconv.Itoa(n.next))
			if !used(a) {
				return a, nil
			}
		}
		return "", errors.New("memnet: no free port")
	}
	if used(addr) {
		return "", errors.New("memnet: address in use")
	}
	return addr, nil
}

func (n *Net) advancePort() {
	if n.next == 0 {
		n.next = 40000
	}
	n.next = n.next%65535 + 1
}

func (n *Net) streamAddressUsed(addr string) bool {
	return n.listeners[addr] != nil || n.dialPorts[addr]
}

// Listen opens a stream listener at addr; the network is ignored.
func (n *Net) Listen(_ context.Context, _, addr string) (net.Listener, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	a, err := n.bindLocked(addr, n.streamAddressUsed)
	if err != nil {
		return nil, err
	}
	l := &listener{n: n, addr: memAddr{network, a}, ch: make(chan net.Conn), done: make(chan struct{})}
	if n.listeners == nil {
		n.listeners = make(map[string]*listener)
	}
	n.listeners[a] = l
	return l, nil
}

// Listening reports a stream listener at addr.
func (n *Net) Listening(addr string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.listeners[addr] != nil
}

// Dial connects to the stream listener at addr; both ends have no address
// ("pipe"). A dial to no listener, or over a link that is Off, is refused
// with ECONNREFUSED, as the system reports it.
func (n *Net) Dial(ctx context.Context, _, addr string) (net.Conn, error) {
	return n.dial(ctx, netip.Addr{}, addr)
}

// DialFrom is Dial from host src: the dialer's LocalAddr and the accepted
// end's RemoteAddr are src with an ephemeral port, so a listener sees
// distinct client sources (per-source limits). From(src) dials this way.
func (n *Net) DialFrom(ctx context.Context, src netip.Addr, addr string) (net.Conn, error) {
	return n.dial(ctx, src, addr)
}

// From returns n as seen from host src: its Dial is DialFrom(src), and
// everything else is n's.
func (n *Net) From(src netip.Addr) *Host { return &Host{n, src} }

// Host is a Net as one host sees it; From returns it.
type Host struct {
	*Net
	src netip.Addr
}

// Dial connects from the host to a listener, as DialFrom does.
func (h *Host) Dial(ctx context.Context, _, addr string) (net.Conn, error) {
	return h.dial(ctx, h.src, addr)
}

func (n *Net) dial(ctx context.Context, src netip.Addr, addr string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if n.LinkOf(addr).To.Off {
		return nil, errRefused
	}
	n.mu.Lock()
	l := n.listeners[addr]
	if l == nil {
		n.mu.Unlock()
		return nil, errRefused
	}
	var local, remote net.Addr
	var port string
	if src.IsValid() {
		var err error
		port, err = n.bindLocked(net.JoinHostPort(src.String(), "0"), n.streamAddressUsed)
		if err != nil {
			n.mu.Unlock()
			return nil, err
		}
		if n.dialPorts == nil {
			n.dialPorts = make(map[string]bool)
		}
		n.dialPorts[port] = true
		local, remote = memAddr{network, port}, l.addr
	}
	n.mu.Unlock()
	c0, s0 := halfPipe()
	c := n.track(c0, addr, true, local, remote, port)
	s := n.track(s0, addr, false, remote, local, "")
	var err error
	select {
	case l.ch <- s:
		return c, nil
	case <-l.done:
		err = errRefused
	case <-ctx.Done():
		err = ctx.Err()
	}
	_ = c.Close()
	_ = s.Close()
	return nil, err
}

// ListenPacket opens a packet endpoint at addr; the network is ignored.
// Datagrams to an address where nothing listens are dropped.
func (n *Net) ListenPacket(_ context.Context, _, addr string) (net.PacketConn, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	a, err := n.bindLocked(addr, func(s string) bool { _, ok := n.packets[s]; return ok })
	if err != nil {
		return nil, err
	}
	p := &packetConn{n: n, addr: memAddr{"udp", a}, in: make(chan datagram, 256), done: make(chan struct{})}
	if n.packets == nil {
		n.packets = make(map[string]*packetConn)
	}
	p.rdl.init()
	p.wdl.init()
	n.packets[a] = p
	return p, nil
}

// Resolve returns the addresses of host: those SetHost gave, or host
// itself if it is an IP address, or else a *net.DNSError that IsNotFound.
func (n *Net) Resolve(_ context.Context, host string) ([]netip.Addr, error) {
	n.mu.Lock()
	a, ok := n.hosts[host]
	n.mu.Unlock()
	if ok {
		return slices.Clone(a), nil
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return []netip.Addr{ip}, nil
}

type memAddr struct{ net, s string }

func (a memAddr) Network() string { return a.net }
func (a memAddr) String() string  { return a.s }

type listener struct {
	n    *Net
	addr memAddr
	ch   chan net.Conn
	once sync.Once
	done chan struct{}
}

func (l *listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *listener) Close() error {
	l.once.Do(func() {
		close(l.done)
		l.n.mu.Lock()
		delete(l.n.listeners, l.addr.s)
		l.n.mu.Unlock()
	})
	return nil
}

func (l *listener) Addr() net.Addr { return l.addr }

type datagram struct {
	b    []byte
	from net.Addr
}

type packetConn struct {
	n    *Net
	addr memAddr
	in   chan datagram
	once sync.Once
	done chan struct{}

	// Under n.mu: delayed packets reserve a receive queue slot before copying.
	pending         int
	nextIn, nextOut time.Time
	rdl, wdl        pipeDeadline
}

func (p *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		select {
		case <-p.done:
			return 0, nil, net.ErrClosed
		default:
		}
		dl, moved := p.rdl.snapshot()
		// A deadline set while blocked applies to this read, as on a
		// real socket.
		var (
			d      datagram
			got    bool
			err    error
			passed = waitDeadline(dl, func(timeout <-chan time.Time) bool {
				select {
				case d = <-p.in:
					got = true
				case <-p.done:
					err = net.ErrClosed
				case <-timeout:
					return true
				case <-moved:
				}
				return false
			})
		)
		switch {
		case passed:
			return 0, nil, os.ErrDeadlineExceeded
		case err != nil:
			return 0, nil, err
		case got:
			return copy(b, d.b), d.from, nil
		}
	}
}

// waitDeadline calls wait with a channel that receives once deadline has
// passed (nil for the zero deadline) and reports whether the deadline had
// passed or wait reported it so. The timer stops when wait returns.
func waitDeadline(deadline time.Time, wait func(timeout <-chan time.Time) bool) bool {
	if deadline.IsZero() {
		return wait(nil)
	}
	d := time.Until(deadline)
	if d <= 0 {
		return true
	}
	t := time.NewTimer(d)
	defer t.Stop()
	return wait(t.C)
}

func (p *packetConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	select {
	case <-p.done:
		return 0, net.ErrClosed
	default:
	}
	if p.wdl.expired() {
		return 0, os.ErrDeadlineExceeded
	}
	if len(b) > bufpool.MaxDatagram {
		return 0, errors.New("memnet: datagram too large")
	}
	if addr == nil || netutil.IsNilPointer(addr) {
		return 0, errors.New("memnet: nil destination")
	}
	name := addr.String()
	p.n.mu.Lock()
	dst := p.n.packets[name]
	p.n.mu.Unlock()
	if dst == nil {
		return len(b), nil
	}
	// the link of the destination (towards it) and of the source (out of it)
	to, from := p.n.LinkOf(name).To, p.n.LinkOf(p.addr.s).From
	if to.Off || from.Off || p.n.lose(max(to.Loss, from.Loss)) {
		return len(b), nil
	}
	clk := timeshim.Or(p.n.Clock)
	now := clk.Now()
	p.n.mu.Lock()
	if dst.pending+len(dst.in) >= cap(dst.in) {
		p.n.mu.Unlock()
		return len(b), nil
	}
	dst.pending++
	tx := reserveLink(now, &dst.nextIn, len(b), to.Rate)
	out := reserveLink(now, &p.nextOut, len(b), from.Rate)
	delay := addDelay(max(tx, out), addDelay(to.Delay, from.Delay))
	p.n.mu.Unlock()
	d := datagram{from: p.addr, b: slices.Clone(b)}
	if delay <= 0 {
		dst.deliver(d)
		return len(b), nil
	}
	timer := timeshim.NewTimer(clk, delay)
	go func() {
		defer timer.Stop()
		select {
		case <-timer.C:
			dst.deliver(d)
		case <-dst.done:
			dst.n.mu.Lock()
			dst.pending--
			dst.n.mu.Unlock()
		}
	}()
	return len(b), nil
}

func reserveLink(now time.Time, next *time.Time, size int, rate int64) time.Duration {
	if rate <= 0 {
		return 0
	}
	start := now
	if next.After(now) {
		start = *next
	}
	*next = start.Add(transmission(size, rate))
	return next.Sub(now)
}

func (p *packetConn) deliver(d datagram) {
	p.n.mu.Lock()
	defer p.n.mu.Unlock()
	p.pending--
	select {
	case <-p.done:
		return
	default:
	}
	p.in <- d // the sender reserved this slot
}

func (p *packetConn) Close() error {
	p.once.Do(func() {
		close(p.done)
		p.n.mu.Lock()
		delete(p.n.packets, p.addr.s)
		p.n.mu.Unlock()
	})
	return nil
}

func (p *packetConn) LocalAddr() net.Addr { return p.addr }

func (p *packetConn) SetDeadline(t time.Time) error { p.wdl.set(t); return p.SetReadDeadline(t) }

func (p *packetConn) SetReadDeadline(t time.Time) error {
	p.rdl.set(t)
	return nil
}

func (p *packetConn) SetWriteDeadline(t time.Time) error { p.wdl.set(t); return nil }

// halfConn is one end of a stream connection: r carries the peer's bytes,
// w ours, so CloseWrite is a FIN (the peer reads EOF and may still write)
// and Close ends both directions.
type halfConn struct {
	r, w    *streamDir
	linger0 atomic.Bool // Close resets (SetLinger(0)): the peer gets ECONNRESET; atomic as net.TCPConn allows SetLinger beside Close
}

// Pipe returns the two ends of an in-memory stream connection buffered like
// a socket, 256 KiB in each direction, unlike net.Pipe, whose unbuffered
// writes block two ends that write at once until one reads. CloseWrite ends
// the writing direction alone, and after SetLinger(0) Close resets the
// connection: the peer's reads and writes fail with ECONNRESET.
func Pipe() (net.Conn, net.Conn) {
	// The caller owns both ends and closes them independently.
	//goland:noinspection GoResourceLeak
	return halfPipe()
}

// halfPipe is Pipe with the concrete ends.
func halfPipe() (*halfConn, *halfConn) {
	ab, ba := newStreamDir(), newStreamDir()
	return &halfConn{r: ba, w: ab}, &halfConn{r: ab, w: ba}
}

func (c *halfConn) Read(p []byte) (int, error)  { return c.r.read(p) }
func (c *halfConn) Write(p []byte) (int, error) { return c.w.write(p) }
func (c *halfConn) CloseWrite() error           { c.w.closeWrite(); return nil }
func (c *halfConn) Close() error {
	if c.linger0.Load() {
		c.w.reset()
		c.r.reset()
	}
	c.w.closeWrite()
	c.r.closeRead()
	return nil
}

// SetLinger is net.TCPConn's: 0 makes Close a reset (RST), anything else
// an orderly close.
func (c *halfConn) SetLinger(sec int) error            { c.linger0.Store(sec == 0); return nil }
func (c *halfConn) LocalAddr() net.Addr                { return pipeAddr{} }
func (c *halfConn) RemoteAddr() net.Addr               { return pipeAddr{} }
func (c *halfConn) SetReadDeadline(t time.Time) error  { c.r.rdl.set(t); return nil }
func (c *halfConn) SetWriteDeadline(t time.Time) error { c.w.wdl.set(t); return nil }
func (c *halfConn) SetDeadline(t time.Time) error {
	c.r.rdl.set(t)
	c.w.wdl.set(t)
	return nil
}

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }

// streamBuf is the bytes one direction holds before a write blocks, of
// the order of a socket buffer.
const streamBuf = 256 << 10

// streamDir is one direction of a stream connection: a bounded byte queue.
type streamDir struct {
	mu       sync.Mutex
	buf      []byte
	wclosed  bool          // FIN: the reader gets EOF once drained
	rst      bool          // RST: both ends fail at once, the bytes dropped
	rclosed  bool          // the reader closed: writes fail
	changed  chan struct{} // closed and replaced on every state change
	rdl, wdl pipeDeadline
}

func newStreamDir() *streamDir {
	d := &streamDir{changed: make(chan struct{})}
	d.rdl.init()
	d.wdl.init()
	return d
}

// signalLocked wakes every waiter.
func (d *streamDir) signalLocked() {
	close(d.changed)
	d.changed = make(chan struct{})
}

func (d *streamDir) read(p []byte) (int, error) {
	for {
		d.mu.Lock()
		switch {
		case d.rst:
			d.mu.Unlock()
			return 0, errReset
		case d.rclosed:
			d.mu.Unlock()
			return 0, io.ErrClosedPipe
		case d.rdl.expired():
			d.mu.Unlock()
			return 0, os.ErrDeadlineExceeded
		case len(d.buf) > 0:
			if len(p) == 0 {
				d.mu.Unlock()
				return 0, nil
			}
			n := copy(p, d.buf)
			d.buf = d.buf[n:]
			d.signalLocked()
			d.mu.Unlock()
			return n, nil
		case d.wclosed:
			d.mu.Unlock()
			return 0, io.EOF
		}
		ch := d.changed
		d.mu.Unlock()
		if err := d.rdl.wait(ch); err != nil {
			return 0, err
		}
	}
}

func (d *streamDir) write(p []byte) (int, error) {
	n := 0
	for {
		d.mu.Lock()
		switch {
		case d.rst:
			d.mu.Unlock()
			return n, errReset
		case d.wclosed:
			d.mu.Unlock()
			return n, io.ErrClosedPipe
		case d.rclosed:
			d.mu.Unlock()
			return n, io.ErrClosedPipe
		case d.wdl.expired():
			d.mu.Unlock()
			return n, os.ErrDeadlineExceeded
		case n == len(p):
			d.mu.Unlock()
			return n, nil
		}
		if free := streamBuf - len(d.buf); free > 0 {
			k := min(free, len(p)-n)
			d.buf = append(d.buf, p[n:n+k]...)
			n += k
			d.signalLocked()
			d.mu.Unlock()
			continue
		}
		ch := d.changed
		d.mu.Unlock()
		if err := d.wdl.wait(ch); err != nil {
			return n, err
		}
	}
}

func (d *streamDir) closeWrite() {
	d.mu.Lock()
	if !d.wclosed {
		d.wclosed = true
		d.signalLocked()
	}
	d.mu.Unlock()
}

// reset is an RST: the queued bytes are dropped, every read and write
// of both ends fails with errReset.
func (d *streamDir) reset() {
	d.mu.Lock()
	if !d.rst {
		d.rst, d.buf = true, nil
		d.signalLocked()
	}
	d.mu.Unlock()
}

func (d *streamDir) closeRead() {
	d.mu.Lock()
	if !d.rclosed {
		d.rclosed = true
		d.buf = nil
		d.signalLocked()
	}
	d.mu.Unlock()
}

// pipeDeadline is a settable deadline that wakes the waiters when it moves.
type pipeDeadline struct {
	mu    sync.Mutex
	t     time.Time
	moved chan struct{}
}

func (dl *pipeDeadline) init() { dl.moved = make(chan struct{}) }

func (dl *pipeDeadline) set(t time.Time) {
	dl.mu.Lock()
	dl.t = t
	close(dl.moved)
	dl.moved = make(chan struct{})
	dl.mu.Unlock()
}

func (dl *pipeDeadline) expired() bool {
	dl.mu.Lock()
	defer dl.mu.Unlock()
	return !dl.t.IsZero() && !time.Now().Before(dl.t)
}

func (dl *pipeDeadline) snapshot() (time.Time, <-chan struct{}) {
	dl.mu.Lock()
	defer dl.mu.Unlock()
	return dl.t, dl.moved
}

// wait blocks until ch is closed (nil) or the deadline passes.
func (dl *pipeDeadline) wait(ch <-chan struct{}) error {
	for {
		t, moved := dl.snapshot()
		done := false
		if waitDeadline(t, func(timeout <-chan time.Time) bool {
			select {
			case <-ch:
				done = true
			case <-timeout:
				return true
			case <-moved:
			}
			return false
		}) {
			return os.ErrDeadlineExceeded
		}
		if done {
			return nil
		}
	}
}
