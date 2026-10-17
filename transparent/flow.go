package transparent

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// FlowListener accepts one connection per flow of the datagrams that TPROXY
// redirects to a UDP socket: per source and original destination. The first
// datagram of a flow starts a *FlowConn that Accept returns; later datagrams
// of the flow are read from it, and its writes answer the source from the
// original destination. It is available on Linux and Android.
//
// Each Read of a connection returns one datagram, truncated to the buffer
// like a UDP socket. Datagrams that arrive while a connection's queue is
// full, or while too many connections wait for Accept, are dropped. Datagrams
// sent to the socket directly, which ReadFromUDP reports as not redirected,
// are dropped too unless WithFlowDirect is given: answering them as a proxy
// would send them to the socket again. After a connection is closed, the next
// datagram of its flow starts a new one. A connection lasts until it is
// closed, so a listener facing untrusted or spoofed sources should set
// WithFlowIdleTimeout or read deadlines.
type FlowListener struct {
	c      *net.UDPConn
	accept chan *FlowConn
	done   chan struct{}
	flows  map[flowKey]*FlowConn
	// closeErr is the error of closing c, set once.
	closeErr  error
	wg        sync.WaitGroup
	opts      flowOptions
	mu        sync.Mutex
	closeOnce sync.Once
}

type flowKey struct {
	src, dst netip.AddrPort
}

type flowOptions struct {
	queue   int
	backlog int
	idle    time.Duration
	direct  bool
}

// FlowOption configures ListenUDPFlows and NewFlowListener.
type FlowOption func(*flowOptions)

// WithFlowQueue sets how many datagrams a connection holds until they are
// read, 128 by default. A datagram larger than 2 KiB takes the room of
// several in proportion to its size, so a connection holds at most n × 2 KiB
// of queued datagrams, or a single larger one.
func WithFlowQueue(n int) FlowOption {
	return func(o *flowOptions) { o.queue = n }
}

// WithFlowAcceptBacklog sets how many new connections wait for Accept, 128
// by default.
func WithFlowAcceptBacklog(n int) FlowOption {
	return func(o *flowOptions) { o.backlog = n }
}

// WithFlowIdleTimeout closes a connection that has neither received nor sent
// a datagram for d since Accept returned it. Its pending and later Reads
// return io.EOF. Connections waiting for Accept are kept with their
// datagrams. A non-positive d, the default, keeps idle connections.
func WithFlowIdleTimeout(d time.Duration) FlowOption {
	return func(o *flowOptions) { o.idle = d }
}

// WithFlowDirect also accepts flows of datagrams sent to the socket directly,
// not redirected, which are dropped by default. FlowConn.Redirected tells
// them apart, and their connections answer from the listening socket, from
// the address the source sent to.
func WithFlowDirect() FlowOption {
	return func(o *flowOptions) { o.direct = true }
}

// ListenUDPFlows listens on a UDP address with ListenPacket and returns a
// FlowListener for the datagrams redirected to it. network must be "udp",
// "udp4" or "udp6". It needs CAP_NET_ADMIN. It is available on Linux and
// Android; elsewhere it returns ErrListenUnsupported.
func ListenUDPFlows(ctx context.Context, network, address string, opts ...FlowOption) (*FlowListener, error) {
	c, err := ListenPacket(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return NewFlowListener(c, opts...)
}

// NewFlowListener starts reading c, a socket set up with ControlPacket, such
// as one from ListenPacket, and returns a FlowListener for its flows. The
// listener owns c and closes it on Close; c must not be read otherwise. A
// read error meaning that c is closed closes the listener; other read errors
// are retried, with a growing delay while they persist, and an expired read
// deadline on c is cleared. It is available on Linux and Android; elsewhere
// it returns ErrListenUnsupported.
func NewFlowListener(c *net.UDPConn, opts ...FlowOption) (*FlowListener, error) {
	if err := packetErr(); err != nil {
		return nil, err
	}
	if c == nil {
		return nil, errors.New("transparent: nil UDP connection")
	}
	l := newFlowListener(c, opts)
	l.wg.Go(l.readLoop)
	return l, nil
}

// newFlowListener returns a listener on c that reads nothing yet.
func newFlowListener(c *net.UDPConn, opts []FlowOption) *FlowListener {
	cfg := flowOptions{queue: 128, backlog: 128}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	cfg.queue = max(cfg.queue, 1)
	cfg.backlog = max(cfg.backlog, 1)
	l := &FlowListener{
		c:      c,
		opts:   cfg,
		accept: make(chan *FlowConn, cfg.backlog),
		done:   make(chan struct{}),
		flows:  make(map[flowKey]*FlowConn),
	}
	if cfg.idle > 0 {
		l.wg.Go(l.sweepLoop)
	}
	return l
}

// Accept waits for the next flow and returns its *FlowConn. It returns
// net.ErrClosed once the listener is closed. The idle timeout of a
// connection starts when it is accepted.
func (l *FlowListener) Accept() (net.Conn, error) {
	for {
		select {
		case <-l.done:
			return nil, net.ErrClosed
		default:
		}
		select {
		case f := <-l.accept:
			if isClosedChan(f.closed) {
				continue
			}
			f.touch()
			f.accepted.Store(true)
			return f, nil
		case <-l.done:
			return nil, net.ErrClosed
		}
	}
}

// Close closes the socket and every connection of the listener, and waits
// for the listener's goroutines to stop.
func (l *FlowListener) Close() error {
	l.closeOnce.Do(func() {
		l.mu.Lock()
		close(l.done)
		flows := make([]*FlowConn, 0, len(l.flows))
		for _, f := range l.flows {
			flows = append(flows, f)
		}
		l.mu.Unlock()
		l.closeErr = l.c.Close()
		for _, f := range flows {
			f.shutdown(net.ErrClosed)
		}
		for {
			select {
			case f := <-l.accept:
				f.shutdown(net.ErrClosed)
				continue
			default:
			}
			break
		}
	})
	l.wg.Wait()
	return l.closeErr
}

// Addr returns the listening socket's address.
func (l *FlowListener) Addr() net.Addr {
	return l.c.LocalAddr()
}

func (l *FlowListener) readLoop() {
	buf := make([]byte, maxDatagram)
	var failures int
	var delay time.Duration
	for {
		n, info, err := ReadFromUDP(l.c, buf)
		if err == nil {
			failures, delay = 0, 0
			l.deliver(buf[:n], info)
			continue
		}
		if isClosedChan(l.done) {
			return
		}
		switch {
		case errors.Is(err, net.ErrClosed):
			// Close waits for this goroutine, so it cannot be called here.
			go func() { _ = l.Close() }()
			return
		case errors.Is(err, os.ErrDeadlineExceeded):
			// The listener owns c's reads; a deadline left on c would fail
			// every one of them.
			_ = l.c.SetReadDeadline(time.Time{})
		case info.Src.IsValid():
			// A datagram was read but its destination is unknown, as with
			// ErrControlTruncated: only it is lost.
			continue
		}
		// ICMP errors reported on the socket and the like do not end the
		// loop; errors that persist are retried with a growing delay.
		if failures++; failures > 1 {
			delay = min(max(2*delay, time.Millisecond), time.Second)
			if !l.sleep(delay) {
				return
			}
		}
	}
}

// sleep waits for d and reports false if the listener closed first.
func (l *FlowListener) sleep(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-l.done:
		return false
	}
}

// deliver queues a datagram for its flow, starting the flow if it is new and
// the backlog has room. Only the read loop starts flows.
func (l *FlowListener) deliver(p []byte, info PacketInfo) {
	if !info.Redirected && !l.opts.direct {
		return
	}
	key := flowKey{src: info.Src, dst: info.Dst}
	l.mu.Lock()
	f := l.flows[key]
	if f == nil {
		// Only this goroutine adds to the backlog, so it stays with room
		// once it has some.
		if isClosedChan(l.done) || len(l.accept) == cap(l.accept) {
			l.mu.Unlock()
			return
		}
		f = l.newFlow(key, info.Redirected)
		l.flows[key] = f
		l.accept <- f
	}
	l.mu.Unlock()
	f.enqueue(p)
}

func (l *FlowListener) newFlow(key flowKey, redirected bool) *FlowConn {
	return &FlowConn{
		l:          l,
		key:        key,
		redirected: redirected,
		local:      net.UDPAddrFromAddrPort(key.dst),
		remote:     net.UDPAddrFromAddrPort(key.src),
		queue:      make(chan *[]byte, l.opts.queue),
		closed:     make(chan struct{}),
		budget:     int64(l.opts.queue) * flowBufSize,
		readWait:   makeDeadline(),
	}
}

func (l *FlowListener) remove(f *FlowConn) {
	l.mu.Lock()
	if l.flows[f.key] == f {
		delete(l.flows, f.key)
	}
	l.mu.Unlock()
}

func (l *FlowListener) sweepLoop() {
	ticker := time.NewTicker(max(l.opts.idle/4, 10*time.Millisecond))
	defer ticker.Stop()
	var idle []*FlowConn
	for {
		select {
		case <-l.done:
			return
		case now := <-ticker.C:
			l.mu.Lock()
			for _, f := range l.flows {
				if f.accepted.Load() && now.Sub(time.Unix(0, f.active.Load())) >= l.opts.idle {
					idle = append(idle, f)
				}
			}
			l.mu.Unlock()
			for i, f := range idle {
				f.shutdown(io.EOF)
				idle[i] = nil
			}
			idle = idle[:0]
		}
	}
}

const (
	// maxDatagram holds the largest UDP datagram.
	maxDatagram = 65535
	// flowBufSize is the size of the pooled buffers of queued datagrams and
	// the unit of a queue's room.
	flowBufSize = 2048
)

var (
	flowBufPool = sync.Pool{New: func() any {
		b := make([]byte, flowBufSize)
		return &b
	}}
	datagramPool = sync.Pool{New: func() any {
		b := make([]byte, maxDatagram)
		return &b
	}}
)

// FlowConn is a flow that a FlowListener accepted: the datagrams from one
// source to one original destination. Its RemoteAddr is the source and its
// LocalAddr the original destination, both *net.UDPAddr.
//
// Writes are sent to the source from the original destination, through a
// socket that DialUDP binds to it on the first Write and that is closed with
// the connection; the source's later datagrams arrive on that socket, and are
// read from the connection like the others. A flow sent to the listening
// socket directly, accepted with WithFlowDirect, is answered from the
// listening socket, from the address the source sent to.
type FlowConn struct {
	l      *FlowListener
	local  net.Addr
	remote net.Addr
	queue  chan *[]byte
	closed chan struct{}
	// reply is the socket that answers the flow, once a Write opened it.
	reply *net.UDPConn
	// err is what Read returns once closed is closed.
	err           error
	writeDeadline time.Time
	readWait      deadline
	key           flowKey
	budget        int64
	queued        atomic.Int64
	active        atomic.Int64 // unix nanoseconds of the last datagram
	mu            sync.Mutex   // reply, writeDeadline
	closeOnce     sync.Once
	accepted      atomic.Bool
	redirected    bool
}

// Redirected reports whether the flow was redirected to the listener rather
// than sent to it directly, which only WithFlowDirect accepts.
func (f *FlowConn) Redirected() bool { return f.redirected }

func (f *FlowConn) touch() { f.active.Store(time.Now().UnixNano()) }

// enqueue copies p to the queue unless the queue is full or f is closed.
func (f *FlowConn) enqueue(p []byte) {
	if isClosedChan(f.closed) {
		return
	}
	cost := int64(max(len(p), flowBufSize))
	if q := f.queued.Load(); q > 0 && q+cost > f.budget {
		return
	}
	var bp *[]byte
	if len(p) <= flowBufSize {
		bp = flowBufPool.Get().(*[]byte)
		*bp = (*bp)[:len(p)]
	} else {
		b := make([]byte, len(p))
		bp = &b
	}
	copy(*bp, p)
	select {
	case f.queue <- bp:
		f.queued.Add(cost)
		f.touch()
	default:
		putFlowBuf(bp)
	}
}

func putFlowBuf(bp *[]byte) {
	if cap(*bp) == flowBufSize {
		*bp = (*bp)[:flowBufSize]
		flowBufPool.Put(bp)
	}
}

// Read reads the next datagram of the flow into b, truncated to b. It returns
// io.EOF once an idle timeout closed f, and net.ErrClosed once f or the
// listener is closed.
func (f *FlowConn) Read(b []byte) (int, error) {
	select {
	case <-f.closed:
		return 0, f.err
	default:
	}
	select {
	case bp := <-f.queue:
		if isClosedChan(f.closed) {
			return 0, f.err
		}
		n := copy(b, *bp)
		f.queued.Add(-int64(max(len(*bp), flowBufSize)))
		putFlowBuf(bp)
		return n, nil
	case <-f.closed:
		return 0, f.err
	case <-f.readWait.wait():
		return 0, os.ErrDeadlineExceeded
	}
}

// Write sends b to the source as one datagram from the original destination.
func (f *FlowConn) Write(b []byte) (int, error) {
	if !f.redirected {
		f.mu.Lock()
		dl := f.writeDeadline
		f.mu.Unlock()
		if isClosedChan(f.closed) {
			return 0, net.ErrClosed
		}
		if !dl.IsZero() && !time.Now().Before(dl) {
			return 0, os.ErrDeadlineExceeded
		}
		n, err := writeFrom(f.l.c, b, f.key.dst, f.key.src)
		if err == nil {
			f.touch()
		}
		return n, err
	}
	reply, err := f.replySocket()
	if err != nil {
		return 0, err
	}
	n, err := reply.Write(b)
	if err == nil {
		f.touch()
	}
	return n, err
}

// replySocket returns the socket that answers the flow, opening it and
// starting to read the flow's datagrams from it on the first call.
func (f *FlowConn) replySocket() (*net.UDPConn, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if isClosedChan(f.closed) {
		return nil, net.ErrClosed
	}
	if f.reply != nil {
		return f.reply, nil
	}
	reply, err := DialUDP(context.Background(), f.key.dst, f.key.src)
	if err != nil {
		return nil, err
	}
	if !f.writeDeadline.IsZero() {
		_ = reply.SetWriteDeadline(f.writeDeadline)
	}
	f.reply = reply
	// shutdown closes reply under mu before the listener waits for its
	// goroutines, so this Go call happens before that wait.
	f.l.wg.Go(func() { f.replyLoop(reply) })
	return reply, nil
}

// replyLoop queues the datagrams that arrive on reply until it is closed.
func (f *FlowConn) replyLoop(reply *net.UDPConn) {
	raw, err := reply.SyscallConn()
	if err != nil {
		return
	}
	for {
		bp, n, err := readDatagram(raw)
		if err != nil {
			if isClosedChan(f.closed) || errors.Is(err, net.ErrClosed) {
				return
			}
			// ICMP errors, such as a refused port, concern earlier writes.
			continue
		}
		f.enqueue((*bp)[:n])
		datagramPool.Put(bp)
	}
}

// Close closes the flow and its answering socket. Its pending and later
// Reads and Writes return net.ErrClosed, and the next datagram of the flow
// starts a new connection.
func (f *FlowConn) Close() error {
	if isClosedChan(f.closed) {
		return net.ErrClosed
	}
	f.shutdown(net.ErrClosed)
	return nil
}

// testHookFlowShutdown, set by tests, runs in shutdown once f is removed
// from its listener, before it is closed.
var testHookFlowShutdown func(f *FlowConn)

func (f *FlowConn) shutdown(err error) {
	f.closeOnce.Do(func() {
		// Removed first, so that a datagram arriving from here on starts a
		// new flow rather than finding this one closed.
		f.l.remove(f)
		if testHookFlowShutdown != nil {
			testHookFlowShutdown(f)
		}
		f.mu.Lock()
		f.err = err
		close(f.closed)
		reply := f.reply
		f.reply = nil
		f.mu.Unlock()
		if reply != nil {
			_ = reply.Close()
		}
		f.readWait.stop()
		for {
			select {
			case bp := <-f.queue:
				putFlowBuf(bp)
				continue
			default:
			}
			break
		}
	})
}

// LocalAddr returns the flow's original destination.
func (f *FlowConn) LocalAddr() net.Addr { return f.local }

// RemoteAddr returns the flow's source.
func (f *FlowConn) RemoteAddr() net.Addr { return f.remote }

// SetDeadline sets the read and write deadlines.
func (f *FlowConn) SetDeadline(t time.Time) error {
	if err := f.SetReadDeadline(t); err != nil {
		return err
	}
	return f.SetWriteDeadline(t)
}

// SetReadDeadline sets the deadline of pending and later Reads.
func (f *FlowConn) SetReadDeadline(t time.Time) error {
	if isClosedChan(f.closed) {
		return net.ErrClosed
	}
	f.readWait.set(t)
	return nil
}

// SetWriteDeadline sets the deadline of later Writes.
func (f *FlowConn) SetWriteDeadline(t time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if isClosedChan(f.closed) {
		return net.ErrClosed
	}
	f.writeDeadline = t
	if f.reply != nil {
		return f.reply.SetWriteDeadline(t)
	}
	return nil
}

// deadline is a channel that is closed when a deadline passes.
type deadline struct {
	timer *time.Timer
	ch    chan struct{}
	mu    *sync.Mutex
}

func makeDeadline() deadline {
	return deadline{ch: make(chan struct{}), mu: new(sync.Mutex)}
}

// set arms the deadline at t, or disarms it for a zero t. A Read waiting on
// the channel keeps waiting on it unless t has passed.
func (d *deadline) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
	if isClosedChan(d.ch) {
		d.ch = make(chan struct{})
	}
	if t.IsZero() {
		return
	}
	if dur := time.Until(t); dur > 0 {
		ch := d.ch
		d.timer = time.AfterFunc(dur, func() {
			d.mu.Lock()
			defer d.mu.Unlock()
			if d.ch == ch && !isClosedChan(ch) {
				close(ch)
			}
		})
		return
	}
	close(d.ch)
}

func (d *deadline) stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
}

func (d *deadline) wait() chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.ch
}

func isClosedChan(c chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}
