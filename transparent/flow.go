package transparent

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/djylb/netx/internal/dgram"
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
	c     *net.UDPConn
	flows dgram.Table[flowKey, *FlowConn]
	// closeErr is the error of closing c, set once.
	closeErr  error
	wg        sync.WaitGroup
	opts      flowOptions
	closeOnce sync.Once
	// mu orders the reply loops that wg counts before Close's wait: once
	// closed is set, none starts.
	mu     sync.Mutex
	closed bool
}

type flowKey struct {
	src, dst netip.AddrPort
}

type flowOptions struct {
	queue    int
	backlog  int
	maxConns int
	idle     time.Duration
	direct   bool
}

// Defaults of NewFlowListener.
const (
	// DefaultFlowQueue is how many datagrams a connection holds until they
	// are read; see WithFlowQueue.
	DefaultFlowQueue = 128
	// DefaultFlowAcceptBacklog is how many new connections wait for Accept;
	// see WithFlowAcceptBacklog.
	DefaultFlowAcceptBacklog = 128
)

// FlowOption configures ListenUDPFlows and NewFlowListener.
type FlowOption func(*flowOptions)

// WithFlowQueue sets how many datagrams a connection holds until they are
// read, DefaultFlowQueue by default. A datagram larger than 2 KiB takes the
// room of several in proportion to its size, so a connection holds at most
// n × 2 KiB of queued datagrams, or a single larger one.
func WithFlowQueue(n int) FlowOption {
	return func(o *flowOptions) { o.queue = n }
}

// WithFlowAcceptBacklog sets how many new connections wait for Accept,
// DefaultFlowAcceptBacklog by default.
func WithFlowAcceptBacklog(n int) FlowOption {
	return func(o *flowOptions) { o.backlog = n }
}

// WithFlowMaxConns sets how many connections the listener holds at once,
// accepted or waiting for Accept; a non-positive n, the default, sets no
// limit. While it holds n, a datagram of a new flow is dropped before
// anything is allocated for it. Each connection holds its queued datagrams
// and, once it has written, a socket, so the limit bounds the listener's
// memory and descriptors with WithFlowQueue. Sources that spoof their
// address can take every place, and keep it while they send, until an idle
// timeout or the application closes their connections: pair the limit with
// WithFlowIdleTimeout.
func WithFlowMaxConns(n int) FlowOption {
	return func(o *flowOptions) { o.maxConns = n }
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
	cfg := flowOptions{queue: DefaultFlowQueue, backlog: DefaultFlowAcceptBacklog}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	cfg.queue = max(cfg.queue, 1)
	cfg.backlog = max(cfg.backlog, 1)
	l := &FlowListener{c: c, opts: cfg}
	l.flows.Init(cfg.backlog, cfg.maxConns, (*FlowConn).queue, (*FlowConn).shutdown)
	if cfg.idle > 0 {
		l.wg.Go(func() { l.flows.Sweep(cfg.idle) })
	}
	return l
}

// Accept waits for the next flow and returns its *FlowConn. It returns
// net.ErrClosed once the listener is closed. The idle timeout of a
// connection starts when it is accepted.
func (l *FlowListener) Accept() (net.Conn, error) {
	f, err := l.flows.Accept()
	if err != nil {
		return nil, err
	}
	return f, nil
}

// Close closes the socket and every connection of the listener, and waits
// for the listener's goroutines to stop.
func (l *FlowListener) Close() error {
	l.closeOnce.Do(func() {
		l.mu.Lock()
		l.closed = true
		l.mu.Unlock()
		l.flows.Close(net.ErrClosed)
		l.closeErr = l.c.Close()
	})
	l.wg.Wait()
	return l.closeErr
}

// Addr returns the listening socket's address.
func (l *FlowListener) Addr() net.Addr {
	return l.c.LocalAddr()
}

func (l *FlowListener) readLoop() {
	buf := make([]byte, dgram.MaxDatagram)
	done := l.flows.Done()
	var backoff dgram.Backoff
	for {
		n, info, err := ReadFromUDP(l.c, buf)
		if err == nil {
			backoff.Reset()
			l.deliver(buf[:n], info)
			continue
		}
		if dgram.IsClosed(done) {
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
		if !backoff.Wait(done) {
			return
		}
	}
}

// deliver queues a datagram for its flow, starting the flow if it is new and
// the backlog and the connection limit have room. Only the read loop starts
// flows.
func (l *FlowListener) deliver(p []byte, info PacketInfo) {
	if !info.Redirected && !l.opts.direct {
		return
	}
	key := flowKey{src: info.Src, dst: info.Dst}
	f, ok := l.flows.Get(key)
	if !ok {
		// Dropped before anything is allocated for it while Accept falls
		// behind or the limit is reached.
		if !l.flows.Room() {
			return
		}
		if f, _ = l.flows.Add(key, l.newFlow(key, info.Redirected), true); f == nil {
			return
		}
	}
	f.q.Enqueue(p)
}

func (l *FlowListener) newFlow(key flowKey, redirected bool) *FlowConn {
	f := &FlowConn{
		l:          l,
		key:        key,
		redirected: redirected,
		local:      net.UDPAddrFromAddrPort(key.dst),
		remote:     net.UDPAddrFromAddrPort(key.src),
	}
	f.q.Init(l.opts.queue)
	f.datagramSource = dgram.NewSource(f, &f.q)
	return f
}

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
	q      dgram.Queue
	datagramSource
	// reply is the socket that answers the flow, once a Write opened it.
	reply         *net.UDPConn
	writeDeadline time.Time
	key           flowKey
	mu            sync.Mutex // reply, writeDeadline
	closeOnce     sync.Once
	redirected    bool
}

func (f *FlowConn) queue() *dgram.Queue { return &f.q }

// datagramSource is embedded in FlowConn, so that netx.Relay and netx.Copy
// take the flow's queued datagrams whole; see dgram.Source.
type datagramSource = dgram.Source

// Redirected reports whether the flow was redirected to the listener rather
// than sent to it directly, which only WithFlowDirect accepts.
func (f *FlowConn) Redirected() bool { return f.redirected }

// Read reads the next datagram of the flow into b, truncated to b. As on a
// socket, an expired read deadline fails it even while datagrams are
// queued. It returns io.EOF once an idle timeout closed f, and net.ErrClosed
// once f or the listener is closed.
func (f *FlowConn) Read(b []byte) (int, error) { return f.q.Read(b) }

// Write sends b to the source as one datagram from the original destination.
func (f *FlowConn) Write(b []byte) (int, error) {
	if !f.redirected {
		f.mu.Lock()
		dl := f.writeDeadline
		f.mu.Unlock()
		if f.q.Closed() {
			return 0, net.ErrClosed
		}
		if !dl.IsZero() && !time.Now().Before(dl) {
			return 0, os.ErrDeadlineExceeded
		}
		n, err := writeFrom(f.l.c, b, f.key.dst, f.key.src)
		if err == nil {
			f.q.Touch()
		}
		return n, err
	}
	reply, err := f.replySocket()
	if err != nil {
		return 0, err
	}
	n, err := reply.Write(b)
	if err == nil {
		f.q.Touch()
	}
	return n, err
}

// replySocket returns the socket that answers the flow, opening it and
// starting to read the flow's datagrams from it on the first call.
func (f *FlowConn) replySocket() (*net.UDPConn, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.q.Closed() {
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
	// The reply loop is counted before Close waits for the listener's
	// goroutines, or not started once Close has begun.
	f.l.mu.Lock()
	if f.l.closed {
		f.l.mu.Unlock()
		_ = reply.Close()
		return nil, net.ErrClosed
	}
	f.l.wg.Add(1)
	f.l.mu.Unlock()
	f.reply = reply
	go func() {
		defer f.l.wg.Done()
		f.replyLoop(reply)
	}()
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
			if f.q.Closed() || errors.Is(err, net.ErrClosed) {
				return
			}
			// ICMP errors, such as a refused port, concern earlier writes.
			continue
		}
		f.q.Enqueue((*bp)[:n])
		dgram.Large.Put(bp)
	}
}

// Close closes the flow and its answering socket. Its pending and later
// Reads and Writes return net.ErrClosed, and the next datagram of the flow
// starts a new connection.
func (f *FlowConn) Close() error {
	if f.q.Closed() {
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
		f.l.flows.Remove(f.key, f)
		if testHookFlowShutdown != nil {
			testHookFlowShutdown(f)
		}
		f.mu.Lock()
		f.q.Close(err)
		reply := f.reply
		f.reply = nil
		f.mu.Unlock()
		if reply != nil {
			_ = reply.Close()
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
	if f.q.Closed() {
		return net.ErrClosed
	}
	f.q.SetReadDeadline(t)
	return nil
}

// SetWriteDeadline sets the deadline of later Writes.
func (f *FlowConn) SetWriteDeadline(t time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.q.Closed() {
		return net.ErrClosed
	}
	f.writeDeadline = t
	if f.reply != nil {
		return f.reply.SetWriteDeadline(t)
	}
	return nil
}
