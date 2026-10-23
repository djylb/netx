package netx

import (
	"context"
	"errors"
	"net"
	"sync"
)

var errNilListenerConn = errors.New("netx: nil connection")

// ChanListener is a net.Listener fed by the program instead of a socket.
// Deliver hands it a connection accepted elsewhere, and Dial connects to it
// through an in-memory pipe. Accept returns the connections in order. All
// methods are safe for concurrent use. The zero value is ready to use, as a
// ChanListener of NewChanListener(nil, 0).
type ChanListener struct {
	addr      net.Addr
	conns     chan net.Conn
	done      chan struct{}
	initOnce  sync.Once
	closeOnce sync.Once
}

// init makes the channels of the zero ChanListener.
func (l *ChanListener) init() {
	l.initOnce.Do(func() {
		if l.conns == nil {
			l.conns = make(chan net.Conn)
		}
		if l.done == nil {
			l.done = make(chan struct{})
		}
	})
}

// NewChanListener returns a ChanListener that reports addr from Addr and
// holds up to queue connections that Accept has not taken yet. A nil addr is
// reported as "pipe". With a non-positive queue, Deliver and Dial wait for
// Accept.
func NewChanListener(addr net.Addr, queue int) *ChanListener {
	if addr == nil {
		addr = pipeAddr{}
	}
	return &ChanListener{
		addr:  addr,
		conns: make(chan net.Conn, max(queue, 0)),
		done:  make(chan struct{}),
	}
}

// Deliver queues c for Accept, waiting for queue space until ctx is done or l
// is closed. On success l owns c: Accept returns it, or Close closes it. On
// failure it returns ctx.Err() or net.ErrClosed and c stays the caller's, to
// close or to hand elsewhere.
func (l *ChanListener) Deliver(ctx context.Context, c net.Conn) error {
	if c == nil {
		return errNilListenerConn
	}
	l.init()
	select {
	case <-l.done:
		return net.ErrClosed
	default:
	}
	// A context that is already done fails Deliver, rather than the select
	// below picking between it and free queue space at random.
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case l.conns <- c:
		l.delivered()
		return nil
	case <-l.done:
		return net.ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

// TryDeliver queues c for Accept if the queue has room and l is open, and
// reports whether it did; l then owns c, as after Deliver. Otherwise c stays
// the caller's.
func (l *ChanListener) TryDeliver(c net.Conn) bool {
	if c == nil {
		return false
	}
	l.init()
	select {
	case <-l.done:
		return false
	default:
	}
	select {
	case l.conns <- c:
		l.delivered()
		return true
	default:
		return false
	}
}

// delivered closes what a Close that raced with a delivery left queued.
func (l *ChanListener) delivered() {
	select {
	case <-l.done:
		// Close may have drained the queue before c entered it.
		l.drain()
	default:
	}
}

// Dial connects to l through a synchronous in-memory net.Pipe and returns the
// client end. The server end is queued as by Deliver. It reports remote as its
// RemoteAddr and l.Addr() as its LocalAddr, and the client end reports the
// reverse; a nil remote is reported as "pipe".
func (l *ChanListener) Dial(ctx context.Context, remote net.Addr) (net.Conn, error) {
	client, server := net.Pipe()
	addr := l.Addr()
	// Delivered, l owns sc; on failure it is closed below.
	//noinspection GoResourceLeak
	sc := NewAddrOverrideConn(server, addr, remote)
	if err := l.Deliver(ctx, sc); err != nil {
		_ = client.Close()
		_ = sc.Close()
		return nil, err
	}
	return NewAddrOverrideConn(client, remote, addr), nil
}

// Accept waits for the next queued connection. It returns net.ErrClosed once
// l is closed.
func (l *ChanListener) Accept() (net.Conn, error) {
	l.init()
	select {
	case <-l.done:
		return nil, net.ErrClosed
	default:
	}
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

// Close stops l and closes the connections still queued. Blocked Accept,
// Deliver and Dial calls return net.ErrClosed. Close always returns nil.
func (l *ChanListener) Close() error {
	l.init()
	l.closeOnce.Do(func() {
		close(l.done)
		l.drain()
	})
	return nil
}

// Addr returns the address given to NewChanListener, or "pipe".
func (l *ChanListener) Addr() net.Addr {
	if l.addr == nil {
		return pipeAddr{}
	}
	return l.addr
}

func (l *ChanListener) drain() {
	for {
		select {
		case c := <-l.conns:
			_ = c.Close()
		default:
			return
		}
	}
}

// NewSingleConnListener returns a listener whose first Accept returns c.
// Later Accept calls block until that connection or the listener is closed
// and then return net.ErrClosed, so a server loop such as http.Server.Serve
// handles c and returns when it is done.
//
// Accept returns c wrapped so that its Close can be observed; InnermostConn
// unwraps it. The wrapper hides c's concrete type, so to serve TLS pass the
// plain connection and wrap the listener with tls.NewListener.
//
// The connection belongs to the server once Accept has returned it: Close
// closes c only if Accept has not returned it yet, and otherwise only ends a
// blocked Accept, so closing the listener does not cut off the connection
// being served. To stop serving it, close the connection, or shut the server
// down, as http.Server.Shutdown does for its connections; Serve returns once
// the connection is closed.
func NewSingleConnListener(c net.Conn) *SingleConnListener {
	l := &SingleConnListener{conn: c}
	if c != nil {
		l.addr = c.LocalAddr()
	}
	return l
}

// SingleConnListener is the listener that NewSingleConnListener returns. The
// zero value has no connection: its Accept blocks until Close.
type SingleConnListener struct {
	mu       sync.Mutex
	conn     net.Conn // nil once accepted or closed
	addr     net.Addr
	done     chan struct{}
	initOnce sync.Once
	doneOnce sync.Once
}

// init makes the done channel, also of the zero SingleConnListener.
func (l *SingleConnListener) init() {
	l.initOnce.Do(func() { l.done = make(chan struct{}) })
}

// Accept returns the connection the first time and then blocks until it or
// l is closed, returning net.ErrClosed.
func (l *SingleConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	c := l.conn
	l.conn = nil
	l.mu.Unlock()
	if c != nil {
		return &singleConn{Conn: c, l: l}, nil
	}
	l.init()
	<-l.done
	return nil, net.ErrClosed
}

// Close ends a blocked Accept and closes the connection if Accept has not
// returned it yet.
func (l *SingleConnListener) Close() error {
	l.mu.Lock()
	c := l.conn
	l.conn = nil
	l.mu.Unlock()
	l.finish()
	if c != nil {
		return c.Close()
	}
	return nil
}

// Addr returns the connection's LocalAddr, or "pipe" if it has none.
func (l *SingleConnListener) Addr() net.Addr {
	if l.addr == nil {
		return pipeAddr{}
	}
	return l.addr
}

func (l *SingleConnListener) finish() {
	l.init()
	l.doneOnce.Do(func() { close(l.done) })
}

// singleConn ends its listener's Accept loop when it is closed.
type singleConn struct {
	net.Conn
	l *SingleConnListener
}

func (c *singleConn) Close() error {
	err := c.Conn.Close()
	c.l.finish()
	return err
}

func (c *singleConn) CloseWrite() error {
	return closeWrite(c.Conn)
}

func (c *singleConn) NetConn() net.Conn {
	return c.Conn
}

func (c *singleConn) netxLayer() layerInfo {
	info := layerInfo{self: c, kind: layerWraps | layerReads | layerPasses}
	if c != nil {
		info.conn = c.Conn
	}
	return info
}

// pipeAddr is the address of an in-memory connection, matching net.Pipe.
type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }
