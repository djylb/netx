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
// methods are safe for concurrent use.
type ChanListener struct {
	addr      net.Addr
	conns     chan net.Conn
	done      chan struct{}
	closeOnce sync.Once
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
// failure Deliver closes c and returns ctx.Err() or net.ErrClosed.
func (l *ChanListener) Deliver(ctx context.Context, c net.Conn) error {
	if c == nil {
		return errNilListenerConn
	}
	select {
	case <-l.done:
		_ = c.Close()
		return net.ErrClosed
	default:
	}
	select {
	case l.conns <- c:
		select {
		case <-l.done:
			// Close may have drained the queue before c entered it.
			l.drain()
		default:
		}
		return nil
	case <-l.done:
		_ = c.Close()
		return net.ErrClosed
	case <-ctx.Done():
		_ = c.Close()
		return ctx.Err()
	}
}

// Dial connects to l through a synchronous in-memory net.Pipe and returns the
// client end. The server end is queued as by Deliver. It reports remote as its
// RemoteAddr and l.Addr() as its LocalAddr, and the client end reports the
// reverse; a nil remote is reported as "pipe".
func (l *ChanListener) Dial(ctx context.Context, remote net.Addr) (net.Conn, error) {
	client, server := net.Pipe()
	// Deliver owns the server end from here on and closes it on failure.
	//noinspection GoResourceLeak
	if err := l.Deliver(ctx, NewAddrOverrideConn(server, remote, l.addr)); err != nil {
		_ = client.Close()
		return nil, err
	}
	return NewAddrOverrideConn(client, l.addr, remote), nil
}

// Accept waits for the next queued connection. It returns net.ErrClosed once
// l is closed.
func (l *ChanListener) Accept() (net.Conn, error) {
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
	l.closeOnce.Do(func() {
		close(l.done)
		l.drain()
	})
	return nil
}

// Addr returns the address given to NewChanListener.
func (l *ChanListener) Addr() net.Addr {
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
// Accept returns c wrapped so that its Close can be observed; RawConnOf
// unwraps it. The wrapper hides c's concrete type, so to serve TLS pass the
// plain connection and wrap the listener with tls.NewListener. Close closes c
// only if Accept has not returned it yet.
func NewSingleConnListener(c net.Conn) net.Listener {
	l := &singleConnListener{conn: c, done: make(chan struct{})}
	if c != nil {
		l.addr = c.LocalAddr()
	}
	if l.addr == nil {
		l.addr = pipeAddr{}
	}
	return l
}

type singleConnListener struct {
	mu       sync.Mutex
	conn     net.Conn // nil once accepted or closed
	addr     net.Addr
	done     chan struct{}
	doneOnce sync.Once
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	c := l.conn
	l.conn = nil
	l.mu.Unlock()
	if c != nil {
		return &singleConn{Conn: c, l: l}, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *singleConnListener) Close() error {
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

func (l *singleConnListener) Addr() net.Addr {
	return l.addr
}

func (l *singleConnListener) finish() {
	l.doneOnce.Do(func() { close(l.done) })
}

// singleConn ends its listener's Accept loop when it is closed.
type singleConn struct {
	net.Conn
	l *singleConnListener
}

func (c *singleConn) Close() error {
	err := c.Conn.Close()
	c.l.finish()
	return err
}

func (c *singleConn) CloseWrite() error {
	return closeWrite(c.Conn)
}

func (c *singleConn) RawConn() net.Conn {
	return c.Conn
}

// pipeAddr is the address of an in-memory connection, matching net.Pipe.
type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }
