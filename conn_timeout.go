package netx

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultTimeout is used when a helper receives a non-positive timeout.
const DefaultTimeout = 5 * time.Second

func normalizeLinkTimeout(timeout time.Duration) time.Duration {
	if timeout <= 0 {
		return DefaultTimeout
	}
	return timeout
}

// TimeoutConn closes an idle connection: before each read or write it moves
// the deadline of both directions to now plus the idle timeout. Construct it
// with NewTimeoutConn; a zero idle timeout, including one left by a struct
// literal, uses DefaultTimeout.
//
// To keep the per-call cost to an atomic load, the deadline is only moved once
// it lags behind by more than a small slack (idle/16, at most one second), so
// a connection may time out up to that slack early. SetDeadline,
// SetReadDeadline and SetWriteDeadline pass through and stay in effect until
// the next read or write moves the deadline again.
type TimeoutConn struct {
	net.Conn
	idleTimeout time.Duration
	deadline    atomic.Int64 // unix nanoseconds last set on Conn, 0 to force an update
	mu          sync.Mutex   // serializes deadline updates
}

// NewTimeoutConn wraps c and refreshes its deadline before each read or write.
func NewTimeoutConn(c net.Conn, idle time.Duration) *TimeoutConn {
	return &TimeoutConn{Conn: c, idleTimeout: normalizeLinkTimeout(idle)}
}

func (c *TimeoutConn) Read(b []byte) (int, error) {
	if c == nil || c.Conn == nil {
		return 0, net.ErrClosed
	}
	if err := c.refreshDeadline(); err != nil {
		return 0, err
	}
	return c.Conn.Read(b)
}

func (c *TimeoutConn) Write(b []byte) (int, error) {
	if c == nil || c.Conn == nil {
		return 0, net.ErrClosed
	}
	if err := c.refreshDeadline(); err != nil {
		return 0, err
	}
	return c.Conn.Write(b)
}

func (c *TimeoutConn) refreshDeadline() error {
	idle := normalizeLinkTimeout(c.idleTimeout)
	slack := int64(min(idle/16, time.Second))
	if time.Now().UnixNano()+int64(idle)-c.deadline.Load() < slack {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// Recompute under the lock so a slower caller never moves the deadline back.
	want := time.Now().UnixNano() + int64(idle)
	if want-c.deadline.Load() < slack {
		return nil
	}
	if err := c.Conn.SetDeadline(time.Unix(0, want)); err != nil {
		return err
	}
	c.deadline.Store(want)
	return nil
}

func (c *TimeoutConn) Close() error {
	if c == nil || c.Conn == nil {
		return nil
	}
	return c.Conn.Close()
}

// CloseWrite shuts down the writing side of the wrapped connection, so the
// peer reads EOF while reads continue. It returns an error matching
// errors.ErrUnsupported when the wrapped connection cannot do that.
func (c *TimeoutConn) CloseWrite() error {
	if c == nil || c.Conn == nil {
		return net.ErrClosed
	}
	return closeWrite(c.Conn)
}

func (c *TimeoutConn) LocalAddr() net.Addr {
	if c == nil || c.Conn == nil {
		return nil
	}
	return c.Conn.LocalAddr()
}

func (c *TimeoutConn) RemoteAddr() net.Addr {
	if c == nil || c.Conn == nil {
		return nil
	}
	return c.Conn.RemoteAddr()
}

func (c *TimeoutConn) SetDeadline(t time.Time) error {
	if c == nil || c.Conn == nil {
		return net.ErrClosed
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadline.Store(0) // the next read or write sets the idle deadline again
	return c.Conn.SetDeadline(t)
}

func (c *TimeoutConn) SetReadDeadline(t time.Time) error {
	if c == nil || c.Conn == nil {
		return net.ErrClosed
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadline.Store(0) // the next read or write sets the idle deadline again
	return c.Conn.SetReadDeadline(t)
}

func (c *TimeoutConn) SetWriteDeadline(t time.Time) error {
	if c == nil || c.Conn == nil {
		return net.ErrClosed
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadline.Store(0) // the next read or write sets the idle deadline again
	return c.Conn.SetWriteDeadline(t)
}

// RawConn returns the innermost connection beneath c; see RawConnProvider.
func (c *TimeoutConn) RawConn() net.Conn {
	if c == nil {
		return nil
	}
	return rawConnOf(c.Conn)
}
