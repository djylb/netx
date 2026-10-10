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
// a connection may time out up to that slack early.
//
// SetDeadline, SetReadDeadline and SetWriteDeadline are remembered until they
// are changed again. Setting them and every read and write keep each
// direction's deadline at the earlier of the remembered one and now plus the
// idle timeout, so a deadline set to interrupt a blocked Read or Write stays in
// effect while the other direction is in use, and a later or zero one does not
// lift the idle timeout of a Read or Write that is already blocked. A zero time
// leaves only the idle timeout.
type TimeoutConn struct {
	net.Conn
	idleTimeout time.Duration
	deadline    atomic.Int64 // idle deadline last set on Conn as a clock offset, 0 to force an update
	mu          sync.Mutex   // serializes deadline updates
	userRead    time.Time    // set by SetDeadline or SetReadDeadline, guarded by mu
	userWrite   time.Time    // set by SetDeadline or SetWriteDeadline, guarded by mu
}

// clockBase anchors the monotonic clock offsets that idle tracking stores in
// atomics, so a step of the wall clock neither stretches nor cuts an idle
// period.
var clockBase = time.Now()

// clockOffset returns t as a monotonic offset from clockBase.
func clockOffset(t time.Time) int64 {
	return int64(t.Sub(clockBase))
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
	if clockOffset(time.Now())+int64(idle)-c.deadline.Load() < slack {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// Recompute under the lock so a slower caller never moves the deadline back.
	now := time.Now()
	want := clockOffset(now) + int64(idle)
	if want-c.deadline.Load() < slack {
		return nil
	}
	// now.Add keeps the monotonic reading, so the socket deadline does not
	// follow wall-clock steps either.
	rd := now.Add(idle)
	wd := rd
	if !c.userRead.IsZero() && c.userRead.Before(rd) {
		rd = c.userRead
	}
	if !c.userWrite.IsZero() && c.userWrite.Before(wd) {
		wd = c.userWrite
	}
	var err error
	if rd.Equal(wd) {
		err = c.Conn.SetDeadline(rd)
	} else if err = c.Conn.SetReadDeadline(rd); err == nil {
		err = c.Conn.SetWriteDeadline(wd)
	}
	if err != nil {
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
	c.userRead, c.userWrite = t, t
	c.deadline.Store(0) // the next read or write sets the idle deadline again
	return c.Conn.SetDeadline(c.capDeadline(t))
}

func (c *TimeoutConn) SetReadDeadline(t time.Time) error {
	if c == nil || c.Conn == nil {
		return net.ErrClosed
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.userRead = t
	c.deadline.Store(0) // the next read or write sets the idle deadline again
	return c.Conn.SetReadDeadline(c.capDeadline(t))
}

func (c *TimeoutConn) SetWriteDeadline(t time.Time) error {
	if c == nil || c.Conn == nil {
		return net.ErrClosed
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.userWrite = t
	c.deadline.Store(0) // the next read or write sets the idle deadline again
	return c.Conn.SetWriteDeadline(c.capDeadline(t))
}

// capDeadline returns the deadline to set on the wrapped connection for a user
// deadline t: t when it comes before the idle deadline of an operation
// starting now, and that idle deadline otherwise, so that a Read or Write
// already blocked keeps its idle timeout.
func (c *TimeoutConn) capDeadline(t time.Time) time.Time {
	idle := time.Now().Add(normalizeLinkTimeout(c.idleTimeout))
	if t.IsZero() || t.After(idle) {
		return idle
	}
	return t
}

// RawConn returns the innermost connection beneath c; see RawConnProvider.
func (c *TimeoutConn) RawConn() net.Conn {
	if c == nil {
		return nil
	}
	return rawConnOf(c.Conn)
}
