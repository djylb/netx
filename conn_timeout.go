package netx

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/netx/internal/dgram"
)

// TimeoutConn closes an idle connection: before each read or write it moves
// the deadline of both directions to now plus the idle timeout. Construct it
// with NewTimeoutConn; SetIdleTimeout changes the timeout later, such as from
// a short one for a handshake to a longer one once it is done. A
// non-positive idle timeout sets none.
//
// To keep the per-call cost to an atomic load, a read or write moves the
// deadline only once less than the idle timeout is left, and then to now plus
// the idle timeout and a small slack (idle/16, at most one second). A
// connection therefore never times out before it has been idle for the idle
// timeout, and at most that slack later.
//
// SetDeadline, SetReadDeadline and SetWriteDeadline are remembered until they
// are changed again. Setting them and every read and write keep each
// direction's deadline at the earlier of the remembered one and now plus the
// idle timeout, so a deadline set to interrupt a blocked Read or Write stays in
// effect while the other direction is in use, and a later or zero one does not
// lift the idle timeout of a Read or Write that is already blocked. A zero time
// leaves only the idle timeout.
type TimeoutConn struct {
	conn        net.Conn
	idleTimeout atomic.Int64 // nanoseconds; none if not positive
	deadline    atomic.Int64 // idle deadline last set on Conn as a clock offset, 0 to force an update
	mu          sync.Mutex   // serializes deadline updates
	userRead    time.Time    // set by SetDeadline or SetReadDeadline, guarded by mu
	userWrite   time.Time    // set by SetDeadline or SetWriteDeadline, guarded by mu
}

// NewTimeoutConn wraps c and refreshes its deadline before each read or
// write, so that it times out after idle without either; a non-positive idle
// sets no idle timeout.
func NewTimeoutConn(c net.Conn, idle time.Duration) *TimeoutConn {
	tc := &TimeoutConn{conn: c}
	tc.idleTimeout.Store(int64(idle))
	return tc
}

// SetIdleTimeout changes the idle timeout, also of a Read or Write already
// blocked; a non-positive d removes it, leaving the deadlines that were set.
func (c *TimeoutConn) SetIdleTimeout(d time.Duration) error {
	if c == nil || c.conn == nil {
		return net.ErrClosed
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.idleTimeout.Store(int64(d))
	c.deadline.Store(0) // the next read or write sets the idle deadline again
	rd, wd := c.capDeadline(c.userRead), c.capDeadline(c.userWrite)
	if rd.Equal(wd) {
		return c.conn.SetDeadline(rd)
	}
	if err := c.conn.SetReadDeadline(rd); err != nil {
		return err
	}
	return c.conn.SetWriteDeadline(wd)
}

// IdleTimeout returns the idle timeout; see SetIdleTimeout.
func (c *TimeoutConn) IdleTimeout() time.Duration {
	if c == nil {
		return 0
	}
	return time.Duration(c.idleTimeout.Load())
}

func (c *TimeoutConn) Read(b []byte) (int, error) {
	if c == nil || c.conn == nil {
		return 0, net.ErrClosed
	}
	if err := c.refreshDeadline(); err != nil {
		return 0, err
	}
	return c.conn.Read(b)
}

func (c *TimeoutConn) Write(b []byte) (int, error) {
	if c == nil || c.conn == nil {
		return 0, net.ErrClosed
	}
	if err := c.refreshDeadline(); err != nil {
		return 0, err
	}
	return c.conn.Write(b)
}

func (c *TimeoutConn) refreshDeadline() error {
	idle := time.Duration(c.idleTimeout.Load())
	if idle <= 0 {
		return nil
	}
	if dgram.Mono(time.Now())+int64(idle) <= c.deadline.Load() {
		return nil // at least idle left
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// Recompute under the lock so a slower caller never moves the deadline
	// back, with the idle timeout that SetIdleTimeout may have changed.
	if idle = time.Duration(c.idleTimeout.Load()); idle <= 0 {
		return nil
	}
	now := time.Now()
	if dgram.Mono(now)+int64(idle) <= c.deadline.Load() {
		return nil
	}
	ahead := idle + min(idle/16, time.Second)
	want := dgram.Mono(now) + int64(ahead)
	// now.Add keeps the monotonic reading, so the socket deadline does not
	// follow wall-clock steps either.
	rd := now.Add(ahead)
	wd := rd
	if !c.userRead.IsZero() && c.userRead.Before(rd) {
		rd = c.userRead
	}
	if !c.userWrite.IsZero() && c.userWrite.Before(wd) {
		wd = c.userWrite
	}
	var err error
	if rd.Equal(wd) {
		err = c.conn.SetDeadline(rd)
	} else if err = c.conn.SetReadDeadline(rd); err == nil {
		err = c.conn.SetWriteDeadline(wd)
	}
	if err != nil {
		return err
	}
	c.deadline.Store(want)
	return nil
}

// inner returns the wrapped connection, or noConn.
func (c *TimeoutConn) inner() net.Conn {
	if c == nil {
		return noConn
	}
	return orClosed(c.conn)
}

func (c *TimeoutConn) Close() error         { return c.inner().Close() }
func (c *TimeoutConn) LocalAddr() net.Addr  { return c.inner().LocalAddr() }
func (c *TimeoutConn) RemoteAddr() net.Addr { return c.inner().RemoteAddr() }

// CloseWrite shuts down the writing side of the wrapped connection, so the
// peer reads EOF while reads continue. It returns an error matching
// errors.ErrUnsupported when the wrapped connection cannot do that.
func (c *TimeoutConn) CloseWrite() error { return closeWrite(c.inner()) }

func (c *TimeoutConn) SetDeadline(t time.Time) error {
	if c == nil || c.conn == nil {
		return net.ErrClosed
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.userRead, c.userWrite = t, t
	c.deadline.Store(0) // the next read or write sets the idle deadline again
	return c.conn.SetDeadline(c.capDeadline(t))
}

func (c *TimeoutConn) SetReadDeadline(t time.Time) error {
	if c == nil || c.conn == nil {
		return net.ErrClosed
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.userRead = t
	c.deadline.Store(0) // the next read or write sets the idle deadline again
	return c.conn.SetReadDeadline(c.capDeadline(t))
}

func (c *TimeoutConn) SetWriteDeadline(t time.Time) error {
	if c == nil || c.conn == nil {
		return net.ErrClosed
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.userWrite = t
	c.deadline.Store(0) // the next read or write sets the idle deadline again
	return c.conn.SetWriteDeadline(c.capDeadline(t))
}

// capDeadline returns the deadline to set on the wrapped connection for a user
// deadline t: t when it comes before the idle deadline of an operation
// starting now, and that idle deadline otherwise, so that a Read or Write
// already blocked keeps its idle timeout; t without an idle timeout.
func (c *TimeoutConn) capDeadline(t time.Time) time.Time {
	d := time.Duration(c.idleTimeout.Load())
	if d <= 0 {
		return t
	}
	idle := time.Now().Add(d)
	if t.IsZero() || t.After(idle) {
		return idle
	}
	return t
}

// NetConn returns the connection that c wraps, as *tls.Conn's NetConn does;
// see InnermostConn and ConnAs. Its reads and writes do not refresh the idle
// timeout.
func (c *TimeoutConn) NetConn() net.Conn {
	if c == nil {
		return nil
	}
	return c.conn
}

func (c *TimeoutConn) netxLayer() layerInfo {
	info := layerInfo{self: c, kind: layerWraps | layerReads | layerRefresh}
	if c != nil {
		info.conn = c.conn
	}
	return info
}
