package netx

import (
	"io"
	"net"
	"sync"
	"time"
)

// DefaultRecordingLimit is how many read bytes a RecordingConn records when
// NewRecordingConn is given no positive limit.
const DefaultRecordingLimit = 64 * 1024

// RecordingConn records the bytes read from a connection, up to a limit, so
// that they can be replayed later, such as when a protocol was sniffed by
// reading it: Release returns the connection and the bytes, for a
// PrefixConn. For a single look at the first bytes, Peek is simpler.
type RecordingConn struct {
	underlying  net.Conn
	buf         []byte
	mu          sync.Mutex
	detached    bool
	truncated   bool
	maxBufBytes int
}

// NewRecordingConn wraps conn and records up to maxBufBytes read bytes,
// DefaultRecordingLimit if maxBufBytes is not positive.
func NewRecordingConn(conn net.Conn, maxBufBytes int) *RecordingConn {
	size := DefaultRecordingLimit
	if maxBufBytes > 0 {
		size = maxBufBytes
	}
	return &RecordingConn{
		underlying:  conn,
		maxBufBytes: size,
	}
}

func (c *RecordingConn) Read(p []byte) (n int, err error) {
	conn := c.conn()
	if conn == nil {
		return 0, net.ErrClosed
	}
	n, err = conn.Read(p)
	if n > 0 {
		c.mu.Lock()
		c.captureLocked(p[:n])
		c.mu.Unlock()
	}
	return n, err
}

func (c *RecordingConn) Write(p []byte) (n int, err error) {
	conn := c.conn()
	if conn == nil {
		return 0, net.ErrClosed
	}
	return conn.Write(p)
}

func (c *RecordingConn) LocalAddr() net.Addr {
	conn := c.conn()
	if conn == nil {
		return nil
	}
	return conn.LocalAddr()
}

func (c *RecordingConn) RemoteAddr() net.Addr {
	conn := c.conn()
	if conn == nil {
		return nil
	}
	return conn.RemoteAddr()
}

func (c *RecordingConn) SetDeadline(deadline time.Time) error {
	conn := c.conn()
	if conn == nil {
		return net.ErrClosed
	}
	return conn.SetDeadline(deadline)
}

func (c *RecordingConn) SetReadDeadline(deadline time.Time) error {
	conn := c.conn()
	if conn == nil {
		return net.ErrClosed
	}
	return conn.SetReadDeadline(deadline)
}

func (c *RecordingConn) SetWriteDeadline(deadline time.Time) error {
	conn := c.conn()
	if conn == nil {
		return net.ErrClosed
	}
	return conn.SetWriteDeadline(deadline)
}

func (c *RecordingConn) innerReader() io.Reader {
	if conn := c.conn(); conn != nil {
		return conn
	}
	return nil
}

// NetConn returns the connection that c wraps, or nil after Close or
// Release, as *tls.Conn's NetConn does; see InnermostConn and ConnAs.
func (c *RecordingConn) NetConn() net.Conn {
	if c == nil {
		return nil
	}
	return c.conn()
}

// Stop stops recording reads, and with discard frees what was recorded.
func (c *RecordingConn) Stop(discard bool) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.detached = true
	if discard {
		c.buf = nil
	}
	c.mu.Unlock()
}

func (c *RecordingConn) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	conn := c.underlying
	c.underlying = nil
	c.detached = true
	c.buf = nil
	c.mu.Unlock()
	if conn == nil {
		return nil
	}
	return conn.Close()
}

// CloseWrite shuts down the writing side of the underlying connection; see
// TimeoutConn.CloseWrite.
func (c *RecordingConn) CloseWrite() error {
	conn := c.conn()
	if conn == nil {
		return net.ErrClosed
	}
	return closeWrite(conn)
}

// Buffered returns a copy of the bytes recorded so far.
func (c *RecordingConn) Buffered() []byte {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buf...)
}

// Truncated reports whether reads went past the limit, so that the recorded
// bytes are not all that was read.
func (c *RecordingConn) Truncated() bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.truncated
}

// Release detaches the underlying connection and returns it with a copy of
// the buffered bytes. The caller then owns the connection: the RecordingConn reports
// net.ErrClosed from Read, Write and the deadline methods, and its Close does
// not close the returned connection.
func (c *RecordingConn) Release() (net.Conn, []byte) {
	if c == nil {
		return nil, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	conn := c.underlying
	c.underlying = nil
	c.detached = true
	data := append([]byte(nil), c.buf...)
	c.buf = nil
	return conn, data
}

func (c *RecordingConn) conn() net.Conn {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.underlying
}

func (c *RecordingConn) bufferLimit() int {
	if c == nil || c.maxBufBytes <= 0 {
		return DefaultRecordingLimit
	}
	return c.maxBufBytes
}

func (c *RecordingConn) captureLocked(p []byte) {
	if c.detached || len(p) == 0 {
		return
	}
	available := c.bufferLimit() - len(c.buf)
	if len(p) > available {
		c.truncated = true
		p = p[:max(available, 0)]
	}
	c.buf = append(c.buf, p...)
}
