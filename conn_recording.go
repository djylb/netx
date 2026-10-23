package netx

import (
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

// NewRecordingConn wraps c and records up to limit read bytes,
// DefaultRecordingLimit if limit is not positive.
func NewRecordingConn(c net.Conn, limit int) *RecordingConn {
	size := DefaultRecordingLimit
	if limit > 0 {
		size = limit
	}
	return &RecordingConn{
		underlying:  c,
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

// inner returns the connection that c records, or noConn after Close or
// Release.
func (c *RecordingConn) inner() net.Conn { return orClosed(c.conn()) }

func (c *RecordingConn) Write(p []byte) (int, error)        { return c.inner().Write(p) }
func (c *RecordingConn) LocalAddr() net.Addr                { return c.inner().LocalAddr() }
func (c *RecordingConn) RemoteAddr() net.Addr               { return c.inner().RemoteAddr() }
func (c *RecordingConn) SetDeadline(t time.Time) error      { return c.inner().SetDeadline(t) }
func (c *RecordingConn) SetReadDeadline(t time.Time) error  { return c.inner().SetReadDeadline(t) }
func (c *RecordingConn) SetWriteDeadline(t time.Time) error { return c.inner().SetWriteDeadline(t) }

// CloseWrite shuts down the writing side of the underlying connection; see
// TimeoutConn.CloseWrite.
func (c *RecordingConn) CloseWrite() error { return closeWrite(c.inner()) }

// NetConn returns the connection that c wraps, or nil after Close or
// Release, as *tls.Conn's NetConn does; see InnermostConn and ConnAs.
func (c *RecordingConn) NetConn() net.Conn { return c.conn() }

func (c *RecordingConn) netxLayer() layerInfo {
	return layerInfo{self: c, conn: c.conn(), kind: layerWraps | layerReads}
}

// Stop stops recording reads and keeps what was recorded, for Buffered and
// Release.
func (c *RecordingConn) Stop() { c.stop(false) }

// Discard stops recording reads and frees what was recorded, such as once a
// sniffed protocol turned out not to need replaying.
func (c *RecordingConn) Discard() { c.stop(true) }

func (c *RecordingConn) stop(discard bool) {
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
