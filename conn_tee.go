package netx

import (
	"net"
	"sync"
	"time"
)

const defaultMaxBufBytes = 64 * 1024

// TeeConn records bytes read from an underlying net.Conn until buffering is stopped.
type TeeConn struct {
	underlying  net.Conn
	buf         []byte
	mu          sync.Mutex
	detached    bool
	maxBufBytes int
}

// NewTeeConn wraps conn and stores up to maxBufBytes read bytes.
func NewTeeConn(conn net.Conn, maxBufBytes ...int) *TeeConn {
	size := defaultMaxBufBytes
	if len(maxBufBytes) > 0 && maxBufBytes[0] > 0 {
		size = maxBufBytes[0]
	}
	return &TeeConn{
		underlying:  conn,
		maxBufBytes: size,
	}
}

func (t *TeeConn) Read(p []byte) (n int, err error) {
	conn := t.conn()
	if conn == nil {
		return 0, net.ErrClosed
	}
	n, err = conn.Read(p)
	if n > 0 {
		t.mu.Lock()
		t.captureLocked(p[:n])
		t.mu.Unlock()
	}
	return n, err
}

func (t *TeeConn) Write(p []byte) (n int, err error) {
	conn := t.conn()
	if conn == nil {
		return 0, net.ErrClosed
	}
	return conn.Write(p)
}

func (t *TeeConn) LocalAddr() net.Addr {
	conn := t.conn()
	if conn == nil {
		return nil
	}
	return conn.LocalAddr()
}

func (t *TeeConn) RemoteAddr() net.Addr {
	conn := t.conn()
	if conn == nil {
		return nil
	}
	return conn.RemoteAddr()
}

func (t *TeeConn) SetDeadline(deadline time.Time) error {
	conn := t.conn()
	if conn == nil {
		return net.ErrClosed
	}
	return conn.SetDeadline(deadline)
}

func (t *TeeConn) SetReadDeadline(deadline time.Time) error {
	conn := t.conn()
	if conn == nil {
		return net.ErrClosed
	}
	return conn.SetReadDeadline(deadline)
}

func (t *TeeConn) SetWriteDeadline(deadline time.Time) error {
	conn := t.conn()
	if conn == nil {
		return net.ErrClosed
	}
	return conn.SetWriteDeadline(deadline)
}

// RawConn returns the innermost connection beneath t, or nil after Close or
// Release; see RawConnProvider.
func (t *TeeConn) RawConn() net.Conn {
	if t == nil {
		return nil
	}
	return rawConnOf(t.conn())
}

// StopBuffering stops recording reads. Bytes already buffered are kept.
func (t *TeeConn) StopBuffering() {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.detached = true
	t.mu.Unlock()
}

func (t *TeeConn) Close() error {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	conn := t.underlying
	t.underlying = nil
	t.detached = true
	t.buf = nil
	t.mu.Unlock()
	if conn == nil {
		return nil
	}
	return conn.Close()
}

// Buffered returns a copy of the bytes recorded so far.
func (t *TeeConn) Buffered() []byte {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]byte(nil), t.buf...)
}

// ResetBuffer empties the buffer. It does not change whether reads are
// recorded, so it does not undo StopBuffering.
func (t *TeeConn) ResetBuffer() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = t.buf[:0]
}

// ExtractAndReset returns a copy of the buffered bytes and empties the buffer,
// as Buffered followed by ResetBuffer.
func (t *TeeConn) ExtractAndReset() []byte {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	data := append([]byte(nil), t.buf...)
	t.buf = t.buf[:0]
	return data
}

// Release detaches the underlying connection and returns it with a copy of
// the buffered bytes. The caller then owns the connection: the TeeConn reports
// net.ErrClosed from Read, Write and the deadline methods, and its Close does
// not close the returned connection.
func (t *TeeConn) Release() (net.Conn, []byte) {
	if t == nil {
		return nil, nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	conn := t.underlying
	t.underlying = nil
	t.detached = true
	data := append([]byte(nil), t.buf...)
	t.buf = nil
	return conn, data
}

// DiscardBuffer stops recording reads and frees the buffer.
func (t *TeeConn) DiscardBuffer() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.detached = true
	t.buf = nil
}

func (t *TeeConn) conn() net.Conn {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.underlying
}

func (t *TeeConn) bufferLimit() int {
	if t == nil || t.maxBufBytes <= 0 {
		return defaultMaxBufBytes
	}
	return t.maxBufBytes
}

func (t *TeeConn) captureLocked(p []byte) {
	if t.detached || len(p) == 0 {
		return
	}
	available := t.bufferLimit() - len(t.buf)
	if available <= 0 {
		return
	}
	if len(p) > available {
		p = p[:available]
	}
	t.buf = append(t.buf, p...)
}
