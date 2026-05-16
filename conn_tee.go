package netx

import (
	"bytes"
	"net"
	"sync"
	"time"
)

const defaultMaxBufBytes = 64 * 1024

// TeeConn records bytes read from an underlying net.Conn until buffering is stopped.
type TeeConn struct {
	underlying  net.Conn
	buf         *bytes.Buffer
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
		buf:         new(bytes.Buffer),
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
		if !t.detached {
			buf := t.bufferLocked()
			available := t.bufferLimit() - buf.Len()
			if available > 0 {
				if n > available {
					buf.Write(p[:available])
				} else {
					buf.Write(p[:n])
				}
			}
		}
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

func (t *TeeConn) RawConn() net.Conn {
	if t == nil {
		return nil
	}
	return rawConnOf(t.conn())
}

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

func (t *TeeConn) Buffered() []byte {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.buf == nil {
		return nil
	}
	return append([]byte(nil), t.buf.Bytes()...)
}

func (t *TeeConn) ResetBuffer() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.buf != nil {
		t.buf.Reset()
	}
}

func (t *TeeConn) ExtractAndReset() []byte {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.buf == nil {
		return nil
	}
	data := append([]byte(nil), t.buf.Bytes()...)
	t.buf.Reset()
	return data
}

func (t *TeeConn) Release() (net.Conn, []byte) {
	if t == nil {
		return nil, nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	conn := t.underlying
	t.underlying = nil
	t.detached = true
	var data []byte
	if t.buf != nil {
		data = append([]byte(nil), t.buf.Bytes()...)
	}
	t.buf = nil
	return conn, data
}

func (t *TeeConn) DiscardBuffer() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.detached = true
	t.buf = new(bytes.Buffer)
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

func (t *TeeConn) bufferLocked() *bytes.Buffer {
	if t.buf == nil {
		t.buf = new(bytes.Buffer)
	}
	return t.buf
}
