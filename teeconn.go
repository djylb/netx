package netx

import (
	"bytes"
	"net"
	"sync"
	"time"
)

const defaultMaxBufBytes = 64 * 1024

type TeeConn struct {
	underlying  net.Conn
	buf         *bytes.Buffer
	mu          sync.Mutex
	detached    bool
	maxBufBytes int
}

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
	if t == nil || t.underlying == nil {
		return 0, net.ErrClosed
	}
	n, err = t.underlying.Read(p)
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
	if t == nil || t.underlying == nil {
		return 0, net.ErrClosed
	}
	return t.underlying.Write(p)
}

func (t *TeeConn) LocalAddr() net.Addr {
	if t == nil || t.underlying == nil {
		return nil
	}
	return t.underlying.LocalAddr()
}

func (t *TeeConn) RemoteAddr() net.Addr {
	if t == nil || t.underlying == nil {
		return nil
	}
	return t.underlying.RemoteAddr()
}

func (t *TeeConn) SetDeadline(deadline time.Time) error {
	if t == nil || t.underlying == nil {
		return net.ErrClosed
	}
	return t.underlying.SetDeadline(deadline)
}

func (t *TeeConn) SetReadDeadline(deadline time.Time) error {
	if t == nil || t.underlying == nil {
		return net.ErrClosed
	}
	return t.underlying.SetReadDeadline(deadline)
}

func (t *TeeConn) SetWriteDeadline(deadline time.Time) error {
	if t == nil || t.underlying == nil {
		return net.ErrClosed
	}
	return t.underlying.SetWriteDeadline(deadline)
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
	if t == nil || t.underlying == nil {
		return nil
	}
	t.StopBuffering()
	return t.underlying.Close()
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
	t.detached = true
	var data []byte
	if t.buf != nil {
		data = append([]byte(nil), t.buf.Bytes()...)
	}
	t.buf = new(bytes.Buffer)
	return t.underlying, data
}

func (t *TeeConn) StopAndClean() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.detached = true
	t.buf = new(bytes.Buffer)
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
