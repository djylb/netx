package netx

import (
	"crypto/tls"
	"net"
	"sync"
	"time"
)

type TimeoutConn struct {
	net.Conn
	idleTimeout time.Duration
	mu          sync.Mutex
	lastSet     time.Time
}

func NewTimeoutConn(c net.Conn, idle time.Duration) net.Conn {
	return &TimeoutConn{Conn: c, idleTimeout: normalizeLinkTimeout(idle)}
}

func (c *TimeoutConn) Read(b []byte) (int, error) {
	if c == nil || c.Conn == nil {
		return 0, net.ErrClosed
	}
	c.refreshDeadline()
	return c.Conn.Read(b)
}

func (c *TimeoutConn) Write(b []byte) (int, error) {
	if c == nil || c.Conn == nil {
		return 0, net.ErrClosed
	}
	c.refreshDeadline()
	return c.Conn.Write(b)
}

func (c *TimeoutConn) refreshDeadline() {
	if c == nil || c.Conn == nil {
		return
	}
	deadline := time.Now().Add(c.idleTimeout)
	c.mu.Lock()
	if !c.lastSet.IsZero() && !deadline.After(c.lastSet) {
		deadline = c.lastSet.Add(time.Nanosecond)
	}
	c.lastSet = deadline
	c.mu.Unlock()
	_ = c.SetDeadline(deadline)
}

func (c *TimeoutConn) Close() error {
	if c == nil || c.Conn == nil {
		return nil
	}
	return c.Conn.Close()
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
	return c.Conn.SetDeadline(t)
}

func (c *TimeoutConn) SetReadDeadline(t time.Time) error {
	if c == nil || c.Conn == nil {
		return net.ErrClosed
	}
	return c.Conn.SetReadDeadline(t)
}

func (c *TimeoutConn) SetWriteDeadline(t time.Time) error {
	if c == nil || c.Conn == nil {
		return net.ErrClosed
	}
	return c.Conn.SetWriteDeadline(t)
}

func NewTimeoutTLSConn(raw net.Conn, cfg *tls.Config, idle, handshakeTimeout time.Duration) (net.Conn, error) {
	if raw == nil {
		return nil, net.ErrClosed
	}
	idle = normalizeLinkTimeout(idle)
	handshakeTimeout = normalizeLinkTimeout(handshakeTimeout)
	if err := raw.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		_ = raw.Close()
		return nil, err
	}
	tlsConn := tls.Client(raw, cfg)
	if err := tlsConn.Handshake(); err != nil {
		_ = raw.Close()
		return nil, err
	}
	_ = tlsConn.SetDeadline(time.Time{})
	return NewTimeoutConn(tlsConn, idle), nil
}
