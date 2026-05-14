package netx

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"time"
)

// TimeoutConn refreshes the deadline before each read or write.
type TimeoutConn struct {
	net.Conn
	idleTimeout time.Duration
	mu          sync.Mutex
	lastSet     time.Time
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
	if c == nil || c.Conn == nil {
		return net.ErrClosed
	}
	deadline := time.Now().Add(c.idleTimeout)
	c.mu.Lock()
	if !c.lastSet.IsZero() && !deadline.After(c.lastSet) {
		deadline = c.lastSet.Add(time.Nanosecond)
	}
	c.lastSet = deadline
	c.mu.Unlock()
	return c.SetDeadline(deadline)
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

func (c *TimeoutConn) RawConn() net.Conn {
	if c == nil {
		return nil
	}
	return rawConnOf(c.Conn)
}

// NewTimeoutTLSConn performs a TLS handshake and returns a timeout-wrapped connection.
func NewTimeoutTLSConn(raw net.Conn, cfg *tls.Config, idle, handshakeTimeout time.Duration) (*TimeoutConn, error) {
	return NewTimeoutTLSConnContext(context.Background(), raw, cfg, idle, handshakeTimeout)
}

// NewTimeoutTLSConnContext performs a TLS handshake using ctx and returns a timeout-wrapped connection.
func NewTimeoutTLSConnContext(ctx context.Context, raw net.Conn, cfg *tls.Config, idle, handshakeTimeout time.Duration) (*TimeoutConn, error) {
	tlsConn, err := NewTLSConnContext(ctx, raw, handshakeTimeout, cfg)
	if err != nil {
		return nil, err
	}
	return NewTimeoutConn(tlsConn, idle), nil
}
