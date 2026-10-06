package netx

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// TLSConn keeps access to both the TLS connection and its raw connection.
type TLSConn struct {
	*tls.Conn
	rawConn net.Conn
}

// NewTLSConn performs a TLS client handshake bounded by timeout.
// A non-positive timeout uses DefaultTimeout. On failure rawConn is closed and
// the returned *TLSConn is nil; callers that return it as a net.Conn should
// return an untyped nil on error.
func NewTLSConn(rawConn net.Conn, timeout time.Duration, tlsConfig *tls.Config) (*TLSConn, error) {
	return NewTLSConnContext(context.Background(), rawConn, timeout, tlsConfig)
}

// NewTLSConnContext performs a TLS client handshake that stops when ctx is done
// or timeout elapses. The timeout is applied both as a deadline on rawConn and
// as a context deadline, so it also holds when rawConn ignores deadlines.
// A non-positive timeout uses DefaultTimeout. On failure rawConn is closed and
// the returned *TLSConn is nil.
func NewTLSConnContext(ctx context.Context, rawConn net.Conn, timeout time.Duration, tlsConfig *tls.Config) (*TLSConn, error) {
	if rawConn == nil {
		return nil, net.ErrClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	timeout = normalizeLinkTimeout(timeout)

	err := rawConn.SetDeadline(time.Now().Add(timeout))
	if err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("failed to set deadline for rawConn: %w", err)
	}

	tlsConn := tls.Client(rawConn, tlsConfig)

	hsCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := tlsConn.HandshakeContext(hsCtx); err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}
	if err := tlsConn.SetDeadline(time.Time{}); err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("failed to clear TLS deadline after handshake: %w", err)
	}

	return &TLSConn{
		Conn:    tlsConn,
		rawConn: rawConn,
	}, nil
}

// RawConn returns the connection the TLS handshake ran over; see
// RawConnProvider.
func (c *TLSConn) RawConn() net.Conn {
	if c == nil {
		return nil
	}
	return c.rawConn
}

func (c *TLSConn) Close() error {
	if c == nil {
		return nil
	}
	if c.Conn != nil {
		if err := c.Conn.Close(); err != nil {
			return fmt.Errorf("failed to close tlsConn: %w", err)
		}
		return nil
	}
	if c.rawConn != nil {
		if err := c.rawConn.Close(); err != nil {
			return fmt.Errorf("failed to close rawConn: %w", err)
		}
	}
	return nil
}

func (c *TLSConn) Read(b []byte) (n int, err error) {
	if c == nil || c.Conn == nil {
		return 0, net.ErrClosed
	}
	return c.Conn.Read(b)
}

func (c *TLSConn) Write(b []byte) (n int, err error) {
	if c == nil || c.Conn == nil {
		return 0, net.ErrClosed
	}
	return c.Conn.Write(b)
}

func (c *TLSConn) SetDeadline(t time.Time) error {
	if c == nil || c.Conn == nil {
		return net.ErrClosed
	}
	return c.Conn.SetDeadline(t)
}

func (c *TLSConn) SetReadDeadline(t time.Time) error {
	if c == nil || c.Conn == nil {
		return net.ErrClosed
	}
	return c.Conn.SetReadDeadline(t)
}

func (c *TLSConn) SetWriteDeadline(t time.Time) error {
	if c == nil || c.Conn == nil {
		return net.ErrClosed
	}
	return c.Conn.SetWriteDeadline(t)
}

func (c *TLSConn) LocalAddr() net.Addr {
	if c == nil {
		return nil
	}
	if c.rawConn == nil {
		if c.Conn == nil {
			return nil
		}
		return c.Conn.LocalAddr()
	}
	return c.rawConn.LocalAddr()
}

func (c *TLSConn) RemoteAddr() net.Addr {
	if c == nil {
		return nil
	}
	if c.Conn != nil {
		return c.Conn.RemoteAddr()
	}
	if c.rawConn == nil {
		return nil
	}
	return c.rawConn.RemoteAddr()
}
