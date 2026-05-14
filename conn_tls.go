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

// NewTLSConn performs a TLS client handshake with a temporary deadline.
func NewTLSConn(rawConn net.Conn, timeout time.Duration, tlsConfig *tls.Config) (*TLSConn, error) {
	return NewTLSConnContext(context.Background(), rawConn, timeout, tlsConfig)
}

// NewTLSConnContext performs a TLS client handshake using ctx and a temporary deadline.
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

	if err := tlsConn.HandshakeContext(ctx); err != nil {
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

func (c *TLSConn) GetRawConn() net.Conn {
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
	if c == nil || c.Conn == nil || c.rawConn == nil {
		return net.ErrClosed
	}
	if err := c.Conn.SetDeadline(t); err != nil {
		return err
	}
	if err := c.rawConn.SetDeadline(t); err != nil {
		return err
	}
	return nil
}

func (c *TLSConn) SetReadDeadline(t time.Time) error {
	if c == nil || c.Conn == nil || c.rawConn == nil {
		return net.ErrClosed
	}
	if err := c.Conn.SetReadDeadline(t); err != nil {
		return err
	}
	if err := c.rawConn.SetReadDeadline(t); err != nil {
		return err
	}
	return nil
}

func (c *TLSConn) SetWriteDeadline(t time.Time) error {
	if c == nil || c.Conn == nil || c.rawConn == nil {
		return net.ErrClosed
	}
	if err := c.Conn.SetWriteDeadline(t); err != nil {
		return err
	}
	if err := c.rawConn.SetWriteDeadline(t); err != nil {
		return err
	}
	return nil
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
