package netx

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// TlsConn keeps access to both the TLS connection and its raw connection.
type TlsConn struct {
	*tls.Conn
	rawConn net.Conn
}

// NewTlsConn performs a TLS client handshake with a temporary deadline.
func NewTlsConn(rawConn net.Conn, timeout time.Duration, tlsConfig *tls.Config) (*TlsConn, error) {
	return NewTlsConnContext(context.Background(), rawConn, timeout, tlsConfig)
}

// NewTlsConnContext performs a TLS client handshake using ctx and a temporary deadline.
func NewTlsConnContext(ctx context.Context, rawConn net.Conn, timeout time.Duration, tlsConfig *tls.Config) (*TlsConn, error) {
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

	return &TlsConn{
		Conn:    tlsConn,
		rawConn: rawConn,
	}, nil
}

// GetTlsConn wraps c with TLS using sni and optional certificate verification.
func GetTlsConn(c net.Conn, sni string, verifyCertificate bool) (net.Conn, error) {
	if c == nil {
		return nil, net.ErrClosed
	}
	return NewTlsConn(c, 0, &tls.Config{
		InsecureSkipVerify: !verifyCertificate,
		ServerName:         removePortFromHost(sni),
	})
}

func removePortFromHost(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	}
	return host
}

func (c *TlsConn) GetRawConn() net.Conn {
	if c == nil {
		return nil
	}
	return c.rawConn
}

func (c *TlsConn) Close() error {
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

func (c *TlsConn) Read(b []byte) (n int, err error) {
	if c == nil || c.Conn == nil {
		return 0, net.ErrClosed
	}
	return c.Conn.Read(b)
}

func (c *TlsConn) Write(b []byte) (n int, err error) {
	if c == nil || c.Conn == nil {
		return 0, net.ErrClosed
	}
	return c.Conn.Write(b)
}

func (c *TlsConn) SetDeadline(t time.Time) error {
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

func (c *TlsConn) SetReadDeadline(t time.Time) error {
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

func (c *TlsConn) SetWriteDeadline(t time.Time) error {
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

func (c *TlsConn) LocalAddr() net.Addr {
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

func (c *TlsConn) RemoteAddr() net.Addr {
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
