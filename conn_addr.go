package netx

import (
	"net"
	"time"
)

type AddrOverrideConn struct {
	net.Conn
	lAddr net.Addr
	rAddr net.Addr
}

// NewAddrOverrideConn wraps base and overrides its local or remote address.
func NewAddrOverrideConn(base net.Conn, remote, local net.Addr) *AddrOverrideConn {
	return &AddrOverrideConn{
		Conn:  base,
		lAddr: local,
		rAddr: remote,
	}
}

func (c *AddrOverrideConn) Read(b []byte) (int, error) {
	if c == nil || c.Conn == nil {
		return 0, net.ErrClosed
	}
	return c.Conn.Read(b)
}

func (c *AddrOverrideConn) Write(b []byte) (int, error) {
	if c == nil || c.Conn == nil {
		return 0, net.ErrClosed
	}
	return c.Conn.Write(b)
}

func (c *AddrOverrideConn) Close() error {
	if c == nil || c.Conn == nil {
		return nil
	}
	return c.Conn.Close()
}

func (c *AddrOverrideConn) LocalAddr() net.Addr {
	if c == nil {
		return nil
	}
	if c.lAddr != nil {
		return c.lAddr
	}
	if c.Conn == nil {
		return nil
	}
	return c.Conn.LocalAddr()
}

func (c *AddrOverrideConn) RemoteAddr() net.Addr {
	if c == nil {
		return nil
	}
	if c.rAddr != nil {
		return c.rAddr
	}
	if c.Conn == nil {
		return nil
	}
	return c.Conn.RemoteAddr()
}

func (c *AddrOverrideConn) SetDeadline(t time.Time) error {
	if c == nil || c.Conn == nil {
		return net.ErrClosed
	}
	return c.Conn.SetDeadline(t)
}

func (c *AddrOverrideConn) SetReadDeadline(t time.Time) error {
	if c == nil || c.Conn == nil {
		return net.ErrClosed
	}
	return c.Conn.SetReadDeadline(t)
}

func (c *AddrOverrideConn) SetWriteDeadline(t time.Time) error {
	if c == nil || c.Conn == nil {
		return net.ErrClosed
	}
	return c.Conn.SetWriteDeadline(t)
}

func (c *AddrOverrideConn) RawConn() net.Conn {
	if c == nil {
		return nil
	}
	return rawConnOf(c.Conn)
}
