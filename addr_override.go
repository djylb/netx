package netx

import (
	"fmt"
	"net"
	"time"
)

type AddrOverrideConn struct {
	net.Conn
	lAddr net.Addr
	rAddr net.Addr
}

func NewAddrOverrideConn(base net.Conn, remote, local string) (*AddrOverrideConn, error) {
	if base == nil {
		return nil, fmt.Errorf("base conn is nil")
	}
	rAddr, err := parseTCPAddrMaybe(remote)
	if err != nil {
		return nil, fmt.Errorf("invalid remote addr %q: %w", remote, err)
	}
	lAddr, _ := parseTCPAddrMaybe(local)
	return &AddrOverrideConn{
		Conn:  base,
		lAddr: lAddr,
		rAddr: rAddr,
	}, nil
}

func NewAddrOverrideFromAddr(base net.Conn, remote, local net.Addr) *AddrOverrideConn {
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

func (c *AddrOverrideConn) GetRawConn() net.Conn {
	if c == nil {
		return nil
	}
	return c.Conn
}

func parseTCPAddrMaybe(s string) (*net.TCPAddr, error) {
	if s == "" {
		return nil, nil
	}
	a, err := net.ResolveTCPAddr("tcp", s)
	if err != nil {
		return nil, err
	}
	return a, nil
}
