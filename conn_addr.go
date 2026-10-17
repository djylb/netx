package netx

import (
	"io"
	"net"
	"time"
)

// AddrOverrideConn is a net.Conn that reports overridden local and remote
// addresses. A nil override falls back to the wrapped connection's address.
type AddrOverrideConn struct {
	conn  net.Conn
	lAddr net.Addr
	rAddr net.Addr
}

// NewAddrOverrideConn wraps base and overrides its local or remote address,
// in the order of LocalAddr and RemoteAddr; a nil address keeps base's own.
func NewAddrOverrideConn(base net.Conn, local, remote net.Addr) *AddrOverrideConn {
	return &AddrOverrideConn{
		conn:  base,
		lAddr: local,
		rAddr: remote,
	}
}

func (c *AddrOverrideConn) Read(b []byte) (int, error) {
	if c == nil || c.conn == nil {
		return 0, net.ErrClosed
	}
	return c.conn.Read(b)
}

func (c *AddrOverrideConn) Write(b []byte) (int, error) {
	if c == nil || c.conn == nil {
		return 0, net.ErrClosed
	}
	return c.conn.Write(b)
}

func (c *AddrOverrideConn) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

// CloseWrite shuts down the writing side of the wrapped connection; see
// TimeoutConn.CloseWrite.
func (c *AddrOverrideConn) CloseWrite() error {
	if c == nil || c.conn == nil {
		return net.ErrClosed
	}
	return closeWrite(c.conn)
}

func (c *AddrOverrideConn) LocalAddr() net.Addr {
	if c == nil {
		return nil
	}
	if c.lAddr != nil {
		return c.lAddr
	}
	if c.conn == nil {
		return nil
	}
	return c.conn.LocalAddr()
}

func (c *AddrOverrideConn) RemoteAddr() net.Addr {
	if c == nil {
		return nil
	}
	if c.rAddr != nil {
		return c.rAddr
	}
	if c.conn == nil {
		return nil
	}
	return c.conn.RemoteAddr()
}

func (c *AddrOverrideConn) SetDeadline(t time.Time) error {
	if c == nil || c.conn == nil {
		return net.ErrClosed
	}
	return c.conn.SetDeadline(t)
}

func (c *AddrOverrideConn) SetReadDeadline(t time.Time) error {
	if c == nil || c.conn == nil {
		return net.ErrClosed
	}
	return c.conn.SetReadDeadline(t)
}

func (c *AddrOverrideConn) SetWriteDeadline(t time.Time) error {
	if c == nil || c.conn == nil {
		return net.ErrClosed
	}
	return c.conn.SetWriteDeadline(t)
}

// WriteTo copies the wrapped connection to w, through its own WriteTo when it
// has one, so a *net.TCPConn can still splice.
func (c *AddrOverrideConn) WriteTo(w io.Writer) (int64, error) {
	if c == nil || c.conn == nil {
		return 0, net.ErrClosed
	}
	return io.Copy(w, c.conn)
}

func (c *AddrOverrideConn) innerReader() io.Reader {
	if c == nil {
		return nil
	}
	return c.conn
}

// NetConn returns the connection that c wraps, as *tls.Conn's NetConn does;
// see InnermostConn and ConnAs.
func (c *AddrOverrideConn) NetConn() net.Conn {
	if c == nil {
		return nil
	}
	return c.conn
}
