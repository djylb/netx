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

// NewAddrOverrideConn wraps c and overrides its local or remote address, in
// the order of LocalAddr and RemoteAddr; a nil address keeps c's own.
func NewAddrOverrideConn(c net.Conn, local, remote net.Addr) *AddrOverrideConn {
	return &AddrOverrideConn{
		conn:  c,
		lAddr: local,
		rAddr: remote,
	}
}

// inner returns the wrapped connection, or noConn.
func (c *AddrOverrideConn) inner() net.Conn {
	if c == nil {
		return noConn
	}
	return orClosed(c.conn)
}

func (c *AddrOverrideConn) Read(b []byte) (int, error)         { return c.inner().Read(b) }
func (c *AddrOverrideConn) Write(b []byte) (int, error)        { return c.inner().Write(b) }
func (c *AddrOverrideConn) Close() error                       { return c.inner().Close() }
func (c *AddrOverrideConn) SetDeadline(t time.Time) error      { return c.inner().SetDeadline(t) }
func (c *AddrOverrideConn) SetReadDeadline(t time.Time) error  { return c.inner().SetReadDeadline(t) }
func (c *AddrOverrideConn) SetWriteDeadline(t time.Time) error { return c.inner().SetWriteDeadline(t) }

// CloseWrite shuts down the writing side of the wrapped connection; see
// TimeoutConn.CloseWrite.
func (c *AddrOverrideConn) CloseWrite() error { return closeWrite(c.inner()) }

func (c *AddrOverrideConn) LocalAddr() net.Addr {
	if c != nil && c.lAddr != nil {
		return c.lAddr
	}
	return c.inner().LocalAddr()
}

func (c *AddrOverrideConn) RemoteAddr() net.Addr {
	if c != nil && c.rAddr != nil {
		return c.rAddr
	}
	return c.inner().RemoteAddr()
}

// WriteTo copies the wrapped connection to w, through its own WriteTo when it
// has one, so a *net.TCPConn can still splice.
func (c *AddrOverrideConn) WriteTo(w io.Writer) (int64, error) {
	if c == nil || c.conn == nil {
		return 0, net.ErrClosed
	}
	return io.Copy(w, c.conn)
}

// NetConn returns the connection that c wraps, as *tls.Conn's NetConn does;
// see InnermostConn and ConnAs.
func (c *AddrOverrideConn) NetConn() net.Conn {
	if c == nil {
		return nil
	}
	return c.conn
}

func (c *AddrOverrideConn) netxLayer() layerInfo {
	info := layerInfo{self: c, kind: layerWraps | layerReads | layerPasses}
	if c != nil {
		info.conn = c.conn
	}
	return info
}
