package netx

import (
	"errors"
	"fmt"
	"net"
	"time"
)

// errCloseWriteUnsupported is returned by the CloseWrite methods of the
// wrappers when the wrapped connection cannot shut down only its writing side.
var errCloseWriteUnsupported = fmt.Errorf("netx: connection does not support CloseWrite: %w", errors.ErrUnsupported)

// closeWrite shuts down the writing side of c, as *net.TCPConn, *net.UnixConn
// and *tls.Conn do, or returns an error matching errors.ErrUnsupported.
func closeWrite(c any) error {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return errCloseWriteUnsupported
}

// closedConn is what a wrapper of this package forwards to when it is nil
// or wraps nothing, so that its methods fail as on a closed connection
// instead of panicking: reads, writes, deadlines and CloseWrite return
// net.ErrClosed, Close does nothing and the addresses are nil.
type closedConn struct{}

// noConn is the closedConn that the wrappers forward to.
var noConn net.Conn = closedConn{}

func (closedConn) Read([]byte) (int, error)         { return 0, net.ErrClosed }
func (closedConn) Write([]byte) (int, error)        { return 0, net.ErrClosed }
func (closedConn) Close() error                     { return nil }
func (closedConn) CloseWrite() error                { return net.ErrClosed }
func (closedConn) LocalAddr() net.Addr              { return nil }
func (closedConn) RemoteAddr() net.Addr             { return nil }
func (closedConn) SetDeadline(time.Time) error      { return net.ErrClosed }
func (closedConn) SetReadDeadline(time.Time) error  { return net.ErrClosed }
func (closedConn) SetWriteDeadline(time.Time) error { return net.ErrClosed }

// orClosed returns c, or noConn for a nil c.
func orClosed(c net.Conn) net.Conn {
	if c == nil {
		return noConn
	}
	return c
}
