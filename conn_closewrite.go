package netx

import (
	"errors"
	"fmt"
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
