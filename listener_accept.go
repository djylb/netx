package netx

import (
	"context"
	"errors"
	"net"

	"github.com/djylb/netx/internal/dgram"
)

// IsAcceptRetryable reports whether err, returned by a listener's Accept, is
// worth calling Accept again for, as net/http decides: a timeout, or an
// error that reports itself temporary, such as running out of file
// descriptors (EMFILE, ENFILE) or a connection that the client aborted
// before it was accepted (ECONNABORTED). An error of a closed listener is
// not.
func IsAcceptRetryable(err error) bool {
	if err == nil || IsClosed(err) {
		return false
	}
	if ne, ok := errors.AsType[net.Error](err); ok && ne.Timeout() {
		return true
	}
	var te interface{ Temporary() bool }
	return errors.As(err, &te) && te.Temporary()
}

// Accept waits for the next connection of l. It calls l.Accept again after
// the errors for which IsAcceptRetryable reports true: at once after the
// first, as such an error concerns one connection, and then, while they
// persist, after a delay that doubles from 1ms up to 1s, so that a server
// out of file descriptors does not spin. It returns the first other error,
// such as that of a closed listener, or ctx's error when ctx ends while it
// waits to retry. ctx does not end a blocked l.Accept; close l for that.
func Accept(ctx context.Context, l net.Listener) (net.Conn, error) {
	var backoff dgram.Backoff
	for {
		c, err := l.Accept()
		if err == nil {
			return c, nil
		}
		if !IsAcceptRetryable(err) {
			return nil, err
		}
		if !backoff.Wait(ctx.Done()) {
			return nil, ctx.Err()
		}
	}
}
