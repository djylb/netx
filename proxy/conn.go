package proxy

import (
	"context"
	"errors"
	"net"
	"os"
	"time"
)

// handshake runs fn on c with ctx's deadline as the connection deadline and
// interrupts its I/O when ctx is canceled. On success it clears the
// deadline; on failure it closes c and reports ctx's error when ctx ended
// the handshake.
func handshake(ctx context.Context, c net.Conn, fn func() (net.Conn, error)) (net.Conn, error) {
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() {
		_ = c.SetDeadline(time.Unix(1, 0))
	})
	out, err := fn()
	if !stop() && err == nil {
		// ctx ended after fn returned and has already poisoned the deadline.
		err = ctx.Err()
	}
	if err == nil {
		// Connections without deadline support, such as SSH channels, fail
		// here although they have no deadline to clear.
		_ = c.SetDeadline(time.Time{})
	}
	if err != nil {
		_ = c.Close()
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		// The connection deadline equals ctx's, so it can expire just before
		// ctx reports it.
		if _, ok := ctx.Deadline(); ok && errors.Is(err, os.ErrDeadlineExceeded) {
			return nil, context.DeadlineExceeded
		}
		return nil, err
	}
	return out, nil
}
