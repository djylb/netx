package netx

import (
	"context"
	"errors"
	"net"
	"os"
	"time"
)

// DoWithContext runs fn, which does I/O on c, such as a protocol handshake,
// bounded by ctx: ctx's deadline becomes c's deadline, and once ctx is done
// c's deadline is set in the past to interrupt the I/O, or c is closed when
// it has no deadlines. When fn succeeds the deadline is cleared again. It
// returns ctx's error when ctx ended fn, also context.DeadlineExceeded when
// c's deadline, which is ctx's, expired just before ctx reported it, and
// otherwise fn's error; c is left open, for the caller to close on failure.
func DoWithContext(ctx context.Context, c net.Conn, fn func() error) error {
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(deadline)
	}
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(interrupted)
		if c.SetDeadline(time.Unix(1, 0)) != nil {
			_ = c.Close()
		}
	})
	err := fn()
	if !stop() {
		// ctx ended: wait until the deadline is poisoned, so that it cannot
		// undo a deadline the caller sets after DoWithContext returns.
		<-interrupted
		if err == nil {
			err = ctx.Err()
		}
	}
	if err == nil {
		// Connections without deadline support, such as SSH channels, fail
		// here although they have no deadline to clear.
		_ = c.SetDeadline(time.Time{})
		return nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if _, ok := ctx.Deadline(); ok && errors.Is(err, os.ErrDeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return err
}
