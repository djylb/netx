package netutil

import (
	"context"
	"net"
	"time"
)

// DoWithContext runs fn with ctx bounding I/O on c.
func DoWithContext(ctx context.Context, c net.Conn, fn func() error, owned bool) (err error) {
	if err = ctx.Err(); err != nil {
		return err
	}
	deadline, ok := ctx.Deadline()
	if ctx.Done() != nil {
		initial := deadline
		if !owned && !ok {
			// Some connections accept clearing a deadline but reject a real one.
			initial = time.Now().Add(time.Duration(1<<63 - 1))
		}
		if ok || !owned {
			if err = c.SetDeadline(initial); err != nil && !owned {
				_ = c.SetDeadline(time.Time{})
				return err
			}
		}
	}
	stop := AfterFuncSync(ctx, func() {
		if c.SetDeadline(time.Unix(1, 0)) != nil && owned {
			_ = c.Close()
		}
	})
	defer func() {
		timedOut := ok && !time.Now().Before(deadline) && IsDeadlineTimeout(err)
		interrupted := !stop.Stop()
		_ = c.SetDeadline(time.Time{})
		if interrupted || err != nil && ctx.Err() != nil {
			err = ctx.Err()
		} else if timedOut {
			err = context.DeadlineExceeded
		}
	}()
	return fn()
}

// Interrupt is a context.AfterFunc whose stop waits for the function.
type Interrupt struct {
	stop func() bool
	done chan struct{}
}

// AfterFuncSync arranges for fn to run once ctx is done, as context.AfterFunc
// does, for fn to interrupt blocked I/O; see Interrupt.Stop.
func AfterFuncSync(ctx context.Context, fn func()) Interrupt {
	if ctx.Done() == nil {
		return Interrupt{} // never done
	}
	done := make(chan struct{})
	return Interrupt{
		stop: context.AfterFunc(ctx, func() {
			defer close(done)
			fn()
		}),
		done: done,
	}
}

// Stop keeps fn from running and reports whether it did. When fn has
// started, Stop waits for it to return, so that what fn does, such as
// setting a deadline, cannot undo what the caller does after Stop.
func (a Interrupt) Stop() bool {
	if a.stop == nil || a.stop() {
		return true
	}
	<-a.done
	return false
}
