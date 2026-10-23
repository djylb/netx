package netx

import (
	"context"
	"io"
	"net"
)

// writeOnce writes p to w with one Write, which io.Writer requires to write
// all of p unless it fails, and reports a short write as io.ErrShortWrite,
// as it does a count out of range.
func writeOnce(w io.Writer, p []byte) (n int, err error) {
	if n, err = w.Write(p); n != len(p) && err == nil {
		err = io.ErrShortWrite
	}
	return
}

// writeBuffers writes every buffer of bufs to w, consuming bufs.
func writeBuffers(w io.Writer, bufs *net.Buffers) (int64, error) {
	var want int64
	for _, b := range *bufs {
		want += int64(len(b))
	}
	n, err := bufs.WriteTo(w)
	if err == nil && n != want {
		err = io.ErrShortWrite
	}
	return n, err
}

// syncAfterFunc is a context.AfterFunc whose stop waits for the function.
type syncAfterFunc struct {
	stop func() bool
	done chan struct{}
}

// afterFuncSync arranges for fn to run once ctx is done, as context.AfterFunc
// does, for fn to interrupt blocked I/O; see syncAfterFunc.Stop.
func afterFuncSync(ctx context.Context, fn func()) syncAfterFunc {
	if ctx.Done() == nil {
		return syncAfterFunc{} // never done
	}
	done := make(chan struct{})
	return syncAfterFunc{
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
func (a syncAfterFunc) Stop() bool {
	if a.stop == nil || a.stop() {
		return true
	}
	<-a.done
	return false
}
