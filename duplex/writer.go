package duplex

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/djylb/netx/internal/netutil"
)

// Writer is a write half whose stream can be swapped while it is in use,
// such as an uplink that moves to a new connection or request. Swap
// installs the stream that writes go to; until the first, writes wait. The
// zero value is ready to use. A Writer owns its streams: Swap closes the
// stream it replaces and Close the current one.
//
// The receiver learns of a swap only from the old stream ending, so each
// stream must end cleanly when closed, as a request body or a pipe does,
// and the bytes written to the next one wait in its transport until the
// receiver reads it; a sender that must know the old stream was read takes
// that from its transport, such as the response to the old request.
//
// Write may be called concurrently with itself, Swap, SetWriteDeadline and
// Close, and does not allocate. A Writer copies through Write, without a
// ReadFrom of its own, so that a copy into it never holds up a Swap.
type Writer struct {
	deadline time.Time // under mu
	w        io.Writer // under mu
	changed  waiter    // under mu
	gen      uint64    // counts the changes of deadline and stream, see Reader.gen; under mu
	mu       sync.Mutex
	writing  bool // a Write owns the stream; under mu
	set      bool // w was installed, perhaps nil; under mu
	swapping bool // a swap waits for the writes to end; new ones wait; under mu
	closed   bool // under mu
}

// Write writes p to the current stream, waiting first while there is none
// or while a swap is waiting for the writes in progress to end; the write
// deadline and Close end that wait. A nil stream fails writes with an error
// matching errors.ErrUnsupported.
func (w *Writer) Write(p []byte) (int, error) {
	if w == nil {
		return 0, net.ErrClosed
	}
	w.mu.Lock()
	for !w.closed && (w.swapping || !w.set || w.writing) {
		if err := w.changed.wait(&w.mu, w.deadline, nil); err != nil {
			w.mu.Unlock()
			return 0, err
		}
	}
	if w.closed {
		w.mu.Unlock()
		return 0, net.ErrClosed
	}
	h := w.w
	if h == nil {
		w.mu.Unlock()
		return 0, errNoWriter
	}
	w.writing = true
	w.mu.Unlock()
	defer func() {
		w.mu.Lock()
		w.writing = false
		w.changed.broadcast()
		w.mu.Unlock()
	}()
	return h.Write(p)
}

// Swap waits for active writes, sets the inherited write deadline on next,
// installs it, and closes the previous stream unless it is next. New writes
// wait for the installation. Each Write goes wholly to one stream.
//
// A nil error or a direct *ReplacedStreamError transfers ownership of next.
// The latter reports an error closing the previous stream. Test the returned
// error with a type assertion. All other errors leave next with the caller.
// Cancellation before installation returns an error matching context.Cause(ctx).
// Swaps run one at a time, in no set order: a sender whose receiver must
// get the streams in the order of the swaps opens each stream and swaps to
// it under one lock, or from one goroutine.
func (w *Writer) Swap(ctx context.Context, next io.Writer) error {
	if w == nil {
		return net.ErrClosed
	}
	old, err := w.install(ctx, next)
	if err != nil {
		return fmt.Errorf("duplex: installing stream: %w", err)
	}
	if cl, ok := old.(io.Closer); ok && !netutil.Same(old, next) {
		if err := cl.Close(); err != nil {
			return &ReplacedStreamError{Err: err}
		}
	}
	return nil
}

func (w *Writer) install(ctx context.Context, next io.Writer) (io.Writer, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for w.swapping && !w.closed && ctx.Err() == nil {
		_ = w.changed.wait(&w.mu, time.Time{}, ctx.Done())
	}
	if w.closed {
		return nil, net.ErrClosed
	}
	if ctx.Err() != nil {
		return nil, context.Cause(ctx)
	}
	w.swapping = true
	defer func() { w.swapping = false; w.changed.broadcast() }()
	for w.writing && !w.closed && ctx.Err() == nil {
		_ = w.changed.wait(&w.mu, time.Time{}, ctx.Done())
	}
	for !w.closed && ctx.Err() == nil {
		deadline, gen := w.deadline, w.gen
		err := func() error {
			w.mu.Unlock()
			defer w.mu.Lock()
			return setStreamWriteDeadline(next, deadline)
		}()
		if w.closed || ctx.Err() != nil || gen != w.gen {
			continue
		}
		if err != nil {
			return nil, err
		}
		old := w.w
		w.w, w.set = next, true
		w.gen++
		return old, nil
	}
	if w.closed {
		return nil, net.ErrClosed
	}
	return nil, context.Cause(ctx)
}

// ReplacedStreamError means Swap installed next and closing the previous stream failed.
type ReplacedStreamError struct{ Err error }

func (e *ReplacedStreamError) Error() string {
	if e == nil || e.Err == nil {
		return "duplex: closing the replaced stream failed"
	}
	return e.Err.Error()
}
func (e *ReplacedStreamError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// SetWriteDeadline sets the deadline for writes and their waits, and on
// the current stream and those that Swap installs. It returns an error
// matching errors.ErrUnsupported when the current stream has no
// SetWriteDeadline method, but keeps the deadline for the waits and the
// streams to come.
func (w *Writer) SetWriteDeadline(t time.Time) error {
	if w == nil {
		return net.ErrClosed
	}
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return net.ErrClosed
	}
	w.deadline = t
	w.gen++
	w.changed.broadcast()
	w.mu.Unlock()
	return w.applyDeadline()
}

// applyDeadline sets the write deadline on the current stream without
// holding w.mu, as Reader.applyDeadline does.
func (w *Writer) applyDeadline() error {
	for {
		w.mu.Lock()
		h, t, gen := w.w, w.deadline, w.gen
		w.mu.Unlock()
		err := setStreamWriteDeadline(h, t)
		w.mu.Lock()
		latest := w.gen == gen
		w.mu.Unlock()
		if latest {
			return err
		}
	}
}

func setStreamWriteDeadline(h io.Writer, t time.Time) error {
	if h == nil {
		return nil
	}
	if d, ok := h.(writeDeadliner); ok {
		return d.SetWriteDeadline(t)
	}
	return noDeadline(t, errNoWriteDeadline)
}

// Close closes the current stream and ends the writes and swaps that wait.
// Later writes and swaps return net.ErrClosed, as does a second Close.
func (w *Writer) Close() error {
	if w == nil {
		return net.ErrClosed
	}
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return net.ErrClosed
	}
	w.closed = true
	h := w.w
	w.w = nil
	w.gen++
	w.changed.broadcast()
	w.mu.Unlock()
	if cl, ok := h.(io.Closer); ok {
		return cl.Close()
	}
	return nil
}
