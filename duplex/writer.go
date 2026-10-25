package duplex

import (
	"context"
	"io"
	"net"
	"sync"
	"time"
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
	mu       sync.Mutex
	w        io.Writer
	writes   int // writes in progress on w
	deadline time.Time
	gen      uint64 // counts the changes of deadline and stream; see Reader.gen
	changed  waiter
	set      bool // w was installed, perhaps nil
	swapping bool // a swap waits for the writes to end; new ones wait
	closed   bool
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
	for !w.closed && (w.swapping || !w.set) {
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
	w.writes++
	w.mu.Unlock()

	n, err := h.Write(p)

	w.mu.Lock()
	if w.writes--; w.writes == 0 && w.swapping {
		w.changed.broadcast()
	}
	w.mu.Unlock()
	return n, err
}

// Swap makes next the stream that writes go to. It waits for the writes in
// progress to end, holding back new ones, so that each Write goes whole to
// one stream and the old stream gets nothing after them. Then it installs
// next, sets the write deadline of w on it, the zero time included, when it
// has SetWriteDeadline, and closes the old stream, unless it is next,
// ending it for its reader; it returns the error of that Close.
//
// Swap dials nothing: a caller that moves to a new connection prepares next
// first, while writes go on into the old one. When ctx ends or w is closed
// before the writes in progress do, Swap returns context.Cause(ctx) or
// net.ErrClosed and leaves both streams as they were, next with the caller.
// Swaps run one at a time, in no set order: a sender whose receiver must
// get the streams in the order of the swaps opens each stream and swaps to
// it under one lock, or from one goroutine.
func (w *Writer) Swap(ctx context.Context, next io.Writer) error {
	if w == nil {
		return net.ErrClosed
	}
	w.mu.Lock()
	for w.swapping && !w.closed && ctx.Err() == nil {
		_ = w.changed.wait(&w.mu, time.Time{}, ctx.Done())
	}
	if w.closed || ctx.Err() != nil {
		closed := w.closed
		w.mu.Unlock()
		if closed {
			return net.ErrClosed
		}
		return context.Cause(ctx)
	}
	w.swapping = true
	for w.writes > 0 && !w.closed && ctx.Err() == nil {
		_ = w.changed.wait(&w.mu, time.Time{}, ctx.Done())
	}
	w.swapping = false
	w.changed.broadcast()
	if w.closed || w.writes > 0 {
		closed := w.closed
		w.mu.Unlock()
		if closed {
			return net.ErrClosed
		}
		return context.Cause(ctx)
	}
	old := w.w
	w.w, w.set = next, true
	w.gen++
	w.mu.Unlock()
	_ = w.applyDeadline()
	if cl, ok := old.(io.Closer); ok && !same(old, next) {
		return cl.Close()
	}
	return nil
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
		if h == nil {
			return nil
		}
		var err error
		if d, ok := h.(writeDeadliner); ok {
			err = d.SetWriteDeadline(t)
		} else {
			err = noDeadline(t, errNoWriteDeadline)
		}
		w.mu.Lock()
		latest := w.gen == gen
		w.mu.Unlock()
		if latest {
			return err
		}
	}
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
