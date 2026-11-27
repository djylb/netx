package dgram

import (
	"net"
	"os"
	"sync"
	"time"

	"github.com/djylb/netx/internal/clock"
)

// WriteGate serializes sends on one shared socket so a flow can interrupt
// its current write without changing the deadline of a different flow.
type WriteGate struct {
	pc       net.PacketConn
	token    chan struct{}
	deadline time.Time // last unambiguous installation, while token is held
	unknown  bool
}

// NewWriteGate takes ownership of the socket's write deadline.
func NewWriteGate(pc net.PacketConn) *WriteGate {
	return &WriteGate{pc: pc, token: make(chan struct{}, 1)}
}

// Writer holds the write deadline of one flow.
type Writer struct {
	deadline time.Time
	active   *WriteGate
	expiry   clock.Deadline
	mu       sync.Mutex
	applying int
	updates  sync.WaitGroup
	closed   bool
}

// NewWriter returns a writer with no deadline.
func NewWriter() Writer { return Writer{expiry: clock.MakeDeadline()} }

// Write serializes a send and its deadline changes with the other users of the
// socket. A nil writer is a listener send with no flow deadline.
func (g *WriteGate) Write(w *Writer, done <-chan struct{}, send func() (int, error)) (int, error) {
	var timeout <-chan struct{}
	if w != nil {
		timeout = w.expiry.Wait()
	}
	select {
	case g.token <- struct{}{}:
	case <-done:
		return 0, net.ErrClosed
	case <-timeout:
		return 0, os.ErrDeadlineExceeded
	}
	defer func() { <-g.token }()
	if clock.IsClosed(done) {
		return 0, net.ErrClosed
	}
	if w == nil {
		if g.unknown || !g.deadline.IsZero() {
			g.unknown = true
			if err := g.pc.SetWriteDeadline(time.Time{}); err != nil {
				return 0, err
			}
			g.deadline, g.unknown = time.Time{}, false
		}
		return send()
	}

	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return 0, net.ErrClosed
	}
	if !w.deadline.IsZero() && !time.Now().Before(w.deadline) {
		w.mu.Unlock()
		return 0, os.ErrDeadlineExceeded
	}
	w.active = g
	defer func() {
		w.active = nil
		w.mu.Unlock()
		// Keep the socket until every setter that borrowed it has returned.
		w.updates.Wait()
	}()
	err := w.applyLocked()
	if w.closed {
		return 0, net.ErrClosed
	}
	if err != nil {
		return 0, err
	}
	n, err := func() (int, error) {
		w.mu.Unlock()
		defer w.mu.Lock()
		return send()
	}()
	if w.closed && err != nil {
		err = net.ErrClosed
	}
	return n, err
}

// applyLocked installs this caller's deadline. PacketConn permits concurrent
// setters. A setter overtaken during the external call reapplies the latest
// deadline before releasing the socket, while preserving its own error.
func (w *Writer) applyLocked() error {
	g := w.active
	if g == nil {
		return nil
	}
	w.updates.Add(1)
	defer w.updates.Done()
	var firstErr error
	for {
		want := w.deadline
		if w.applying == 0 && !g.unknown && g.deadline.Equal(want) {
			return firstErr
		}
		g.unknown = true
		w.applying++
		err := func() error {
			w.mu.Unlock()
			defer func() { w.mu.Lock(); w.applying-- }()
			return g.pc.SetWriteDeadline(want)
		}()
		if err != nil && firstErr == nil {
			firstErr = err
		}
		if w.applying == 0 && err == nil {
			g.deadline = want
			// Concurrent calls can return in a different order than they
			// installed. Only trust a stable, uncontested installation.
			g.unknown = !want.Equal(w.deadline)
		}
		if want.Equal(w.deadline) || w.active != g {
			return firstErr
		}
	}
}

// SetDeadline bounds waiting and active sends. For an idle flow, the next send
// reports any error installing its deadline on the socket.
func (w *Writer) SetDeadline(t time.Time) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return net.ErrClosed
	}
	w.deadline = t
	w.expiry.Set(t)
	return w.applyLocked()
}

// Close wakes a socket send through its deadline if the socket supports it.
// An uninterruptible send retains the socket until it returns or the socket closes.
func (w *Writer) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return
	}
	w.closed = true
	w.deadline = clock.Past
	w.expiry.Stop()
	// An active setter may have called Close itself. It will see Past
	// and apply it before giving up the socket.
	if w.applying == 0 {
		_ = w.applyLocked()
	}
}
