package netx

import (
	"context"
	"errors"
	"io"
	"sync/atomic"

	"github.com/djylb/netx/internal/netutil"
)

// ErrWouldBlock is returned by ReadNotifier.TryRead when the source holds
// nothing to read yet and has neither ended nor failed. It also ends an
// io.ReaderFrom that Relay feeds only while its source has data; see Relay.
// Its WouldBlock method reports true, so IsWouldBlock recognizes it; a
// source may return an error of its own instead.
var ErrWouldBlock error = wouldBlockError{}

type wouldBlockError struct{}

func (wouldBlockError) Error() string    { return "netx: read would block" }
func (wouldBlockError) WouldBlock() bool { return true }

// IsWouldBlock reports whether err, or an error it wraps, has a method
// WouldBlock() bool that reports true, as ErrWouldBlock does: the error
// says that a read found nothing yet, not that it failed. A source can so
// signal it without depending on this package.
func IsWouldBlock(err error) bool {
	var wb interface{ WouldBlock() bool }
	return errors.As(err, &wb) && wb.WouldBlock()
}

// ReadNotifier is a source that can be read without blocking and that tells
// when it becomes readable, such as a stream of a multiplexed connection.
// Relay copies from it without a goroutine of its own: no goroutine waits
// while the source is idle, and a short task, started by the notification,
// copies what there is and ends once TryRead would block. Copy waits on it
// before it takes a buffer, so that an idle copy holds none.
//
// The source is readable once TryRead would return anything but an error
// for which IsWouldBlock reports true: data, the end of the stream after the peer closed its
// writing side, or an error, such as for a reset, a local Close or
// CloseRead, or a read deadline that has passed.
type ReadNotifier interface {
	// TryRead reads as Read does but never blocks: while the source holds
	// no data and has not ended or failed, it returns 0 and an error for
	// which IsWouldBlock reports true: ErrWouldBlock, or an error of the
	// source's own, possibly wrapped, with a method WouldBlock() bool that
	// reports true. An error whose WouldBlock reports false is an ordinary
	// error, as is any other.
	// Otherwise it returns at once what Read would: n > 0 bytes, or 0 and
	// io.EOF at the end of the stream, or 0 and the error Read would
	// return. TryRead and Read share the source's data and are not called
	// concurrently with each other, as Reads are not.
	TryRead(p []byte) (n int, err error)

	// NotifyReadable arranges for f to be called once the source is
	// readable, and returns a function that cancels the call.
	//
	// f is called at most once, and exactly once unless stop cancels it
	// first: when data arrives, at the end of the stream, on an error or a
	// reset, when the source or the connection it belongs to is closed, and
	// when a read deadline passes. A source that is readable when
	// NotifyReadable is called calls f at once, without waiting for another
	// event, possibly on the calling goroutine before NotifyReadable
	// returns; a caller need not try TryRead first, and f must not wait for
	// NotifyReadable to return.
	//
	// f may run on any goroutine, such as the one that reads the
	// connection, and must not block; it may call the source's methods,
	// so the source must not hold a lock of its own while it calls f.
	//
	// stop cancels the call as the stop of context.AfterFunc does: it
	// returns true if it kept f from being called, and false if f has
	// already been called or started, or the call was stopped already. stop
	// does not wait for a running f to return, and calling it again is
	// harmless.
	//
	// A source need support only one pending call at a time: a caller
	// calls NotifyReadable again only after f has been called or stop
	// returned true. Changing the read deadline does not affect a pending
	// call beyond calling f when the deadline passes.
	NotifyReadable(f func()) (stop func() bool)
}

// notifySocket is a source read through a ReadNotifier beneath the wrappers
// that pass reads on.
type notifySocket struct {
	src *relaySource
	n   ReadNotifier
}

// notifierSource returns the source's ReadNotifier, beneath the wrappers
// that pass reads on, or nil.
func notifierSource(s *relaySource) *notifySocket {
	n, ok := s.base.(ReadNotifier)
	if !ok || netutil.IsNilPointer(n) {
		return nil
	}
	return &notifySocket{src: s, n: n}
}

// wait waits until the source is readable, or ctx is done.
func (s *notifySocket) wait(ctx context.Context) (bool, error) {
	switch {
	case s.src.exhausted():
		return true, nil // the bound ends the source
	case s.src.prefixPending():
		return false, nil
	}
	if err := s.src.timeouts.refresh(); err != nil {
		return false, err
	}
	ready := make(chan struct{})
	stop := s.n.NotifyReadable(func() { close(ready) })
	select {
	case <-ready:
		return false, nil
	case <-ctx.Done():
		if stop() {
			return false, context.Cause(ctx)
		}
		<-ready // called meanwhile: readable after all
		return false, nil
	}
}

// readNow reads what the source holds without waiting, reporting blocked
// when there is nothing yet. Bytes a PrefixConn holds are read through it.
func (s *notifySocket) readNow(b []byte) (int, bool, error) {
	if s.src.prefixPending() {
		n, err := s.src.r.Read(b)
		return n, false, err
	}
	if s.src.exhausted() {
		return 0, false, io.EOF
	}
	b = b[:s.src.limited(int64(len(b)))]
	if err := s.src.timeouts.refresh(); err != nil {
		return 0, false, err
	}
	n, err := s.n.TryRead(b)
	if n == 0 && IsWouldBlock(err) {
		return 0, true, nil
	}
	s.src.consumed(n)
	return n, false, err
}

// Read reads without waiting, failing with ErrWouldBlock when the source
// holds nothing, for the ReadFrom of readFromReady.
func (s *notifySocket) Read(p []byte) (int, error) {
	n, blocked, err := s.readNow(p)
	if blocked {
		return 0, ErrWouldBlock
	}
	return n, err
}

// readFromReady feeds the destination's ReadFrom only while the source has
// data, as streamSocket.readFromReady does.
func (s *notifySocket) readFromReady(ctx context.Context, rf io.ReaderFrom, idle *relayIdle) (int64, error) {
	r := idle.reader(s)
	var written int64
	for {
		if _, err := s.wait(ctx); err != nil {
			return written, err
		}
		n, err := rf.ReadFrom(r)
		written += n
		if !IsWouldBlock(err) {
			return written, err
		}
	}
}

// The states of a notifyCopy.
const (
	notifyRunning int32 = iota // a task copies
	notifyArming               // a task registers for the notification
	notifyArmed                // no task: the notification starts one
)

// notifyCopy copies one direction of a Relay from a ReadNotifier without a
// goroutine of its own: a task copies while the source is readable, then
// registers for the next notification and ends; the notification starts
// the next task. A task blocked writing holds the source back, which
// passes the back pressure on to the source's peer.
type notifyCopy struct {
	ctx  context.Context //nolint:containedctx // the relay's, which the tasks started by notifications pace Wait with
	dst  io.Writer
	f    *RelayFlow
	end  func(n int64, err error) // called once, by the last task
	sock *notifySocket
	// first is f.First until the first data has passed.
	first   func([]byte)
	written int64
	state   atomic.Int32
}

// newNotifyCopy returns a notifyCopy from src to dst, or nil if src is no
// ReadNotifier that Relay can copy so: one read through Relay's buffer, not
// datagrams, nor the parts of a ChainReader. idle, if not nil, records the
// data that passes when f does not.
func newNotifyCopy(ctx context.Context, dst io.Writer, src io.Reader, f *RelayFlow, idle *relayIdle, end func(int64, error)) *notifyCopy {
	dst, src = unwrapRelayEnds(dst, src)
	if _, ok := src.(*ChainReader); ok {
		return nil
	}
	e := newRelayEnds(dst, src)
	sock := notifierSource(&e.src)
	if sock == nil || e.src.readsDatagrams() {
		return nil
	}
	if !f.active() && idle != nil {
		f = &RelayFlow{Done: idle.done}
	}
	return &notifyCopy{ctx: ctx, dst: e.dst.w, f: f, end: end, sock: sock, first: f.firstHook()}
}

// start starts the copy: it waits for the first notification without a
// task.
func (c *notifyCopy) start() {
	if !c.arm() {
		go c.run()
	}
}

// arm registers for the next notification and reports whether that left
// the copy to it; false means the source is readable already, and the
// caller goes on copying.
func (c *notifyCopy) arm() bool {
	c.state.Store(notifyArming)
	c.sock.n.NotifyReadable(c.notify)
	return c.state.CompareAndSwap(notifyArming, notifyArmed)
}

// notify is the notification: a call while arm runs leaves the copy to arm's
// caller; a later one starts a task.
func (c *notifyCopy) notify() {
	if c.state.CompareAndSwap(notifyArming, notifyRunning) {
		return
	}
	c.state.Store(notifyRunning)
	go c.run()
}

// run is a task: it copies until the source would block or the copy ends.
func (c *notifyCopy) run() {
	for {
		limit, err := c.f.wait(c.ctx, relayBufSize)
		if err != nil {
			c.end(c.written, err)
			return
		}
		bp := relayBufs.Get()
		buf := (*bp)[:limit]
		r, blocked, rerr := c.sock.readNow(buf)
		if blocked {
			relayBufs.Put(bp)
			if c.arm() {
				return
			}
			continue
		}
		if r > 0 {
			if c.first != nil {
				c.first(buf[:r])
				c.first = nil
			}
			m, werr := c.f.write(c.dst, buf[:r])
			c.written += m
			if werr != nil {
				relayBufs.Put(bp)
				c.end(c.written, werr)
				return
			}
		}
		relayBufs.Put(bp)
		if rerr != nil {
			c.end(c.written, eofNil(rerr))
			return
		}
		// A short read most likely took all there was: register rather
		// than call Wait while the source may be idle.
		if r < len(buf) && c.arm() {
			return
		}
	}
}
