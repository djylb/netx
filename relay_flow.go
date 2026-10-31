package netx

import (
	"context"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/timeshim"

	"github.com/djylb/netx/internal/dgram"
)

// RelayFlow paces and counts one direction of a Relay or a Copy. Any of its
// functions may be nil. They are called from the goroutine copying that
// direction, one call at a time; functions shared by both directions, or by
// several relays, as a limiter of one user is, must be safe for concurrent
// use.
type RelayFlow struct {
	// Wait is called before each read from the direction's source with the
	// most bytes Relay can take at once, and blocks until bytes may pass. It
	// returns how many may pass now, from 1 to n: a stream is read for at
	// most that many, and a datagram is read whole, as it cannot be split.
	// On Unix systems, a source read straight from a socket is waited on
	// until it has data first, and its end is passed on without Wait; for
	// other sources Wait runs while they may still be idle, and before the
	// read that finds their end. A blocked Wait holds none of Relay's
	// buffers or pipes. A Wait that may block for long must return when ctx
	// is done: closing the relay's ends does not wake it, so end such relays
	// with Relay's context or WithRelayGroup.
	// Wait need not charge them, since Done reports what passed: a limiter
	// can charge that, going into debt that a later Wait waits out, so that
	// a relay idle in a read holds none of an allowance it shares. ctx is
	// done once the relay stops. An error ends the relay and is returned.
	Wait func(ctx context.Context, n int64) (int64, error)
	// Done is called with the bytes written to the direction's destination
	// after each write. An error, such as for a used up allowance, ends the
	// relay and is returned.
	Done func(n int64) error
	// First is called once with the first bytes read from the direction's
	// source, a stream's first non-empty read or the first datagram, before
	// they are written, so that a relay can tell the protocol of a
	// connection or log the start of it. b is valid only during the call.
	// A stream's first read goes through Relay's buffer, also where Relay
	// splices the rest.
	First func(b []byte)
	// End is called once when the direction stops, with the bytes it
	// copied and the error that stopped it: nil at the source's EOF, or
	// net.ErrClosed when the relay stopped it for another reason, such as
	// the other direction ending. Relay calls it before it passes the end on
	// with CloseWrite or stops the relay, so that the other direction can
	// be given a shorter idle timeout once one has ended, and Copy before it
	// returns. Unlike the other hooks, End alone does not make a direction
	// go through Relay's buffer.
	End func(n int64, err error)
}

// active reports whether f has hooks that make a copy go through Relay's
// buffer or its pieces.
func (f *RelayFlow) active() bool {
	return f != nil && (f.Wait != nil || f.Done != nil || f.First != nil)
}

// firstHook returns First, which a copy calls on its first read.
func (f *RelayFlow) firstHook() func([]byte) {
	if f == nil {
		return nil
	}
	return f.First
}

// wait returns how many bytes may pass of at most limit, limit without Wait.
func (f *RelayFlow) wait(ctx context.Context, limit int64) (int64, error) {
	if f == nil || f.Wait == nil {
		return limit, nil
	}
	n, err := f.Wait(ctx, limit)
	if err != nil {
		if ctx.Err() != nil {
			// Ended by the relay or its context; the cause, not the
			// hook's view of it.
			return 0, context.Cause(ctx)
		}
		return 0, err
	}
	return min(max(n, 1), limit), nil
}

func (f *RelayFlow) done(n int64) error {
	if f == nil || f.Done == nil || n <= 0 {
		return nil
	}
	return f.Done(n)
}

// write writes b to dst with one Write, as each piece of a copy is, and
// reports the bytes written to Done. The error is the first of the write's,
// io.ErrShortWrite for a short write, and Done's.
func (f *RelayFlow) write(dst io.Writer, b []byte) (int64, error) {
	m, err := writeOnce(dst, b)
	if derr := f.done(int64(m)); err == nil {
		err = derr
	}
	return int64(m), err
}

func (f *RelayFlow) end(n int64, err error) {
	if f != nil && f.End != nil {
		f.End(n, err)
	}
}

// relayIdle is the idle timeout of a relay: the flows of both directions
// record when data passes, and a timer stops the relay once none has for d.
type relayIdle struct {
	epoch    *dgram.Epoch
	timer    timeshim.Timer
	d        time.Duration
	activity atomic.Int64 // epoch time of the last data
	waiting  atomic.Int32 // flows blocked in Wait, which is not idleness
	mu       sync.Mutex   // orders the timer with start and its stop
	stopped  bool
}

func newRelayIdle(d time.Duration, c timeshim.Clock) *relayIdle {
	i := &relayIdle{d: d, epoch: dgram.NewEpoch(c)}
	i.touch()
	return i
}

func (i *relayIdle) touch() { i.activity.Store(i.epoch.Now()) }

// watch returns f recording the data that passes, and its waits.
func (i *relayIdle) watch(f RelayFlow) RelayFlow {
	done := f.Done
	f.Done = func(n int64) error {
		i.touch()
		if done != nil {
			return done(n)
		}
		return nil
	}
	if wait := f.Wait; wait != nil {
		f.Wait = func(ctx context.Context, n int64) (int64, error) {
			i.waiting.Add(1)
			defer func() {
				i.touch()
				i.waiting.Add(-1)
			}()
			return wait(ctx, n)
		}
	}
	return f
}

// start starts the timer, which calls stop once the relay is idle, and
// returns a function that ends it.
func (i *relayIdle) start(stop func()) func() {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.timer = i.epoch.Clock().AfterFunc(i.d, func() { i.check(stop) })
	return func() {
		i.mu.Lock()
		defer i.mu.Unlock()
		i.stopped = true
		i.timer.Stop()
	}
}

func (i *relayIdle) check(stop func()) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.stopped {
		return
	}
	left := time.Duration(i.activity.Load() + int64(i.d) - i.epoch.Now())
	if i.waiting.Load() > 0 {
		left = i.d // a Wait that blocks counts as activity
	}
	if left > 0 {
		i.timer.Reset(left)
		return
	}
	i.stopped = true
	stop()
}
