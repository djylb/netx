package dgram

import (
	"sync"
	"time"

	"github.com/djylb/timeshim"
)

// Release gives back a buffer of one of the shared pools or of a Queue,
// whatever its length now; one of another capacity is dropped.
func Release(bp *[]byte) {
	switch cap(*bp) {
	case SmallSize:
		Small.Put(bp)
	case StreamSize:
		Stream.Put(bp)
	case LargeSize:
		Large.Put(bp)
	}
}

// Epoch tells the time of a clock as nanoseconds since the clock's time when
// the Epoch was made, for activity tracking in atomics. Each component takes
// the epoch of the clock it is given, so that a clock of any time, such as a
// fake one at the zero time, counts right, and a step of the system's wall
// clock neither stretches nor cuts an idle period.
type Epoch struct {
	clock timeshim.Clock
	base  time.Time
}

// NewEpoch returns the epoch of c, or of the system clock when c is nil, at
// its time now.
func NewEpoch(c timeshim.Clock) *Epoch {
	c = timeshim.Or(c)
	return &Epoch{clock: c, base: c.Now()}
}

// RealEpoch is the epoch of the system clock that components without a
// clock of their own share; it is the one time base of activity tracking
// on the system clock.
var RealEpoch = NewEpoch(nil)

// Clock returns the clock of e.
func (e *Epoch) Clock() timeshim.Clock { return e.clock }

// Now returns the clock's time as nanoseconds since the epoch.
func (e *Epoch) Now() int64 { return e.At(e.clock.Now()) }

// At returns t, a time of the clock, as nanoseconds since the epoch.
func (e *Epoch) At(t time.Time) int64 { return int64(t.Sub(e.base)) }

// Past is a deadline long passed, which interrupts blocked I/O.
var Past = time.Unix(1, 0)

// Deadline is a resettable deadline whose expiry closes a channel, as in
// net.Pipe. Its zero value is not usable; see MakeDeadline.
type Deadline struct {
	mu      sync.Mutex
	timer   *time.Timer
	cancel  chan struct{} // closed when the deadline expires; never nil
	stopped bool          // set by Stop: no more timers
}

// MakeDeadline returns a deadline that is not set.
func MakeDeadline() Deadline {
	return Deadline{cancel: make(chan struct{})}
}

// Set makes the deadline expire at t, or never for the zero t. A wait on the
// channel of an earlier Wait goes on unless t has passed.
func (d *Deadline) Set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil && !d.timer.Stop() {
		<-d.cancel // the timer fired: wait until it closed the channel
	}
	d.timer = nil
	if d.stopped {
		return
	}
	closed := IsClosed(d.cancel)
	if t.IsZero() {
		if closed {
			d.cancel = make(chan struct{})
		}
		return
	}
	if dur := time.Until(t); dur > 0 {
		if closed {
			d.cancel = make(chan struct{})
		}
		cancel := d.cancel
		d.timer = time.AfterFunc(dur, func() { close(cancel) })
		return
	}
	if !closed {
		close(d.cancel)
	}
}

// Stop releases the pending timer, if any, without changing whether the
// deadline has expired, and keeps later calls of Set from starting another.
func (d *Deadline) Stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil && !d.timer.Stop() {
		<-d.cancel // the timer fired: wait until it closed the channel
	}
	d.timer = nil
	d.stopped = true
}

// Wait returns a channel that is closed once the deadline has expired.
func (d *Deadline) Wait() <-chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cancel
}

// IsClosed reports whether c is closed.
func IsClosed(c <-chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}

// Backoff spaces out the retries of a loop whose calls fail, such as the
// reads of a listener's socket or an Accept: the first failure is retried at
// once, as a single error such as an ICMP report or an aborted connection
// concerns that call alone, and failures that persist are retried with a
// delay that doubles from 1ms up to 1s. Its zero value is ready.
type Backoff struct {
	failures int
	delay    time.Duration
}

// Reset starts over after a success.
func (b *Backoff) Reset() { b.failures, b.delay = 0, 0 }

// Wait waits before the retry of a failure and reports whether it did,
// rather than see done closed first.
func (b *Backoff) Wait(done <-chan struct{}) bool {
	if b.failures++; b.failures == 1 {
		return !IsClosed(done)
	}
	b.delay = min(max(2*b.delay, time.Millisecond), time.Second)
	t := time.NewTimer(b.delay)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-done:
		return false
	}
}
