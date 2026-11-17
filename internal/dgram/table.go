package dgram

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/timeshim"
)

// Table holds the connections of a demultiplexing listener by key, such as
// a peer's address, with the backlog of new connections that wait for
// Accept, an optional limit on how many it holds and an optional idle
// timeout. The listener's read loops look connections up with Get and add
// new ones with Add; Accept, Close and Done also work on the zero Table,
// which then holds nothing.
//
// The connections are in a sync.Map, whose lookups take no lock and whose
// structure grows and shrinks with the entries it holds, so that a table of
// a few connections costs about as little as an empty map and one of
// millions spreads its updates over many independent parts; several read
// loops look connections up without contending. Idle connections are found
// by a timing wheel that each connection enters once, when it is added, and
// re-enters only when its slot comes up, so that traffic costs an atomic
// store and a check costs only the connections due in it.
type Table[K comparable, S comparable] struct {
	conns  sync.Map // K → S
	accept chan S
	done   chan struct{}
	// queue returns a connection's Queue; shutdown closes a connection with
	// an error for its reads and removes it from the table.
	queue    func(S) *Queue
	shutdown func(S, error)
	wheel    *idleWheel[S] // nil without an idle timeout
	n        atomic.Int64  // connections held
	max      int64
	once     sync.Once // makes done for the zero Table
	closed   atomic.Bool
}

// TableOptions configures Table.Init.
type TableOptions[S any] struct {
	// Queue returns a connection's Queue.
	Queue func(S) *Queue
	// Shutdown closes a connection with an error for its reads, removing it
	// with Remove; it must be safe to call more than once.
	Shutdown func(S, error)
	// Epoch tells the time of the idle timeout, the system clock's when nil;
	// it is the epoch of the connections' queues.
	Epoch *Epoch
	// Backlog is how many new connections wait for Accept, at least one.
	Backlog int
	// Limit is the most connections held, none when not positive.
	Limit int
	// Idle shuts down, with io.EOF, the accepted connections idle for it,
	// none when not positive.
	Idle time.Duration
}

// Init sets t up. Call it once, before the other methods.
func (t *Table[K, S]) Init(o TableOptions[S]) {
	t.accept = make(chan S, max(o.Backlog, 1))
	t.max, t.queue, t.shutdown = int64(o.Limit), o.Queue, o.Shutdown
	t.lazy()
	if o.Idle > 0 {
		t.wheel = newIdleWheel(t, o.Idle, o.Epoch)
	}
}

// lazy makes done, also for the zero Table.
func (t *Table[K, S]) lazy() {
	t.once.Do(func() { t.done = make(chan struct{}) })
}

// Get returns the connection under k.
func (t *Table[K, S]) Get(k K) (S, bool) {
	v, ok := t.conns.Load(k)
	if !ok {
		var zero S
		return zero, false
	}
	return v.(S), true
}

// Room reports whether a new connection could wait for Accept now: the
// table is open, the backlog has room and the limit is not reached. Check it
// before allocating for a new peer; Add checks again.
func (t *Table[K, S]) Room() bool {
	return len(t.accept) < cap(t.accept) && (t.max <= 0 || t.n.Load() < t.max) && !t.closed.Load()
}

// Result is the outcome of Add.
type Result uint8

// The results of Add.
const (
	Added  Result = iota // the connection was added
	Exists               // a connection under the key was there already
	Full                 // the limit or the backlog refused it
	Closed               // the table is closed
)

// Add adds s under k, to wait for Accept too with backlog. It returns s and
// Added, or the connection already under k and Exists, or Full when the
// table holds its limit of connections or, with backlog, the backlog is
// full, or Closed after Close.
func (t *Table[K, S]) Add(k K, s S, backlog bool) (S, Result) {
	var zero S
	if t.closed.Load() {
		return zero, Closed
	}
	if other, ok := t.Get(k); ok {
		return other, Exists
	}
	// The place is taken before the entry is stored, so that concurrent
	// adds cannot pass the limit together.
	if n := t.n.Add(1); t.max > 0 && n > t.max {
		t.n.Add(-1)
		return zero, Full
	}
	if v, loaded := t.conns.LoadOrStore(k, s); loaded {
		t.n.Add(-1)
		return v.(S), Exists
	}
	// Close sets closed before it walks the map: either it sees s there,
	// or this sees closed.
	if t.closed.Load() {
		t.drop(k, s)
		return zero, Closed
	}
	if backlog {
		select {
		case t.accept <- s:
		default:
			t.drop(k, s)
			return zero, Full
		}
	}
	if t.wheel != nil {
		t.wheel.add(s)
	}
	return s, Added
}

// drop takes s, which Add stored under k, back out.
func (t *Table[K, S]) drop(k K, s S) {
	if t.conns.CompareAndDelete(k, s) {
		t.n.Add(-1)
		if t.wheel != nil {
			t.wheel.remove(s)
		}
	}
}

// Remove removes s from under k, but not another connection under k.
func (t *Table[K, S]) Remove(k K, s S) { t.drop(k, s) }

// Accept waits for the next new connection and marks it accepted, skipping
// those closed meanwhile. It returns net.ErrClosed once t is closed.
func (t *Table[K, S]) Accept() (S, error) {
	var zero S
	t.lazy()
	for {
		select {
		case <-t.done:
			return zero, net.ErrClosed
		default:
		}
		select {
		case s := <-t.accept:
			if IsClosed(t.done) {
				// Close came first while select chose between them; it
				// may not have shut s down yet.
				t.shutdown(s, net.ErrClosed)
				return zero, net.ErrClosed
			}
			q := t.queue(s)
			if q.Closed() {
				continue
			}
			q.Accepted()
			return s, nil
		case <-t.done:
			return zero, net.ErrClosed
		}
	}
}

// Close closes t, so that it adds no connection, stops its idle timeout and
// shuts down the connections it holds, with err for their reads. Calls after
// the first do nothing.
func (t *Table[K, S]) Close(err error) {
	t.lazy()
	if !t.closed.CompareAndSwap(false, true) {
		return
	}
	close(t.done)
	if t.wheel != nil {
		t.wheel.stop() // waits for a check in progress
	}
	t.conns.Range(func(_, v any) bool {
		t.shutdown(v.(S), err)
		return true
	})
	// The connections waiting for Accept are in conns too, unless they
	// were shut down meanwhile; their slots are freed here.
	for {
		select {
		case s := <-t.accept:
			t.shutdown(s, err)
		default:
			return
		}
	}
}

// Done returns a channel that Close closes.
func (t *Table[K, S]) Done() <-chan struct{} {
	t.lazy()
	return t.done
}

// Len returns how many connections t holds.
func (t *Table[K, S]) Len() int { return int(t.n.Load()) }

// Pending returns how many connections wait for Accept.
func (t *Table[K, S]) Pending() int { return len(t.accept) }

// wheelSlots is the number of slots of an idleWheel, each a tick of a
// quarter of the timeout: a connection is due at most the timeout and a
// tick ahead, which fits.
const wheelSlots = 8

// idleWheel is the timing wheel of a Table's idle timeout. Each connection
// sits in the slot of the tick when it may first be idle, at a position
// that its Queue records, so that it leaves the wheel in constant time when
// it is removed from the table. When its slot comes up, a connection that
// is idle is shut down, and any other moves to the slot of its new due
// time, so that traffic never touches the wheel. Its slots grow with the
// connections they hold and give their room back when they empty.
type idleWheel[S comparable] struct {
	table    interface{ shutdownIdle(s S) }
	queue    func(S) *Queue
	epoch    *Epoch
	timer    timeshim.Timer
	slots    [wheelSlots][]S
	idle     []S            // the idle connections of a tick, shut down after it
	inflight sync.WaitGroup // ticks shutting connections down
	d        time.Duration
	every    time.Duration
	mu       sync.Mutex // guards the fields above, the queues' positions and those below
	cur      int        // the slot of the last tick
	stopped  bool
}

func (t *Table[K, S]) shutdownIdle(s S) { t.shutdown(s, io.EOF) }

func newIdleWheel[K comparable, S comparable](t *Table[K, S], d time.Duration, e *Epoch) *idleWheel[S] {
	if e == nil {
		e = RealEpoch
	}
	w := &idleWheel[S]{table: t, queue: t.queue, epoch: e, d: d, every: max(d/4, 10*time.Millisecond)}
	w.mu.Lock()
	w.timer = e.Clock().AfterFunc(w.every, w.tick)
	w.mu.Unlock()
	return w
}

// add puts a new connection into the wheel, due d from now.
func (w *idleWheel[S]) add(s S) {
	w.mu.Lock()
	if !w.stopped && !w.queue(s).Closed() {
		w.place(s, w.d)
	}
	w.mu.Unlock()
}

// remove takes s out of the wheel, if it is in it.
func (w *idleWheel[S]) remove(s S) {
	q := w.queue(s)
	w.mu.Lock()
	defer w.mu.Unlock()
	if q.wheelSlot == 0 {
		return
	}
	slot := &w.slots[q.wheelSlot-1]
	last := len(*slot) - 1
	if i := int(q.wheelPos); i != last {
		moved := (*slot)[last]
		(*slot)[i] = moved
		w.queue(moved).wheelPos = int32(i)
	}
	var zero S
	(*slot)[last] = zero
	*slot = (*slot)[:last]
	q.wheelSlot, q.wheelPos = 0, 0
}

// place puts s into the slot of the first tick at least in from now; mu is
// held.
func (w *idleWheel[S]) place(s S, in time.Duration) {
	ticks := int((in + w.every - 1) / w.every)
	ticks = min(max(ticks, 1), wheelSlots-1)
	i := (w.cur + ticks) % wheelSlots
	q := w.queue(s)
	q.wheelSlot, q.wheelPos = int32(i+1), int32(len(w.slots[i]))
	w.slots[i] = append(w.slots[i], s)
}

// tick checks the connections of the next slot, and shuts the idle ones
// down after it lets mu go, so that adds and removes go on meanwhile.
func (w *idleWheel[S]) tick() {
	w.mu.Lock()
	if w.stopped {
		w.mu.Unlock()
		return
	}
	w.cur = (w.cur + 1) % wheelSlots
	due := w.slots[w.cur]
	w.slots[w.cur] = nil
	now := w.epoch.Now()
	var zero S
	for i, s := range due {
		due[i] = zero
		q := w.queue(s)
		q.wheelSlot, q.wheelPos = 0, 0
		active, accepted := q.Activity()
		left := w.d // one waiting for Accept is not idle yet
		if accepted {
			left = time.Duration(active + int64(w.d) - now)
		}
		if left <= 0 {
			w.idle = append(w.idle, s)
			continue
		}
		w.place(s, left)
	}
	// Reuse the slot's room unless it is far larger than what it held;
	// nothing was placed into the current slot, as place skips it.
	if cap(due) <= 64 || len(due) >= cap(due)/4 {
		w.slots[w.cur] = due[:0]
	}
	idle := w.idle
	w.idle = nil
	w.timer.Reset(w.every)
	w.inflight.Add(1)
	w.mu.Unlock()
	defer w.inflight.Done()
	for i, s := range idle {
		w.table.shutdownIdle(s)
		idle[i] = zero
	}
	w.mu.Lock()
	if w.idle == nil {
		w.idle = idle[:0]
	}
	w.mu.Unlock()
}

// stop ends the checks, waiting for those shutting connections down, and
// lets go of the connections.
func (w *idleWheel[S]) stop() {
	w.mu.Lock()
	w.stopped = true
	w.timer.Stop()
	for i := range w.slots {
		for _, s := range w.slots[i] {
			q := w.queue(s)
			q.wheelSlot, q.wheelPos = 0, 0
		}
		w.slots[i] = nil
	}
	w.idle = nil
	w.mu.Unlock()
	w.inflight.Wait()
}
