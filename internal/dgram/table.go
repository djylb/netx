package dgram

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Table holds the connections of a demultiplexing listener by key, such as
// a peer's address, with the backlog of new connections that wait for
// Accept and an optional limit on how many it holds. The listener's read
// loop looks connections up with Get and adds new ones with Add; Accept,
// Close and Done also work on the zero Table, which then holds nothing.
type Table[K comparable, S comparable] struct {
	conns  map[K]S
	accept chan S
	done   chan struct{}
	n      atomic.Int64 // len(conns), for Room
	max    int
	// queue returns a connection's Queue; shutdown closes a connection with
	// an error for its reads and removes it from the table.
	queue    func(S) *Queue
	shutdown func(S, error)
	mu       sync.Mutex
	once     sync.Once // makes done for the zero Table
	closed   bool      // guarded by mu
}

// Init sets t up: backlog connections wait for Accept, at most limit are
// held unless limit is not positive, queue returns a connection's Queue, and
// shutdown closes a connection, removing it with Remove. Call it once,
// before the other methods.
func (t *Table[K, S]) Init(backlog, limit int, queue func(S) *Queue, shutdown func(S, error)) {
	t.conns = make(map[K]S)
	t.accept = make(chan S, max(backlog, 1))
	t.max, t.queue, t.shutdown = limit, queue, shutdown
	t.lazy()
}

// lazy makes done, also for the zero Table.
func (t *Table[K, S]) lazy() {
	t.once.Do(func() { t.done = make(chan struct{}) })
}

// Get returns the connection under k.
func (t *Table[K, S]) Get(k K) (S, bool) {
	t.mu.Lock()
	s, ok := t.conns[k]
	t.mu.Unlock()
	return s, ok
}

// Room reports whether a new connection could wait for Accept now: the
// table is open, the backlog has room and the limit is not reached. Only
// the read loop adds to the backlog, so the room it reports stays until
// that loop adds; check it before allocating for a new peer.
func (t *Table[K, S]) Room() bool {
	return len(t.accept) < cap(t.accept) && (t.max <= 0 || t.n.Load() < int64(t.max)) && !IsClosed(t.done)
}

// Result is the outcome of Add.
type Result uint8

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
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return zero, Closed
	}
	if other, ok := t.conns[k]; ok {
		return other, Exists
	}
	if t.max > 0 && len(t.conns) >= t.max {
		return zero, Full
	}
	if backlog {
		select {
		case t.accept <- s:
		default:
			return zero, Full
		}
	}
	t.conns[k] = s
	t.n.Store(int64(len(t.conns)))
	return s, Added
}

// Remove removes s from under k, but not another connection under k.
func (t *Table[K, S]) Remove(k K, s S) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if other, ok := t.conns[k]; ok && other == s {
		delete(t.conns, k)
		t.n.Store(int64(len(t.conns)))
	}
}

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

// Close closes t, so that it adds no connection, and shuts down the
// connections it holds, with err for their reads. Calls after the first do
// nothing.
func (t *Table[K, S]) Close(err error) {
	t.lazy()
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	t.closed = true
	close(t.done)
	conns := make([]S, 0, len(t.conns))
	for _, s := range t.conns {
		conns = append(conns, s)
	}
	t.mu.Unlock()
	for _, s := range conns {
		t.shutdown(s, err)
	}
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

// Sweep shuts down, with io.EOF, the accepted connections idle for d, until
// t is closed. It checks every quarter of d, at least every 10ms.
func (t *Table[K, S]) Sweep(d time.Duration) {
	ticker := time.NewTicker(max(d/4, 10*time.Millisecond))
	defer ticker.Stop()
	var idle []S
	for {
		select {
		case <-t.done:
			return
		case now := <-ticker.C:
			mono := Mono(now)
			t.mu.Lock()
			for _, s := range t.conns {
				if t.queue(s).IdleAt(mono, d) {
					idle = append(idle, s)
				}
			}
			t.mu.Unlock()
			var zero S
			for i, s := range idle {
				t.shutdown(s, io.EOF)
				idle[i] = zero
			}
			idle = idle[:0]
		}
	}
}

// Len returns how many connections t holds.
func (t *Table[K, S]) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.conns)
}

// Pending returns how many connections wait for Accept.
func (t *Table[K, S]) Pending() int { return len(t.accept) }
