package dgram

import (
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"time"
)

// Queue holds the datagrams of one connection until they are read, within a
// bound on their count and a budget of bytes, with a read deadline, and
// tracks the connection's activity for the idle timeout. Any goroutines may
// enqueue and read. Init it before use.
//
// The datagrams are in a ring that grows as they queue up, doubling up to
// the bound, and is let go once it is read empty, so that an idle
// connection holds at most minRing slots, none before its first datagram,
// whatever its bound.
type Queue struct {
	ring   []*[]byte // datagrams, in Small buffers when they fit; len is a power of two
	ready  chan struct{}
	closed chan struct{}
	err    error // returned by reads once closed; set before closed is
	epoch  *Epoch
	// readDeadline fails reads once it has expired.
	readDeadline Deadline
	head         int          // index of the oldest datagram in ring
	n            int          // datagrams in ring
	limit        int          // the most datagrams queued
	queued       int64        // Cost of the datagrams queued
	budget       int64        // the most Cost queued; one datagram always fits
	active       atomic.Int64 // Epoch time of the last datagram or of Accept
	mu           sync.Mutex   // guards ring, head, n and queued
	// accepted is set by Accept; the idle timeout skips the connection
	// until then.
	accepted atomic.Bool
}

// minRing is the size of a ring when the first datagram queues.
const minRing = 4

// Init makes q hold up to n datagrams of SmallSize, or as many bytes of
// larger ones, telling the time of activity by e, the epoch of the Table's
// idle timeout too, or by the system clock when e is nil.
func (q *Queue) Init(n int, e *Epoch) {
	if e == nil {
		e = RealEpoch
	}
	q.epoch = e
	q.limit = max(n, 1)
	q.budget = int64(q.limit) * SmallSize
	q.ready = make(chan struct{}, 1)
	q.closed = make(chan struct{})
	q.readDeadline = MakeDeadline()
}

// Cost is the memory that a queued datagram of n bytes holds: a Small
// buffer, or an allocation of its own when it is larger.
func Cost(n int) int64 {
	return int64(max(n, SmallSize))
}

// Enqueue copies p into the queue and reports whether it did, which counts
// as activity: a full or closed queue drops it, as a socket buffer would.
// The queue is full at its bound of datagrams, or when p would pass its
// budget of bytes, so that large datagrams cannot pin up to 64 KiB each; an
// empty queue always takes one.
func (q *Queue) Enqueue(p []byte) bool {
	cost := Cost(len(p))
	q.mu.Lock()
	if IsClosed(q.closed) || q.n >= q.limit || q.n > 0 && q.queued+cost > q.budget {
		q.mu.Unlock()
		return false
	}
	var bp *[]byte
	if len(p) <= SmallSize {
		bp = Small.Get()
		*bp = (*bp)[:len(p)]
	} else {
		bp = NewBuf(len(p))
	}
	copy(*bp, p)
	if q.n == len(q.ring) {
		q.grow()
	}
	q.ring[(q.head+q.n)&(len(q.ring)-1)] = bp
	q.n++
	q.queued += cost
	q.mu.Unlock()
	q.signal()
	q.Touch()
	return true
}

// grow doubles the ring, or makes it, keeping the datagrams in order; mu is
// held.
func (q *Queue) grow() {
	ring := make([]*[]byte, max(len(q.ring)*2, minRing))
	for i := range q.n {
		ring[i] = q.ring[(q.head+i)&(len(q.ring)-1)]
	}
	q.ring, q.head = ring, 0
}

// signal wakes a waiting reader.
func (q *Queue) signal() {
	select {
	case q.ready <- struct{}{}:
	default: // one is pending already
	}
}

// pop takes the oldest datagram, or nil when there is none, and lets a
// grown ring go once it is empty.
func (q *Queue) pop() *[]byte {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.n == 0 {
		return nil
	}
	bp := q.ring[q.head]
	q.ring[q.head] = nil
	q.head = (q.head + 1) & (len(q.ring) - 1)
	q.n--
	q.queued -= Cost(len(*bp))
	if q.n == 0 {
		q.head = 0
		if len(q.ring) > minRing {
			q.ring = nil // a burst's room; a small ring stays for steady traffic
		}
	} else {
		q.signal() // for another reader
	}
	return bp
}

// Next returns the next datagram in its buffer, which the caller gives back
// with Release. As on a socket, a closed queue or an expired deadline fails
// it even while datagrams are queued.
func (q *Queue) Next() (*[]byte, error) {
	for {
		if IsClosed(q.closed) {
			return nil, q.err
		}
		expired := q.readDeadline.Wait()
		if IsClosed(expired) {
			return nil, os.ErrDeadlineExceeded
		}
		if bp := q.pop(); bp != nil {
			return bp, nil
		}
		select {
		case <-q.ready:
		case <-q.closed:
			return nil, q.err
		case <-expired:
			return nil, os.ErrDeadlineExceeded
		}
	}
}

// Read reads the next datagram into b, truncated to b, as Next does.
func (q *Queue) Read(b []byte) (int, error) {
	bp, err := q.Next()
	if err != nil {
		return 0, err
	}
	n := copy(b, *bp)
	Release(bp)
	return n, nil
}

// Close makes reads fail with err and releases the queued datagrams. It
// must be called once.
func (q *Queue) Close(err error) {
	q.mu.Lock()
	q.err = err
	close(q.closed)
	ring, head, n := q.ring, q.head, q.n
	q.ring, q.head, q.n, q.queued = nil, 0, 0, 0
	q.mu.Unlock()
	q.readDeadline.Stop()
	for i := range n {
		Release(ring[(head+i)&(len(ring)-1)])
	}
}

// Len returns how many datagrams are queued.
func (q *Queue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.n
}

// Closed reports whether Close was called.
func (q *Queue) Closed() bool { return IsClosed(q.closed) }

// Done returns a channel that is closed by Close.
func (q *Queue) Done() <-chan struct{} { return q.closed }

// SetReadDeadline sets the deadline of pending and later reads.
func (q *Queue) SetReadDeadline(t time.Time) { q.readDeadline.Set(t) }

// Touch records activity now.
func (q *Queue) Touch() { q.active.Store(q.epoch.Now()) }

// Accepted records that the connection was handed to its user, which
// starts its idle timeout.
func (q *Queue) Accepted() {
	q.Touch()
	q.accepted.Store(true)
}

// Activity returns the Epoch time of the last activity, and whether the
// connection was accepted, which starts its idle timeout.
func (q *Queue) Activity() (last int64, accepted bool) {
	// accepted first: Accepted touches before it sets it.
	accepted = q.accepted.Load()
	return q.active.Load(), accepted
}

// Source lets the Relay of package netx find the Queue of a connection of
// another package of this module, which embeds it under an unexported alias,
// so that Relay takes the queued datagrams whole and copies each once. Its
// one method is unexported: only this package's interface matches it, so
// external packages cannot implement it, and it shows in no documentation.
type Source struct {
	// self is the connection that embeds the Source, which tells it apart
	// from a type of another package that embeds the connection in turn.
	self any
	q    *Queue
}

// NewSource returns the Source of self, whose datagrams are in q.
func NewSource(self any, q *Queue) Source { return Source{self: self, q: q} }

func (s Source) datagramSource() Source { return s }

// sourcer is implemented by the connections that embed a Source.
type sourcer interface{ datagramSource() Source }

// QueueOf returns the Queue of v when v embeds a Source of its own, and
// otherwise nil, also for a type that embeds such a connection, which may
// read otherwise, and for a nil pointer.
func QueueOf(v any) *Queue {
	ds, ok := v.(sourcer)
	if !ok {
		return nil
	}
	if rv := reflect.ValueOf(ds); rv.Kind() == reflect.Pointer && rv.IsNil() {
		return nil // the promoted method would dereference it
	}
	if src := ds.datagramSource(); src.self == v {
		return src.q
	}
	return nil
}
