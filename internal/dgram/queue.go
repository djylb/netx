package dgram

import (
	"os"
	"reflect"
	"sync/atomic"
	"time"
)

// Queue holds the datagrams of one connection until they are read, within a
// budget of bytes, with a read deadline, and tracks the connection's
// activity for an idle sweep. Any goroutines may enqueue and read. Init it
// before use.
type Queue struct {
	queue  chan *[]byte // datagrams, in Small buffers when they fit
	queued atomic.Int64 // Cost of the datagrams in queue
	budget int64        // the most Cost queued; one datagram always fits
	closed chan struct{}
	err    error // returned by reads once closed; set before closed is
	// readDeadline fails reads once it has expired.
	readDeadline Deadline
	active       atomic.Int64 // Epoch time of the last datagram or of Accept
	// accepted is set by Accept; the idle sweep skips the connection until
	// then.
	accepted atomic.Bool
	epoch    *Epoch // tells the time of activity
}

// Init makes q hold up to n datagrams of SmallSize, or as many bytes of
// larger ones, telling the time of activity by e, the epoch that the
// Table's Sweep uses too, or by the system clock when e is nil.
func (q *Queue) Init(n int, e *Epoch) {
	if e == nil {
		e = RealEpoch
	}
	q.epoch = e
	q.queue = make(chan *[]byte, n)
	q.budget = int64(n) * SmallSize
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
func (q *Queue) Enqueue(p []byte) bool {
	// Bound the bytes queued as well as the datagrams, so that large
	// datagrams cannot pin up to 64 KiB per queue slot. An empty queue
	// always takes one.
	// The room is taken before the send, so that a read never subtracts
	// first, and atomically, so that concurrent enqueuers, such as a
	// listener's read loop and a reply socket's, cannot both take the last.
	cost := Cost(len(p))
	for {
		n := q.queued.Load()
		if n > 0 && n+cost > q.budget {
			return false
		}
		if q.queued.CompareAndSwap(n, n+cost) {
			break
		}
	}
	var bp *[]byte
	if len(p) <= SmallSize {
		bp = Small.Get()
		*bp = (*bp)[:len(p)]
	} else {
		bp = NewBuf(len(p))
	}
	copy(*bp, p)
	// A send without a case for closed, which a select of one case and a
	// default makes cheap: a Close before it is seen after it.
	select {
	case q.queue <- bp:
		if IsClosed(q.closed) {
			// Close drained the queue before the send, or comes after
			// it; drain it again, or the datagram keeps its buffer while
			// the queue is kept.
			q.drain()
			return false
		}
		q.Touch()
		return true
	default:
	}
	q.queued.Add(-cost)
	Release(bp)
	return false
}

// Next returns the next datagram in its buffer, which the caller gives back
// with Release. As on a socket, a closed queue or an expired deadline fails
// it even while datagrams are queued.
func (q *Queue) Next() (*[]byte, error) {
	// Selects of one case and a default are cheap; the select of all three
	// only runs when the queue is empty.
	if IsClosed(q.closed) {
		return nil, q.err
	}
	expired := q.readDeadline.Wait()
	if IsClosed(expired) {
		return nil, os.ErrDeadlineExceeded
	}
	var bp *[]byte
	select {
	case bp = <-q.queue:
	default:
		select {
		case bp = <-q.queue:
		case <-q.closed:
			return nil, q.err
		case <-expired:
			return nil, os.ErrDeadlineExceeded
		}
	}
	if IsClosed(q.closed) {
		// Close came first while select chose between them.
		Release(bp)
		return nil, q.err
	}
	q.queued.Add(-Cost(len(*bp)))
	return bp, nil
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
	q.err = err
	close(q.closed)
	q.readDeadline.Stop()
	q.drain()
}

// Len returns how many datagrams are queued.
func (q *Queue) Len() int { return len(q.queue) }

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

// IdleAt reports whether the accepted connection has been idle for at least
// d at now, a time of its Epoch. A connection waiting for Accept is not idle: the
// backlog is bounded, and closing it would lose its datagrams.
func (q *Queue) IdleAt(now int64, d time.Duration) bool {
	return q.accepted.Load() && now-q.active.Load() >= int64(d)
}

// drain releases the queued datagrams of a closed queue.
func (q *Queue) drain() {
	for {
		select {
		case bp := <-q.queue:
			Release(bp)
		default:
			return
		}
	}
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
