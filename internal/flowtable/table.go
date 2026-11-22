// Package flowtable manages datagram flow registration, acceptance and expiry.
package flowtable

import (
	"hash/maphash"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/netx/internal/clock"
	"github.com/djylb/netx/internal/dgram"
	"github.com/djylb/timeshim"
)

const tableShards = 32

// Table holds flows by primary key, optionally with a secondary peer index.
// Get uses a sync.Map and takes no lock. Mutations to a peer's keys and index
// take the same shard lock. Without an index, mutations shard by primary key.
// A zero Table is empty and cannot register flows. Accept waits for Close,
// and Close releases it with net.ErrClosed.
type Table[K, P, S comparable] struct {
	accept     chan acceptedFlow[P, S]
	done       chan struct{}
	queue      func(S) *dgram.Queue
	shutdown   func(S, error)
	peer       func(K) P
	membership func(S) *Membership[K, P]
	hashKey    func(maphash.Seed, K) uint64
	hashPeer   func(maphash.Seed, P) uint64

	wheel  atomic.Pointer[idleWheel[S]]
	epoch  *clock.Epoch
	idleMu sync.Mutex
	conns  sync.Map // K → S
	n      atomic.Int64
	max    int64
	seed   maphash.Seed
	shards [tableShards]tableShard[P, S]
	once   sync.Once
	closed atomic.Bool
}

type tableShard[P, S comparable] struct {
	mu    sync.Mutex
	peers map[P]peerFlows[S]
}

type peerFlows[S comparable] struct {
	count   int
	unbound S
}

type acceptedFlow[P, S comparable] struct {
	flow  S
	shard *tableShard[P, S]
}

// Membership records a flow's registration and expiry position. The table
// owns it. A flow supplies its own zero Membership and keeps it for life.
type Membership[K, P comparable] struct {
	// shard is published at registration. Zero means unregistered. The
	// indicated shard's lock protects key, peer and bound.
	key   K
	peer  P
	wheel wheelPosition
	shard atomic.Uint32
	bound bool
}

type wheelPosition struct {
	slot int32 // slot plus one, zero when absent
	pos  int32
}

// TableOptions configures Table.Init.
type TableOptions[K, P, S comparable] struct {
	Queue func(S) *dgram.Queue
	// Shutdown closes a flow with an error for reads and removes it.
	// It must be safe to call more than once.
	Shutdown func(S, error)
	// Membership returns the flow's registration record.
	Membership func(S) *Membership[K, P]
	// HashKey selects the shard for a table without a peer index.
	HashKey func(maphash.Seed, K) uint64
	// Peer and HashPeer enable indexing. Supply both or neither. Keys for
	// the same peer are assigned to the same shard.
	Peer     func(K) P
	HashPeer func(maphash.Seed, P) uint64
	// Epoch is the time base of the queues and their idle timeout. Nil
	// uses the system clock's epoch.
	Epoch *clock.Epoch
	// Backlog is the number of connections waiting for Accept, at least one.
	Backlog int
	// Limit bounds the number of connections held, including unbound flows.
	// A non-positive limit adds no bound.
	Limit int
	// Idle shuts down accepted flows with io.EOF after this much inactivity.
	// A non-positive duration keeps idle flows.
	Idle time.Duration
}

// Init sets t up. Call it once, before the other methods.
func (t *Table[K, P, S]) Init(o TableOptions[K, P, S]) {
	t.accept = make(chan acceptedFlow[P, S], max(o.Backlog, 1))
	t.max, t.queue, t.shutdown = int64(o.Limit), o.Queue, o.Shutdown
	t.peer, t.membership = o.Peer, o.Membership
	t.hashKey, t.hashPeer = o.HashKey, o.HashPeer
	t.seed = maphash.MakeSeed()
	t.lazy()
	t.epoch = o.Epoch
	if o.Idle > 0 {
		t.wheel.Store(newIdleWheel(t, o.Idle, o.Epoch))
	}
}

// SetIdle changes the idle timeout for the flows already held and for new
// flows. A non-positive duration stops it. It does nothing before Init or after Close.
func (t *Table[K, P, S]) SetIdle(d time.Duration) {
	if t.accept == nil {
		return
	}
	t.idleMu.Lock()
	defer t.idleMu.Unlock()
	if t.closed.Load() {
		return
	}
	w := t.wheel.Load()
	switch {
	case d <= 0 && w != nil:
		t.wheel.Store(nil)
		w.stop()
	case d > 0 && w != nil:
		w.setTimeout(d)
	case d > 0:
		w = newIdleWheel(t, d, t.epoch)
		t.wheel.Store(w)
		// Unbound flows can move into conns. Visit them first so a bind
		// during the walk cannot hide a flow from both passes.
		var zero S
		for i := range t.shards {
			shard := &t.shards[i]
			shard.mu.Lock()
			for _, flows := range shard.peers {
				if flows.unbound != zero {
					w.add(i, flows.unbound)
				}
			}
			shard.mu.Unlock()
		}
		t.conns.Range(func(key, v any) bool {
			k, s := key.(K), v.(S)
			i, _ := t.keyShard(k)
			shard := &t.shards[i]
			shard.mu.Lock()
			if current, ok := t.Get(k); ok && current == s {
				w.add(i, s)
			}
			shard.mu.Unlock()
			return true
		})
	}
}

func (t *Table[K, P, S]) lazy() {
	t.once.Do(func() { t.done = make(chan struct{}) })
}

// Get returns the flow under k.
func (t *Table[K, P, S]) Get(k K) (S, bool) {
	v, ok := t.conns.Load(k)
	if !ok {
		var zero S
		return zero, false
	}
	return v.(S), true
}

// Room reports whether a new flow could wait for Accept now. Add checks
// the limit and backlog again when it registers a flow.
func (t *Table[K, P, S]) Room() bool {
	return len(t.accept) < cap(t.accept) && (t.max <= 0 || t.n.Load() < t.max) && !t.closed.Load()
}

// Result is the outcome of adding a flow.
type Result uint8

const (
	Added  Result = iota // the flow was added
	Exists               // an existing flow took precedence
	Full                 // the limit or the backlog refused the flow
	Closed               // the table is closed
)

func (t *Table[K, P, S]) keyShard(k K) (int, P) {
	if t.peer != nil {
		p := t.peer(k)
		return t.peerShard(p), p
	}
	var p P
	return int(t.hashKey(t.seed, k) % tableShards), p
}

func (t *Table[K, P, S]) peerShard(p P) int {
	return int(t.hashPeer(t.seed, p) % tableShards)
}

// Add registers s under k and, with backlog, queues it for Accept.
func (t *Table[K, P, S]) Add(k K, s S, backlog bool) (S, Result) {
	return t.add(k, s, backlog, nil)
}

// AddOrBind looks up k, then binds a peer's unbound flow if prepare is
// supplied, then tries to add s to the backlog. It returns Exists when
// either lookup or binding found the flow. See Resolve for prepare.
func (t *Table[K, P, S]) AddOrBind(k K, s S, prepare func(S)) (S, Result) {
	return t.add(k, s, true, prepare)
}

func (t *Table[K, P, S]) add(k K, s S, backlog bool, prepare func(S)) (S, Result) {
	var zero S
	if t.accept == nil {
		return zero, Closed
	}
	i, p := t.keyShard(k)
	shard := &t.shards[i]
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if t.closed.Load() {
		return zero, Closed
	}
	if other, ok := t.Get(k); ok {
		return other, Exists
	}
	if prepare != nil {
		if bound := t.bind(shard, p, k, prepare); bound != zero {
			return bound, Exists
		}
	}
	if !t.takeSlot() {
		return zero, Full
	}
	if backlog {
		// The receiver takes the shard lock before using s. Reserve the
		// backlog entry first so Get never sees a flow that was refused.
		select {
		case t.accept <- acceptedFlow[P, S]{s, shard}:
		default:
			t.n.Add(-1)
			return zero, Full
		}
	}
	if t.peer != nil {
		flows := shard.peers[p]
		flows.count++
		shard.setPeer(p, flows)
	}
	t.register(i, p, k, s, true)
	t.conns.Store(k, s)
	return s, Added
}

func (t *Table[K, P, S]) takeSlot() bool {
	if n := t.n.Add(1); t.max > 0 && n > t.max {
		t.n.Add(-1)
		return false
	}
	return true
}

func (shard *tableShard[P, S]) setPeer(p P, flows peerFlows[S]) {
	if flows.count == 0 {
		delete(shard.peers, p)
		return
	}
	if shard.peers == nil {
		shard.peers = make(map[P]peerFlows[S])
	}
	shard.peers[p] = flows
}

// AddUnbound registers a flow that does not have a primary key yet. It
// succeeds only if p has no flows. An unbound flow holds a slot and is not
// delivered by Accept. A table without a peer index refuses it with Closed.
func (t *Table[K, P, S]) AddUnbound(p P, s S) (S, Result) {
	var zero S
	if t.accept == nil || t.peer == nil {
		return zero, Closed
	}
	i := t.peerShard(p)
	shard := &t.shards[i]
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if t.closed.Load() {
		return zero, Closed
	}
	if flows := shard.peers[p]; flows.count != 0 {
		return flows.unbound, Exists
	}
	if !t.takeSlot() {
		return zero, Full
	}
	shard.setPeer(p, peerFlows[S]{count: 1, unbound: s})
	var k K
	t.register(i, p, k, s, false)
	return s, Added
}

// Resolve returns the flow under k, or binds a peer's unbound flow to k.
// prepare configures that flow before it becomes visible under k. It runs
// under the shard lock and must be an internal operation that does not call
// back into the table or any user code.
func (t *Table[K, P, S]) Resolve(k K, prepare func(S)) S {
	var zero S
	if t.accept == nil {
		return zero
	}
	i, p := t.keyShard(k)
	shard := &t.shards[i]
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if t.closed.Load() {
		return zero
	}
	if other, ok := t.Get(k); ok {
		return other
	}
	return t.bind(shard, p, k, prepare)
}

func (t *Table[K, P, S]) bind(shard *tableShard[P, S], p P, k K, prepare func(S)) S {
	var zero S
	flows := shard.peers[p]
	s := flows.unbound
	if s == zero || prepare == nil {
		return zero
	}
	prepare(s)
	m := t.membership(s)
	m.key, m.bound = k, true
	flows.unbound = zero
	shard.peers[p] = flows
	t.conns.Store(k, s)
	return s
}

// register records membership and adds the flow to the idle wheel. The
// caller holds the shard lock until the registration is fully published.
func (t *Table[K, P, S]) register(i int, p P, k K, s S, bound bool) {
	m := t.membership(s)
	m.key, m.peer, m.bound = k, p, bound
	m.shard.Store(uint32(i + 1))
	if w := t.wheel.Load(); w != nil {
		w.add(i, s)
	}
}

// Remove removes s whether it has a primary key or is awaiting one.
// The registration record identifies its shard, peer and current key.
func (t *Table[K, P, S]) Remove(s S) {
	if t.accept == nil {
		return
	}
	m := t.membership(s)
	registered := m.shard.Load()
	if registered == 0 {
		return
	}
	i := int(registered - 1)
	shard := &t.shards[i]
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if m.shard.Load() != registered {
		return
	}

	if m.bound {
		t.conns.CompareAndDelete(m.key, s)
	}
	if t.peer != nil {
		flows := shard.peers[m.peer]
		if !m.bound {
			var zero S
			flows.unbound = zero
		}
		flows.count--
		shard.setPeer(m.peer, flows)
	}
	t.n.Add(-1)
	if w := t.wheel.Load(); w != nil {
		w.remove(i, s)
	}
	var key K
	var peer P
	m.key, m.peer, m.bound = key, peer, false
	m.shard.Store(0)
}

// Accept waits for a new flow, skipping any closed meanwhile. It returns
// net.ErrClosed once the table is closed.
func (t *Table[K, P, S]) Accept() (S, error) {
	var zero S
	t.lazy()
	for {
		select {
		case <-t.done:
			return zero, net.ErrClosed
		default:
		}
		select {
		case entry := <-t.accept:
			entry.shard.mu.Lock()
			closed := t.closed.Load()
			entry.shard.mu.Unlock()
			s := entry.flow
			if closed {
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

// Close refuses new flows, stops the idle timeout and shuts down all flows
// with err for reads. Calls after the first do nothing.
func (t *Table[K, P, S]) Close(err error) {
	t.lazy()
	if !t.closed.CompareAndSwap(false, true) {
		return
	}
	close(t.done)
	t.idleMu.Lock()
	if w := t.wheel.Swap(nil); w != nil {
		w.stop()
	}
	t.idleMu.Unlock()

	// Taking each shard in turn finishes any registrations or bindings
	// that began before closed was set. Then a walk of the primary map
	// can see every bound flow.
	var unbound []S
	var zero S
	for i := range t.shards {
		shard := &t.shards[i]
		shard.mu.Lock()
		for _, flows := range shard.peers {
			if flows.unbound != zero {
				unbound = append(unbound, flows.unbound)
			}
		}
		shard.mu.Unlock()
		for _, s := range unbound {
			t.shutdown(s, err)
		}
		clear(unbound)
		unbound = unbound[:0]
	}
	t.conns.Range(func(_, v any) bool {
		t.shutdown(v.(S), err)
		return true
	})
	for {
		select {
		case entry := <-t.accept:
			t.shutdown(entry.flow, err)
		default:
			return
		}
	}
}

// Done returns a channel that Close closes.
func (t *Table[K, P, S]) Done() <-chan struct{} {
	t.lazy()
	return t.done
}

// Len returns the number of flows held, including unbound flows.
func (t *Table[K, P, S]) Len() int { return int(t.n.Load()) }

// Pending returns the number of flows waiting for Accept.
func (t *Table[K, P, S]) Pending() int { return len(t.accept) }

// wheelSlots covers a timeout and a tick, with margin for rounding.
const wheelSlots = 8

// idleWheel uses one timer for all partitions. Registration and removal take
// only their partition lock, and activity updates only the queue's atomic
// timestamp. A flow keeps its position so removal takes constant time.
type idleWheel[S comparable] struct {
	shutdown func(S, error)
	queue    func(S) *dgram.Queue
	position func(S) *wheelPosition
	epoch    *clock.Epoch
	timer    timeshim.Timer
	inflight sync.WaitGroup
	mu       sync.Mutex // serializes ticks and configuration changes
	// Configuration writes also hold every partition lock. Flow
	// mutations read it under their own partition lock.
	d       time.Duration
	every   time.Duration
	stopped bool
	parts   [tableShards]wheelPartition[S]
}

type wheelPartition[S comparable] struct {
	mu    sync.Mutex
	slots [wheelSlots][]S
	cur   int // the last tick
}

func newIdleWheel[K, P, S comparable](t *Table[K, P, S], d time.Duration, e *clock.Epoch) *idleWheel[S] {
	if e == nil {
		e = clock.RealEpoch
	}
	w := &idleWheel[S]{
		shutdown: t.shutdown, queue: t.queue,
		position: func(s S) *wheelPosition { return &t.membership(s).wheel },
		epoch:    e, d: d, every: wheelInterval(d),
	}
	w.mu.Lock()
	w.timer = e.Clock().AfterFunc(w.every, w.tick)
	w.mu.Unlock()
	return w
}

func wheelInterval(d time.Duration) time.Duration { return max(d/4, 10*time.Millisecond) }

func (w *idleWheel[S]) add(shard int, s S) {
	p := &w.parts[shard]
	p.mu.Lock()
	if !w.stopped {
		if !w.queue(s).Closed() && w.position(s).slot == 0 {
			w.place(p, s, w.d)
		}
	}
	p.mu.Unlock()
}

func (w *idleWheel[S]) remove(shard int, s S) {
	p := &w.parts[shard]
	p.mu.Lock()
	defer p.mu.Unlock()
	if w.stopped {
		return
	}
	q := w.position(s)
	if q.slot == 0 {
		return
	}
	slot := &p.slots[q.slot-1]
	last := len(*slot) - 1
	if i := int(q.pos); i != last {
		moved := (*slot)[last]
		(*slot)[i] = moved
		w.position(moved).pos = int32(i)
	}
	var zero S
	(*slot)[last] = zero
	*slot = (*slot)[:last]
	q.slot, q.pos = 0, 0
}

// place needs the partition's lock.
func (w *idleWheel[S]) place(p *wheelPartition[S], s S, in time.Duration) {
	ticks := in / w.every
	if in%w.every > 0 {
		ticks++
	}
	i := (p.cur + int(min(max(ticks, 1), wheelSlots-1))) % wheelSlots
	q := w.position(s)
	q.slot, q.pos = int32(i+1), int32(len(p.slots[i]))
	p.slots[i] = append(p.slots[i], s)
}

func (w *idleWheel[S]) left(s S, now int64) time.Duration {
	if active, accepted := w.queue(s).Activity(); accepted {
		return w.d - time.Duration(now-active)
	}
	return w.d // flows waiting for Accept are spared
}

func (w *idleWheel[S]) tick() {
	w.mu.Lock()
	if w.stopped {
		w.mu.Unlock()
		return
	}
	now := w.epoch.Now()
	var idle []S
	var zero S
	for i := range w.parts {
		p := &w.parts[i]
		p.mu.Lock()
		p.cur = (p.cur + 1) % wheelSlots
		due := p.slots[p.cur]
		p.slots[p.cur] = nil
		for j, s := range due {
			due[j] = zero
			q := w.position(s)
			q.slot, q.pos = 0, 0
			if left := w.left(s, now); left > 0 {
				w.place(p, s, left)
			} else {
				idle = append(idle, s)
			}
		}
		if cap(due) <= 64 || len(due) >= cap(due)/4 {
			p.slots[p.cur] = due[:0]
		}
		p.mu.Unlock()
	}
	w.timer.Reset(w.every)
	w.inflight.Add(1)
	w.mu.Unlock()
	defer w.inflight.Done()
	for _, s := range idle {
		w.shutdown(s, io.EOF)
	}
}

// lockAll takes every partition lock to publish a single configuration
// for subsequent adds, removes and checks.
func (w *idleWheel[S]) lockAll() {
	w.mu.Lock()
	for i := range w.parts {
		w.parts[i].mu.Lock()
	}
}

func (w *idleWheel[S]) unlockAll() {
	for i := range w.parts {
		w.parts[i].mu.Unlock()
	}
	w.mu.Unlock()
}

func (w *idleWheel[S]) setTimeout(d time.Duration) {
	w.lockAll()
	defer w.unlockAll()
	w.d, w.every = d, wheelInterval(d)
	now := w.epoch.Now()
	for i := range w.parts {
		p := &w.parts[i]
		old := p.slots
		clear(p.slots[:])
		for _, slot := range old {
			for _, s := range slot {
				w.place(p, s, w.left(s, now))
			}
		}
	}
	w.timer.Reset(w.every)
}

func (w *idleWheel[S]) stop() {
	w.lockAll()
	w.stopped = true
	for i := range w.parts {
		p := &w.parts[i]
		for _, slot := range p.slots {
			for _, s := range slot {
				q := w.position(s)
				q.slot, q.pos = 0, 0
			}
		}
		clear(p.slots[:])
	}
	w.unlockAll()
	w.timer.Stop()
	w.inflight.Wait()
}
