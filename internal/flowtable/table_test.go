package flowtable

import (
	"errors"
	"hash/maphash"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/djylb/netx/internal/clock"
	"github.com/djylb/netx/internal/dgram"
	"github.com/djylb/timeshim"
)

type wheelConn struct {
	member Membership[int, struct{}]
	q      dgram.Queue
	key    int
	free   bool // the wheel's lock was free while it was shut down
}

func hashInt(_ maphash.Seed, i int) uint64 { return uint64(i) }

func newWheelTable(t *testing.T, fake *timeshim.Fake, onShutdown func(*wheelConn)) *Table[int, struct{}, *wheelConn] {
	t.Helper()
	return newIdleTable(t, fake, onShutdown, time.Minute)
}

func newIdleTable(t *testing.T, fake *timeshim.Fake, onShutdown func(*wheelConn), idle time.Duration) *Table[int, struct{}, *wheelConn] {
	t.Helper()
	tab := new(Table[int, struct{}, *wheelConn])
	tab.Init(TableOptions[int, struct{}, *wheelConn]{
		Queue:      func(c *wheelConn) *dgram.Queue { return &c.q },
		Membership: func(c *wheelConn) *Membership[int, struct{}] { return &c.member },
		HashKey:    hashInt,
		Shutdown: func(c *wheelConn, err error) {
			if onShutdown != nil {
				onShutdown(c)
			}
			tab.Remove(c)
			if !c.q.Closed() {
				c.q.Close(err)
			}
		},
		Epoch: clock.NewEpoch(fake), Backlog: 1, Idle: idle,
	})
	t.Cleanup(func() { tab.Close(nil) })
	return tab
}

func addWheelConn(t *testing.T, tab *Table[int, struct{}, *wheelConn], key int) *wheelConn {
	t.Helper()
	c := &wheelConn{key: key}
	c.q.Init(4, tab.epoch)
	c.q.Accepted()
	if _, res := tab.Add(key, c, false); res != Added {
		t.Fatalf("Add = %v", res)
	}
	return c
}

func wheelLen(tab *Table[int, struct{}, *wheelConn]) int {
	w := tab.wheel.Load()
	w.lockAll()
	defer w.unlockAll()
	n := 0
	for i := range w.parts {
		for _, slot := range w.parts[i].slots {
			n += len(slot)
		}
	}
	return n
}

// A connection removed from the table leaves the wheel at once, and the
// others keep their places.
func TestWheelRemoveUnlinks(t *testing.T) {
	fake := timeshim.NewFake(time.Unix(1000, 0))
	tab := newWheelTable(t, fake, nil)
	conns := make([]*wheelConn, 5)
	for i := range conns {
		conns[i] = addWheelConn(t, tab, i)
	}
	tab.Remove(conns[1])
	tab.Remove(conns[4])
	if n := wheelLen(tab); n != 3 {
		t.Fatalf("wheel holds %d connections, want 3", n)
	}
	for _, i := range []int{1, 4} {
		if conns[i].member.wheel.slot != 0 {
			t.Fatalf("removed connection %d still has a wheel place", i)
		}
	}
	w := tab.wheel.Load()
	w.lockAll()
	for i := range w.parts {
		for si, slot := range w.parts[i].slots {
			for pos, c := range slot {
				if int(c.member.wheel.slot) != si+1 || int(c.member.wheel.pos) != pos {
					t.Errorf("connection %d at slot %d/%d records %d/%d", c.key, si, pos, c.member.wheel.slot-1, c.member.wheel.pos)
				}
			}
		}
	}
	w.unlockAll()
	fake.Advance(2 * time.Minute)
	for _, i := range []int{0, 2, 3} {
		if !conns[i].q.Closed() {
			t.Fatalf("idle connection %d was not shut down", i)
		}
	}
}

// Idle connections are shut down without the wheel's lock, so that adds
// and removes are not held up by them.
func TestWheelShutsDownOutsideLock(t *testing.T) {
	fake := timeshim.NewFake(time.Unix(1000, 0))
	var tab *Table[int, struct{}, *wheelConn]
	tab = newWheelTable(t, fake, func(c *wheelConn) {
		if tab.wheel.Load().mu.TryLock() {
			c.free = true
			tab.wheel.Load().mu.Unlock()
		}
	})
	c := addWheelConn(t, tab, 1)
	fake.Advance(2 * time.Minute)
	if !c.q.Closed() {
		t.Fatal("the idle connection was not shut down")
	}
	if !c.free {
		t.Fatal("the idle connection was shut down while the wheel was locked")
	}
}

// SetIdle changes the idle timeout of the connections held: a shorter one
// closes them by it, one set on a table without any starts it, a
// non-positive one keeps them.
func TestSetIdleHot(t *testing.T) {
	fake := timeshim.NewFake(time.Unix(1000, 0))
	tab := newWheelTable(t, fake, nil)
	c := addWheelConn(t, tab, 1)
	tab.SetIdle(8 * time.Second)
	fake.Advance(12 * time.Second)
	if !c.q.Closed() {
		t.Fatal("the shorter idle timeout did not apply to a held connection")
	}

	none := newIdleTable(t, fake, nil, 0)
	c = addWheelConn(t, none, 1)
	none.SetIdle(8 * time.Second)
	fake.Advance(12 * time.Second)
	if !c.q.Closed() {
		t.Fatal("an idle timeout set later did not apply to a held connection")
	}

	off := newWheelTable(t, fake, nil)
	c = addWheelConn(t, off, 1)
	off.SetIdle(0)
	fake.Advance(3 * time.Minute)
	if c.q.Closed() {
		t.Fatal("a connection closed after the idle timeout was turned off")
	}
}

type indexedKey struct{ peer, dst int }

type indexedConn struct {
	member   Membership[indexedKey, int]
	once     sync.Once
	q        dgram.Queue
	prepared bool
}

func newIndexedTable(t *testing.T, epoch *clock.Epoch) *Table[indexedKey, int, *indexedConn] {
	t.Helper()
	var table Table[indexedKey, int, *indexedConn]
	table.Init(TableOptions[indexedKey, int, *indexedConn]{
		Peer:       func(k indexedKey) int { return k.peer },
		HashPeer:   hashInt,
		Membership: func(c *indexedConn) *Membership[indexedKey, int] { return &c.member },
		Queue:      func(c *indexedConn) *dgram.Queue { return &c.q },
		Shutdown: func(c *indexedConn, err error) {
			c.once.Do(func() {
				table.Remove(c)
				c.q.Close(err)
			})
		},
		Backlog: 1, Limit: 2, Epoch: epoch,
	})
	t.Cleanup(func() { table.Close(net.ErrClosed) })
	return &table
}

func newIndexedConn(epoch *clock.Epoch) *indexedConn {
	c := &indexedConn{}
	c.q.Init(2, epoch)
	return c
}

func TestTableBindKeepsOneSlotAndIndexesAllDestinations(t *testing.T) {
	table := newIndexedTable(t, nil)
	dial := newIndexedConn(nil)
	k, other := indexedKey{1, 1}, indexedKey{1, 2}
	if _, res := table.AddUnbound(k.peer, dial); res != Added {
		t.Fatalf("AddUnbound = %v", res)
	}
	group := newIndexedConn(nil)
	if _, res := table.Add(other, group, true); res != Added {
		t.Fatalf("Add = %v", res)
	}
	if table.Room() {
		t.Fatal("full table reports room")
	}
	got, res := table.AddOrBind(k, newIndexedConn(nil), func(c *indexedConn) { c.prepared = true })
	if got != dial || res != Exists || table.Len() != 2 || table.Pending() != 1 {
		t.Fatalf("bind = %p, %v, len %d, backlog %d", got, res, table.Len(), table.Pending())
	}
	if got, ok := table.Get(k); !ok || got != dial || !got.prepared {
		t.Fatal("bound flow not fully published under the primary key")
	}
	table.shutdown(dial, net.ErrClosed)
	if _, res := table.AddUnbound(k.peer, newIndexedConn(nil)); res != Exists {
		t.Fatalf("Dial with another destination still open = %v", res)
	}
	table.shutdown(group, net.ErrClosed)
	if _, ok := table.Get(k); ok || table.Len() != 0 {
		t.Fatal("closed flow still registered")
	}
	replacement := newIndexedConn(nil)
	if _, res := table.AddUnbound(k.peer, replacement); res != Added {
		t.Fatalf("Dial after removing all destinations = %v", res)
	}
	table.Close(net.ErrClosed)
	if !replacement.q.Closed() || table.Pending() != 0 || table.Len() != 0 {
		t.Fatal("Close did not drain unbound flow and backlog")
	}
}

func TestTableExpireUnboundAndReusePeer(t *testing.T) {
	fake := timeshim.NewFake(time.Time{})
	epoch := clock.NewEpoch(fake)
	table := newIndexedTable(t, epoch)
	dial := newIndexedConn(epoch)
	dial.q.Accepted()
	table.AddUnbound(1, dial)
	table.SetIdle(time.Minute)
	fake.Advance(2 * time.Minute)
	if !dial.q.Closed() {
		t.Fatal("unbound Dial survived the idle timeout")
	}
	if _, err := dial.q.Read(nil); !errors.Is(err, io.EOF) {
		t.Fatalf("idle Dial read = %v", err)
	}
	if _, res := table.AddUnbound(1, newIndexedConn(epoch)); res != Added {
		t.Fatalf("AddUnbound after expiration = %v", res)
	}
}

func TestTableCloseDuringBind(t *testing.T) {
	table := newIndexedTable(t, nil)
	dial := newIndexedConn(nil)
	table.AddUnbound(1, dial)
	entered, finish, bound := make(chan struct{}), make(chan struct{}), make(chan *indexedConn, 1)
	go func() {
		bound <- table.Resolve(indexedKey{1, 1}, func(*indexedConn) {
			close(entered)
			<-finish
		})
	}()
	<-entered
	closed := make(chan struct{})
	go func() {
		table.Close(net.ErrClosed)
		close(closed)
	}()
	<-table.Done()
	close(finish)
	<-closed
	if <-bound != dial || !dial.q.Closed() || table.Len() != 0 {
		t.Fatal("Close lost a flow that was being bound")
	}
}

func TestZeroTable(t *testing.T) {
	var table Table[indexedKey, int, *indexedConn]
	key := indexedKey{peer: 1, dst: 1}
	if _, result := table.Add(key, nil, false); result != Closed {
		t.Fatalf("Add result = %v, want Closed", result)
	}
	if _, result := table.AddUnbound(key.peer, nil); result != Closed {
		t.Fatalf("AddUnbound result = %v, want Closed", result)
	}
	if got := table.Resolve(key, nil); got != nil {
		t.Fatal("zero table resolved a flow")
	}
	table.Remove(nil)
	table.SetIdle(time.Minute)
	if table.Room() || table.wheel.Load() != nil {
		t.Fatal("zero table has room or an idle timer")
	}
	table.Close(net.ErrClosed)
	if _, err := table.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after Close = %v", err)
	}
}
