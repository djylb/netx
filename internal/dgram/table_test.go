package dgram

import (
	"testing"
	"time"

	"github.com/djylb/timeshim"
)

type wheelConn struct {
	q    Queue
	key  int
	tab  *Table[int, *wheelConn]
	free bool // the wheel's lock was free while it was shut down
}

func newWheelTable(t *testing.T, clock *timeshim.Fake, onShutdown func(*wheelConn)) *Table[int, *wheelConn] {
	t.Helper()
	tab := new(Table[int, *wheelConn])
	tab.Init(TableOptions[*wheelConn]{
		Queue: func(c *wheelConn) *Queue { return &c.q },
		Shutdown: func(c *wheelConn, err error) {
			if onShutdown != nil {
				onShutdown(c)
			}
			tab.Remove(c.key, c)
			if !c.q.Closed() {
				c.q.Close(err)
			}
		},
		Epoch: NewEpoch(clock), Backlog: 1, Idle: time.Minute,
	})
	t.Cleanup(func() { tab.Close(nil) })
	return tab
}

func addWheelConn(t *testing.T, tab *Table[int, *wheelConn], clock *timeshim.Fake, key int) *wheelConn {
	t.Helper()
	c := &wheelConn{key: key, tab: tab}
	c.q.Init(4, tab.wheel.epoch)
	c.q.Accepted()
	if _, res := tab.Add(key, c, false); res != Added {
		t.Fatalf("Add = %v", res)
	}
	return c
}

func wheelLen(tab *Table[int, *wheelConn]) int {
	tab.wheel.mu.Lock()
	defer tab.wheel.mu.Unlock()
	n := 0
	for _, s := range tab.wheel.slots {
		n += len(s)
	}
	return n
}

// A connection removed from the table leaves the wheel at once, and the
// others keep their places.
func TestWheelRemoveUnlinks(t *testing.T) {
	clock := timeshim.NewFake(time.Unix(1000, 0))
	tab := newWheelTable(t, clock, nil)
	conns := make([]*wheelConn, 5)
	for i := range conns {
		conns[i] = addWheelConn(t, tab, clock, i)
	}
	tab.Remove(1, conns[1])
	tab.Remove(4, conns[4])
	if n := wheelLen(tab); n != 3 {
		t.Fatalf("wheel holds %d connections, want 3", n)
	}
	for _, i := range []int{1, 4} {
		if conns[i].q.wheelSlot != 0 {
			t.Fatalf("removed connection %d still has a wheel place", i)
		}
	}
	tab.wheel.mu.Lock()
	for si, slot := range tab.wheel.slots {
		for pos, c := range slot {
			if int(c.q.wheelSlot) != si+1 || int(c.q.wheelPos) != pos {
				t.Errorf("connection %d at slot %d/%d records %d/%d", c.key, si, pos, c.q.wheelSlot-1, c.q.wheelPos)
			}
		}
	}
	tab.wheel.mu.Unlock()
	clock.Advance(2 * time.Minute)
	for _, i := range []int{0, 2, 3} {
		if !conns[i].q.Closed() {
			t.Fatalf("idle connection %d was not shut down", i)
		}
	}
}

// Idle connections are shut down without the wheel's lock, so that adds
// and removes are not held up by them.
func TestWheelShutsDownOutsideLock(t *testing.T) {
	clock := timeshim.NewFake(time.Unix(1000, 0))
	var tab *Table[int, *wheelConn]
	tab = newWheelTable(t, clock, func(c *wheelConn) {
		if tab.wheel.mu.TryLock() {
			c.free = true
			tab.wheel.mu.Unlock()
		}
	})
	c := addWheelConn(t, tab, clock, 1)
	clock.Advance(2 * time.Minute)
	if !c.q.Closed() {
		t.Fatal("the idle connection was not shut down")
	}
	if !c.free {
		t.Fatal("the idle connection was shut down while the wheel was locked")
	}
}

// The ring grows to the bound, which need not be a power of two, and no
// further.
func TestQueueRingKeepsToBound(t *testing.T) {
	q := newQueue(100)
	for range 150 {
		q.Enqueue([]byte("x"))
	}
	if q.Len() != 100 || len(q.ring) != 100 {
		t.Fatalf("Len %d, ring %d, want 100 and 100", q.Len(), len(q.ring))
	}
}
