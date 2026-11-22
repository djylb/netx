package clock

import (
	"testing"
	"time"

	"github.com/djylb/timeshim"
)

func TestIdleWaitAndExpiry(t *testing.T) {
	const timeout = time.Second
	c := timeshim.NewFake(time.Time{})
	var idle Idle
	idle.Init(timeout, c)
	defer idle.End()

	expired := 0
	idle.Start(func() {
		expired++
		if !idle.mu.TryLock() {
			t.Error("expiration callback ran under the timer lock")
			return
		}
		idle.mu.Unlock()
		idle.End()
	})
	idle.BeginWait()
	c.Advance(3 * timeout)
	if expired != 0 {
		t.Fatal("idle timer expired while waiting")
	}
	idle.EndWait()
	c.Advance(timeout - time.Nanosecond)
	if expired != 0 {
		t.Fatal("idle timer expired before a full idle interval")
	}
	c.Advance(time.Nanosecond)
	if expired != 1 || c.Pending() != 0 {
		t.Fatalf("expired %d times with %d timers pending", expired, c.Pending())
	}
}

func TestIdleStartsOnce(t *testing.T) {
	const timeout = time.Second
	c := timeshim.NewFake(time.Time{})
	var idle Idle
	idle.Init(timeout, c)
	defer idle.End()

	expired := 0
	idle.Start(func() { expired++ })
	unexpected := func() { t.Error("later Start installed a callback") }
	idle.Start(unexpected)
	if pending := c.Pending(); pending != 1 {
		t.Fatalf("timers pending after repeated Start = %d, want 1", pending)
	}
	c.Advance(timeout)
	idle.Start(unexpected)
	if pending := c.Pending(); expired != 1 || pending != 0 {
		t.Fatalf("expired %d times with %d timers pending, want 1 and 0", expired, pending)
	}
}

func TestIdleEndPreventsStart(t *testing.T) {
	const timeout = time.Second
	for _, arm := range []bool{false, true} {
		c := timeshim.NewFake(time.Time{})
		var idle Idle
		idle.Init(timeout, c)
		unexpected := func() { t.Error("callback ran after End") }
		if arm {
			idle.Start(unexpected)
		}
		idle.End()
		idle.Start(unexpected)
		if pending := c.Pending(); pending != 0 {
			t.Errorf("timers pending after End = %d, want 0 (started before End: %v)", pending, arm)
		}
		c.Advance(timeout)
		idle.End()
	}
}
