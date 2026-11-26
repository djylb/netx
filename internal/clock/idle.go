package clock

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/timeshim"
)

// Idle runs a callback once activity has stopped for a given duration.
// After Init, its other methods are safe to call concurrently.
type Idle struct {
	epoch    Epoch
	timer    timeshim.Timer // nil after End or expiry
	timeout  time.Duration
	activity atomic.Int64
	mu       sync.Mutex
	waiting  atomic.Int32
	used     bool // protected by mu
}

// Init sets up a zero Idle with timeout d, which must be positive.
// Call Start to arm it.
func (i *Idle) Init(d time.Duration, c timeshim.Clock) {
	i.epoch = *NewEpoch(c)
	i.timeout = d
	i.Touch()
}

// Touch records activity.
func (i *Idle) Touch() { i.epoch.Touch(&i.activity) }

// BeginWait begins an operation during which the timer must not expire.
func (i *Idle) BeginWait() { i.waiting.Add(1) }

// EndWait ends one operation started by BeginWait and records activity.
func (i *Idle) EndWait() {
	i.Touch()
	i.waiting.Add(-1)
}

// Start arms the timer on its first call. Later calls and calls after End
// have no effect. On expiry it calls expire outside the lock.
func (i *Idle) Start(expire func()) {
	i.mu.Lock()
	if !i.used {
		i.used = true
		i.timer = i.epoch.Clock().AfterFunc(i.timeout, func() { i.check(expire) })
	}
	i.mu.Unlock()
}

func (i *Idle) check(expire func()) {
	i.mu.Lock()
	if i.timer == nil {
		i.mu.Unlock()
		return
	}
	left := i.timeout
	// Load waiting first so that if the final EndWait just decremented
	// it to zero, the activity load also sees that wait's Touch.
	if i.waiting.Load() == 0 {
		left = time.Duration(i.activity.Load() + int64(i.timeout) - i.epoch.Now())
	}
	if left > 0 {
		i.timer.Reset(left)
		i.mu.Unlock()
		return
	}
	i.timer = nil
	i.mu.Unlock()
	expire()
}

// End disarms the timer and prevents Start from arming it again. A callback
// that has already expired may still run.
func (i *Idle) End() {
	i.mu.Lock()
	i.used = true
	timer := i.timer
	i.timer = nil
	i.mu.Unlock()
	if timer != nil {
		timer.Stop()
	}
}
