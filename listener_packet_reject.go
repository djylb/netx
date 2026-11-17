package netx

import (
	"sync"
	"time"

	"github.com/djylb/netx/internal/dgram"
)

// rejectCache remembers the peers given to PacketListener.RejectPeer, each
// until its time to live passes, in two generations: when the newer one
// holds half the size, it becomes the older one, and the older one is
// dropped, so that the cache holds at most size peers, grows with those it
// has and takes no time to evict. A nil cache remembers nothing.
type rejectCache struct {
	epoch *dgram.Epoch
	cur   map[peerKey]int64 // peer → epoch time it expires
	old   map[peerKey]int64
	ttl   int64
	half  int  // the most peers of a generation
	keep  bool // whether a full generation is kept as the older one
	mu    sync.Mutex
}

func newRejectCache(size int, ttl time.Duration, e *dgram.Epoch) *rejectCache {
	// A size of one has a single generation, so that it holds one peer.
	return &rejectCache{epoch: e, ttl: int64(ttl), half: max(size/2, 1), keep: size > 1}
}

// has reports whether k was rejected within its time to live.
func (c *rejectCache) has(k peerKey) bool {
	if c == nil {
		return false
	}
	now := c.epoch.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if exp, ok := c.cur[k]; ok {
		return now < exp
	}
	exp, ok := c.old[k]
	return ok && now < exp
}

// add remembers that k was rejected now.
func (c *rejectCache) add(k peerKey) {
	if c == nil {
		return
	}
	exp := c.epoch.Now() + c.ttl
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.cur[k]; !ok && len(c.cur) >= c.half {
		c.old = nil
		if c.keep {
			c.old = c.cur
		}
		c.cur = nil
	}
	if c.cur == nil {
		c.cur = make(map[peerKey]int64)
	}
	c.cur[k] = exp
}
