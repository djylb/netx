package memnet

import (
	"math"
	"math/bits"
	"math/rand/v2"
	"net"
	"os"
	"sync"
	"time"

	"github.com/djylb/timeshim"
)

// Link describes the properties of traffic in one direction to or from an
// address of a Net.
type Link struct {
	Delay time.Duration // added before every write or datagram
	Loss  float64       // datagram drop probability in [0, 1]; streams stay reliable
	Rate  int64         // bytes per second; 0 = unlimited
	Off   bool          // disconnected: dials refused, datagrams dropped, open connections closed
}

func (l Link) zero() bool { return l == Link{} }

// LinkPair describes traffic in both directions for one address: To towards
// it (the dialer's writes), From out of it (the listener's writes).
type LinkPair struct {
	To, From Link
}

type faults struct {
	links map[string]LinkPair
	conns map[string]map[*faultConn]struct{}
	mu    sync.Mutex
}

// SetLink sets the link properties of addr (a listener or packet
// endpoint); a zero pair clears them. Turning a direction Off closes the
// open connections to addr. Delays and rates run on n.Clock (a fake clock
// moves them only when it advances) and losses draw from n.Rand.
func (n *Net) SetLink(addr string, p LinkPair) {
	f := &n.faults
	f.mu.Lock()
	if f.links == nil {
		f.links = map[string]LinkPair{}
	}
	if p.To.zero() && p.From.zero() {
		delete(f.links, addr)
	} else {
		f.links[addr] = p
	}
	var cut []*faultConn
	if p.To.Off || p.From.Off {
		for c := range f.conns[addr] {
			cut = append(cut, c)
		}
	}
	f.mu.Unlock()
	for _, c := range cut {
		_ = c.Close()
	}
}

// LinkOf returns the link properties of addr.
func (n *Net) LinkOf(addr string) LinkPair {
	n.faults.mu.Lock()
	defer n.faults.mu.Unlock()
	return n.faults.links[addr]
}

// lose draws a datagram loss.
func (n *Net) lose(p float64) bool {
	if p <= 0 {
		return false
	}
	if p >= 1 {
		return true
	}
	if n.Rand == nil {
		return rand.Float64() < p //nolint:gosec // simulated loss, not a secret: a seeded Net.Rand replaces it
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.Rand.Float64() < p
}

// transmission is the time taken to serialize size bytes.
func transmission(size int, rate int64) time.Duration {
	if rate <= 0 {
		return 0
	}
	hi, lo := bits.Mul64(uint64(size), uint64(time.Second))
	if hi >= uint64(rate) {
		return math.MaxInt64
	}
	ns, _ := bits.Div64(hi, lo, uint64(rate))
	return time.Duration(min(ns, math.MaxInt64))
}

// addDelay combines nonnegative link waits, saturating at the longest timer.
func addDelay(a, b time.Duration) time.Duration {
	a, b = max(0, a), max(0, b)
	return a + min(b, math.MaxInt64-a)
}

// faultConn is one end of a stream connection to addr; to is true for
// the dialer's end (its writes go towards addr).
type faultConn struct {
	*halfConn
	n    *Net
	done chan struct{}
	// local and remote are the addresses of a DialFrom connection (nil:
	// the halfConn's "pipe").
	local, remote net.Addr
	addr          string
	port          string // local DialFrom port owned until Close
	once          sync.Once
	to            bool
}

func (c *faultConn) LocalAddr() net.Addr {
	if c.local != nil {
		return c.local
	}
	return c.halfConn.LocalAddr()
}

func (c *faultConn) RemoteAddr() net.Addr {
	if c.remote != nil {
		return c.remote
	}
	return c.halfConn.RemoteAddr()
}

func (n *Net) track(c *halfConn, addr string, to bool, local, remote net.Addr, port string) *faultConn {
	fc := &faultConn{halfConn: c, n: n, addr: addr, to: to, local: local, remote: remote, port: port, done: make(chan struct{})}
	f := &n.faults
	f.mu.Lock()
	if f.conns == nil {
		f.conns = map[string]map[*faultConn]struct{}{}
	}
	if f.conns[addr] == nil {
		f.conns[addr] = map[*faultConn]struct{}{}
	}
	f.conns[addr][fc] = struct{}{}
	f.mu.Unlock()
	return fc
}

func (c *faultConn) link() Link {
	p := c.n.LinkOf(c.addr)
	if c.to {
		return p.To
	}
	return p.From
}

func (c *faultConn) Write(b []byte) (int, error) {
	l := c.link()
	if l.Off {
		return 0, net.ErrClosed
	}
	if delay := addDelay(l.Delay, transmission(len(b), l.Rate)); delay > 0 {
		timer := timeshim.NewTimer(timeshim.Or(c.n.Clock), delay)
		defer timer.Stop()
		for {
			deadline, moved := c.w.wdl.snapshot()
			ready, closed := false, false
			if waitDeadline(deadline, func(timeout <-chan time.Time) bool {
				select {
				case <-timer.C:
					ready = true
				case <-c.done:
					closed = true
				case <-moved:
				case <-timeout:
					return true
				}
				return false
			}) {
				return 0, os.ErrDeadlineExceeded
			}
			if closed {
				return 0, net.ErrClosed
			}
			if ready {
				break
			}
		}
	}
	return c.halfConn.Write(b)
}

func (c *faultConn) Close() error {
	c.once.Do(func() {
		close(c.done)
		if c.port != "" {
			c.n.mu.Lock()
			delete(c.n.dialPorts, c.port)
			c.n.mu.Unlock()
		}
		f := &c.n.faults
		f.mu.Lock()
		delete(f.conns[c.addr], c)
		if len(f.conns[c.addr]) == 0 {
			delete(f.conns, c.addr)
		}
		f.mu.Unlock()
	})
	return c.halfConn.Close()
}
