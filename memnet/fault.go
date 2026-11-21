package memnet

import (
	"math/rand/v2"
	"net"
	"sync"
	"time"

	"github.com/djylb/timeshim"
)

// Link are the properties of one direction of the traffic to or from an
// address of a Net.
type Link struct {
	Delay time.Duration // added before every write or datagram
	Loss  float64       // datagram drop probability in [0, 1]; streams stay reliable
	Rate  int64         // bytes per second; 0 = unlimited
	Off   bool          // disconnected: dials refused, datagrams dropped, open connections closed
}

func (l Link) zero() bool { return l == Link{} }

// LinkPair are both directions of the traffic of one address: To towards
// it (the dialer's writes), From out of it (the listener's writes).
type LinkPair struct {
	To, From Link
}

type faults struct {
	mu    sync.Mutex
	links map[string]LinkPair
	conns map[string]map[*faultConn]struct{}
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
		return rand.Float64() < p
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.Rand.Float64() < p
}

// wait blocks for the delay and transmission time of size bytes on l;
// false when done closed first.
func (n *Net) wait(l Link, size int, done <-chan struct{}) bool {
	d := l.Delay
	if l.Rate > 0 {
		d += time.Duration(int64(size) * int64(time.Second) / l.Rate)
	}
	if d <= 0 {
		return true
	}
	t := timeshim.NewTimer(timeshim.Or(n.Clock), d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-done:
		return false
	}
}

// faultConn is one end of a stream connection to addr; to is true for
// the dialer's end (its writes go towards addr).
type faultConn struct {
	*halfConn
	n    *Net
	addr string
	to   bool
	once sync.Once
	done chan struct{}
	// local and remote are the addresses of a DialFrom connection (nil:
	// the halfConn's "pipe").
	local, remote net.Addr
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

func (n *Net) track(c *halfConn, addr string, to bool) *faultConn {
	fc := &faultConn{halfConn: c, n: n, addr: addr, to: to, done: make(chan struct{})}
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
	if !c.n.wait(l, len(b), c.done) {
		return 0, net.ErrClosed
	}
	return c.halfConn.Write(b)
}

func (c *faultConn) Close() error {
	c.once.Do(func() {
		close(c.done)
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
