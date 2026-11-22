package udpflow

import (
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/djylb/netx/internal/clock"
)

// Close must not wait for the accept filter when it runs concurrently with
// it, or a caller that holds a lock the filter takes, such as one guarding an
// allow list, deadlocks with the read loop. Here Close runs just before the
// filter would.
func TestPacketListenerCloseHoldingFilterLock(t *testing.T) {
	var mu sync.Mutex
	closed := make(chan struct{})
	var hooked atomic.Bool
	beforeFilter := func(l *PacketListener) {
		if hooked.Swap(true) {
			return
		}
		go func() {
			mu.Lock()
			_ = l.Close()
			mu.Unlock()
			close(closed)
		}()
		for !clock.IsClosed(l.conns.Done()) {
			runtime.Gosched()
		}
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	filtered := make(chan struct{}, 1)
	NewPacketListener(pc, WithPacketAcceptFilter(func(net.Addr, []byte) bool {
		filtered <- struct{}{}
		mu.Lock()
		defer mu.Unlock()
		return true
	}), func(o *packetListenerOptions) { o.beforeFilter = beforeFilter })
	c, err := net.DialUDP("udp", nil, pc.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close holding the filter's lock deadlocked with the filter")
	}
	if len(filtered) != 0 {
		t.Fatal("the accept filter ran after Close")
	}
}

func TestPacketListenerCloseWhileAnotherFilterRuns(t *testing.T) {
	a, b := newFeedPacketConn(), newFeedPacketConn()
	entered := make(chan struct{})
	unblock := make(chan struct{})
	release := sync.OnceFunc(func() { close(unblock) })
	l := NewPacketListener(a, WithPacketConns(b), WithPacketAcceptFilter(func(_ net.Addr, p []byte) bool {
		if string(p) == "hold" {
			close(entered)
			<-unblock
		}
		return false
	}))
	defer func() {
		release()
		_ = l.Close()
	}()
	a.in <- feedDatagram{from: netip.MustParseAddrPort("192.0.2.1:1"), data: []byte("hold")}
	<-entered
	b.feed(t, feedDatagram{from: netip.MustParseAddrPort("192.0.2.2:1"), data: []byte("pass")})
	closed := make(chan error, 1)
	go func() { closed <- l.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		release()
		err := <-closed
		t.Fatalf("Close waited for a filter that was still running on the other socket (Close error %v)", err)
	}
}
