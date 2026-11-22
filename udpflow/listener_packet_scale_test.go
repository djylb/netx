package udpflow

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/djylb/timeshim"

	"github.com/djylb/netx/internal/clock"
)

// A peer given to RejectPeer is dropped without the filter while the reject
// cache remembers it, and asked again once its entry expires; the filter's
// own rejections are not remembered, as their source may be spoofed.
//
// The filter counts its calls per peer, so that datagrams a peer sent before
// its wait ended, still queued in the socket, cannot be taken for those of
// another peer, and it counts only after RejectPeer, then holds the read loop
// until the cache is checked, so that a count seen means the peer is cached.
func TestPacketListenerRejectCache(t *testing.T) {
	fake := timeshim.NewFake(time.Unix(1000, 0))
	var (
		mu     sync.Mutex
		calls  = make(map[peerKey]int64)
		l      *PacketListener
		held   = make(chan struct{})
		unhold = sync.OnceFunc(func() { close(held) })
	)
	t.Cleanup(unhold)
	count := func(peer net.Addr) int64 {
		mu.Lock()
		defer mu.Unlock()
		return calls[peerKeyOf(peer)]
	}
	l = newUDPListener(t, WithPacketClock(fake), WithPacketRejectCache(16, time.Minute),
		WithPacketAcceptFilter(func(peer net.Addr, first []byte) bool {
			proven := string(first) == "proven"
			if proven {
				l.RejectPeer(peer)
			}
			mu.Lock()
			calls[peerKeyOf(peer)]++
			mu.Unlock()
			if proven {
				<-held
			}
			return false
		}))
	// sendUntil writes msg from c until the filter has run want times for c.
	sendUntil := func(c *net.UDPConn, msg string, want int64) {
		t.Helper()
		for deadline := time.Now().Add(5 * time.Second); count(c.LocalAddr()) < want; time.Sleep(time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("filter calls = %d, want %d", count(c.LocalAddr()), want)
			}
			_, _ = c.Write([]byte(msg))
		}
	}
	spoofed := dialUDP(t, l)
	sendUntil(spoofed, "claimed", 1)
	sendUntil(spoofed, "claimed", 2) // a plain rejection is not remembered
	if l.reject.has(peerKeyOf(spoofed.LocalAddr())) {
		t.Fatal("a plain rejection was cached")
	}
	// Datagrams of spoofed still queued run through the filter meanwhile.
	for range 20 {
		_, _ = spoofed.Write([]byte("claimed"))
	}
	c := dialUDP(t, l)
	sendUntil(c, "proven", 1)
	if !l.reject.has(peerKeyOf(c.LocalAddr())) {
		t.Fatal("the rejected peer is not cached")
	}
	unhold()
	for range 20 {
		_, _ = c.Write([]byte("proven"))
	}
	// A datagram from another peer runs through the read loop after those.
	other := dialUDP(t, l)
	sendUntil(other, "claimed", 1)
	if n := count(c.LocalAddr()); n != 1 {
		t.Fatalf("filter calls = %d, want 1: the cached peer was filtered again", n)
	}
	fake.Advance(time.Minute)
	sendUntil(c, "proven", 2)
}

func TestRejectCacheBound(t *testing.T) {
	c := newRejectCache(4, time.Hour, clock.NewEpoch(timeshim.NewFake(time.Unix(1, 0))))
	key := func(i int) peerKey {
		return peerKey{ap: netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}), 1)}
	}
	for i := range 10 {
		c.add(key(i))
	}
	if n := len(c.cur) + len(c.old); n > 4 {
		t.Fatalf("cache holds %d peers, want at most 4", n)
	}
	if !c.has(key(9)) || c.has(key(0)) {
		t.Fatal("the cache keeps old peers instead of new ones")
	}
	one := newRejectCache(1, time.Hour, clock.NewEpoch(timeshim.NewFake(time.Unix(1, 0))))
	for i := range 3 {
		one.add(key(i))
	}
	if n := len(one.cur) + len(one.old); n != 1 {
		t.Fatalf("a cache of size 1 holds %d peers", n)
	}
	var nilCache *rejectCache
	nilCache.add(key(1))
	if nilCache.has(key(1)) {
		t.Fatal("a nil cache remembers")
	}
}

// Datagrams that reach an added packet connection start connections of the
// listener, which reply from that packet connection.
func TestPacketListenerMoreConns(t *testing.T) {
	more, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := newUDPListener(t, WithPacketConns(more))
	c, err := net.DialUDP("udp", nil, more.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		if a, err := l.Accept(); err == nil {
			accepted <- a
		}
	}()
	var a net.Conn
	for a == nil {
		_, _ = c.Write([]byte("hi"))
		select {
		case a = <-accepted:
		case <-time.After(50 * time.Millisecond):
		}
	}
	if _, err := a.Write([]byte("back")); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 16)
	n, err := c.Read(buf) // a connected socket reads only from more's address
	if err != nil || string(buf[:n]) != "back" {
		t.Fatalf("reply = %q, %v", buf[:n], err)
	}
	_ = l.Close()
	if _, _, err := more.ReadFrom(buf); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("the added packet connection is open after Close: %v", err)
	}
}

func TestListenUDPReusePort(t *testing.T) {
	ctx := context.Background()
	if _, err := ListenUDPReusePort(ctx, nil, "unixgram", "", 1); !errors.Is(err, net.UnknownNetworkError("unixgram")) {
		t.Fatalf("unsupported network: %v, want net.UnknownNetworkError", err)
	}
	conns, err := ListenUDPReusePort(ctx, nil, "udp4", "127.0.0.1:0", 3)
	if unsupported := reusePortSupport(); unsupported != nil {
		if !errors.Is(err, unsupported) {
			t.Fatalf("err = %v, want ErrReusePortUnsupported", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	pcs := make([]net.PacketConn, len(conns))
	for i, c := range conns {
		pcs[i] = c
		if c.LocalAddr().String() != conns[0].LocalAddr().String() {
			t.Fatalf("socket %d on %v, want %v", i, c.LocalAddr(), conns[0].LocalAddr())
		}
	}
	l := NewPacketListener(pcs[0], WithPacketConns(pcs[1:]...), WithPacketReadBatch(8), WithPacketMaxDatagram(1500))
	defer func() { _ = l.Close() }()
	const peers = 16
	go func() {
		// Each peer keeps its socket, so its address stays distinct.
		var dialed []*net.UDPConn
		defer func() {
			for _, c := range dialed {
				_ = c.Close()
			}
		}()
		for i := range peers {
			c, err := net.DialUDP("udp4", nil, l.Addr().(*net.UDPAddr))
			if err != nil {
				return
			}
			dialed = append(dialed, c)
			for range 3 {
				_, _ = c.Write(fmt.Appendf(nil, "peer %d", i))
			}
		}
	}()
	seen := map[string]bool{}
	for len(seen) < peers {
		done := make(chan net.Conn, 1)
		go func() {
			c, err := l.Accept()
			if err == nil {
				done <- c
			}
		}()
		select {
		case c := <-done:
			buf := make([]byte, 64)
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, err := c.Read(buf)
			if err != nil {
				t.Fatal(err)
			}
			seen[string(buf[:n])] = true
		case <-time.After(5 * time.Second):
			t.Fatalf("accepted %d of %d peers", len(seen), peers)
		}
	}
}

// A batch read returns each datagram with its source.
func TestPacketListenerReadBatch(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "android" {
		t.Skip("recvmmsg is Linux-only")
	}
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		pc, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
	}
	defer func() { _ = pc.Close() }()
	b := newBatchReader(pc, 4, 32, 0)
	if b == nil {
		t.Fatal("no batch reader")
	}
	c, err := net.DialUDP("udp", nil, pc.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	for i := range 3 {
		_, _ = c.Write(fmt.Appendf(nil, "d%d", i))
	}
	_, _ = c.Write(make([]byte, 100)) // truncated to the buffer
	got := 0
	for got < 4 {
		n, err := b.read()
		if err != nil {
			t.Fatal(err)
		}
		for i := range n {
			p, ap, _ := b.datagram(i)
			if ap != c.LocalAddr().(*net.UDPAddr).AddrPort() {
				t.Fatalf("source %v, want %v", ap, c.LocalAddr())
			}
			want := fmt.Sprintf("d%d", got)
			if got == 3 {
				want = string(make([]byte, 32))
			}
			if string(p) != want {
				t.Fatalf("datagram %d = %q, want %q", got, p, want)
			}
			got++
		}
	}
}
