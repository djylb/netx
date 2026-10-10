package netx

import (
	"errors"
	"io"
	"net"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newUDPListener(t *testing.T, opts ...PacketListenerOption) *PacketListener {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := NewPacketListener(pc, opts...)
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func dialUDP(t *testing.T, l *PacketListener) *net.UDPConn {
	t.Helper()
	c, err := net.DialUDP("udp", nil, l.Addr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestPacketListenerSplitsPeers(t *testing.T) {
	l := newUDPListener(t)
	a, b := dialUDP(t, l), dialUDP(t, l)

	_, _ = a.Write([]byte("from a"))
	ca, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ca.Close() }()
	if ca.RemoteAddr().String() != a.LocalAddr().String() || ca.LocalAddr().String() != l.Addr().String() {
		t.Fatalf("addresses = %v -> %v", ca.RemoteAddr(), ca.LocalAddr())
	}
	_, _ = b.Write([]byte("from b"))
	cb, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cb.Close() }()
	_, _ = a.Write([]byte("again a"))

	buf := make([]byte, 64)
	for _, want := range []struct {
		c   net.Conn
		msg string
	}{{ca, "from a"}, {cb, "from b"}, {ca, "again a"}} {
		_ = want.c.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := want.c.Read(buf)
		if err != nil || string(buf[:n]) != want.msg {
			t.Fatalf("Read() = %q, %v; want %q", buf[:n], err, want.msg)
		}
	}

	// Writes go to the peer, and a short buffer truncates like UDP.
	if _, err := cb.Write([]byte("reply")); err != nil {
		t.Fatal(err)
	}
	_ = b.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := b.Read(buf); err != nil || string(buf[:n]) != "reply" {
		t.Fatalf("peer Read() = %q, %v", buf[:n], err)
	}
	_, _ = a.Write([]byte("truncated"))
	_ = ca.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := ca.Read(buf[:4]); err != nil || string(buf[:n]) != "trun" {
		t.Fatalf("short Read() = %q, %v", buf[:n], err)
	}
}

func TestPacketListenerReopensClosedPeer(t *testing.T) {
	l := newUDPListener(t)
	a := dialUDP(t, l)
	_, _ = a.Write([]byte("1"))
	c1, _ := l.Accept()
	_ = c1.Close()
	if _, err := c1.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Read() after Close error = %v", err)
	}
	if _, err := c1.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Write() after Close error = %v", err)
	}
	_, _ = a.Write([]byte("2"))
	c2, err := l.Accept()
	if err != nil || c2 == c1 {
		t.Fatalf("Accept() = %v, %v; want a new connection", c2, err)
	}
	buf := make([]byte, 4)
	_ = c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := c2.Read(buf); err != nil || string(buf[:n]) != "2" {
		t.Fatalf("Read() = %q, %v", buf[:n], err)
	}
}

func TestPacketListenerFilterAndBacklog(t *testing.T) {
	var mu sync.Mutex
	allowed := map[string]bool{}
	l := newUDPListener(t, WithAcceptBacklog(1), WithAcceptFilter(func(peer net.Addr) bool {
		mu.Lock()
		defer mu.Unlock()
		return allowed[peer.String()]
	}))
	a, b, c := dialUDP(t, l), dialUDP(t, l), dialUDP(t, l)
	mu.Lock()
	allowed[a.LocalAddr().String()] = true
	allowed[b.LocalAddr().String()] = true
	mu.Unlock()

	_, _ = c.Write([]byte("filtered"))
	_, _ = a.Write([]byte("a"))
	time.Sleep(50 * time.Millisecond)
	_, _ = b.Write([]byte("b")) // backlog of one is taken by a
	time.Sleep(50 * time.Millisecond)
	first, _ := l.Accept()
	if first.RemoteAddr().String() != a.LocalAddr().String() {
		t.Fatalf("first peer = %v, want %v", first.RemoteAddr(), a.LocalAddr())
	}
	done := make(chan net.Conn, 1)
	go func() {
		c, _ := l.Accept()
		done <- c
	}()
	select {
	case got := <-done:
		t.Fatalf("Accept() returned %v for a dropped or filtered peer", got.RemoteAddr())
	case <-time.After(100 * time.Millisecond):
	}
	_, _ = b.Write([]byte("b again"))
	select {
	case got := <-done:
		if got.RemoteAddr().String() != b.LocalAddr().String() {
			t.Fatalf("second peer = %v, want %v", got.RemoteAddr(), b.LocalAddr())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("peer b was not accepted once the backlog had room")
	}
}

func TestPacketListenerQueueDropsOverflow(t *testing.T) {
	l := newUDPListener(t, WithPacketQueue(2))
	a := dialUDP(t, l)
	for _, m := range []string{"1", "2", "3", "4"} {
		_, _ = a.Write([]byte(m))
	}
	c, _ := l.Accept()
	time.Sleep(50 * time.Millisecond)
	buf := make([]byte, 4)
	var got []string
	for {
		_ = c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, err := c.Read(buf)
		if err != nil {
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("Read() error = %v", err)
			}
			break
		}
		got = append(got, string(buf[:n]))
	}
	if len(got) != 2 || got[0] != "1" || got[1] != "2" {
		t.Fatalf("datagrams = %v, want the first two", got)
	}
}

func TestPacketListenerIdleTimeout(t *testing.T) {
	l := newUDPListener(t, WithIdleTimeout(80*time.Millisecond))
	a := dialUDP(t, l)
	_, _ = a.Write([]byte("x"))
	c, _ := l.Accept()
	_, _ = c.Read(make([]byte, 1))
	start := time.Now()
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("Read() error = %v, want EOF after the idle timeout", err)
	}
	if d := time.Since(start); d < 40*time.Millisecond || d > 2*time.Second {
		t.Fatalf("idle close after %v", d)
	}
}

func TestPacketListenerDeadlinesAndClose(t *testing.T) {
	l := newUDPListener(t)
	a := dialUDP(t, l)
	_, _ = a.Write([]byte("x"))
	c, _ := l.Accept()
	_, _ = c.Read(make([]byte, 1))

	_ = c.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) || !IsTimeout(err) {
		t.Fatalf("Read() error = %v, want a timeout", err)
	}
	_ = c.SetReadDeadline(time.Time{})
	_ = c.SetWriteDeadline(time.Now().Add(-time.Second))
	if _, err := c.Write([]byte("x")); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Write() past deadline error = %v", err)
	}
	_ = c.SetDeadline(time.Time{})
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	blocked := make(chan error, 1)
	go func() {
		_, err := c.Read(make([]byte, 1))
		blocked <- err
	}()
	accepting := make(chan error, 1)
	go func() {
		_, err := l.Accept()
		accepting <- err
	}()
	time.Sleep(20 * time.Millisecond)
	if err := l.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := <-blocked; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Read() after listener Close error = %v", err)
	}
	if err := <-accepting; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept() after Close error = %v", err)
	}
	_ = l.Close()
}

func TestPacketConnCloseStopsDeadlineTimers(t *testing.T) {
	l := newUDPListener(t)
	a := dialUDP(t, l)
	_, _ = a.Write([]byte("x"))
	c := acceptWithin(t, l).(*packetConn)
	_ = c.SetDeadline(time.Now().Add(time.Hour))
	_ = c.Close()
	for _, d := range []*deadline{&c.readDeadline, &c.writeDeadline} {
		d.mu.Lock()
		timer := d.timer
		d.mu.Unlock()
		if timer != nil {
			t.Fatal("deadline timer still pending after Close")
		}
	}
	// Deadlines can still be set on the closed connection.
	_ = c.SetDeadline(time.Now().Add(-time.Second))
	_ = c.SetDeadline(time.Now().Add(time.Hour))
	_ = c.SetDeadline(time.Time{})
}

// As on a socket, an expired read deadline fails Read even while datagrams
// are queued, and they are still there once the deadline is cleared.
func TestPacketConnReadHonorsDeadlineBeforeQueue(t *testing.T) {
	l := newUDPListener(t)
	a := dialUDP(t, l)
	_, _ = a.Write([]byte("x"))
	c := acceptWithin(t, l)
	_ = c.SetReadDeadline(time.Now().Add(-time.Second))
	for range 3 {
		if _, err := c.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("Read() past the deadline error = %v, want ErrDeadlineExceeded", err)
		}
	}
	_ = c.SetReadDeadline(time.Time{})
	if n, err := c.Read(make([]byte, 1)); err != nil || n != 1 {
		t.Fatalf("Read() = %d, %v, want the queued datagram", n, err)
	}
	_ = c.Close()
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Read() after Close error = %v, want net.ErrClosed", err)
	}
}

// The queue of a connection is bounded in bytes too, so large datagrams
// cannot hold 64 KiB per slot.
func TestPacketConnQueueBoundsBytes(t *testing.T) {
	l := newUDPListener(t, WithPacketQueue(4)) // 4 datagrams, 8 KiB
	a := dialUDP(t, l)
	_, _ = a.Write([]byte("x"))
	c := acceptWithin(t, l).(*packetConn)
	buf := make([]byte, 65535)
	if _, err := c.Read(buf); err != nil {
		t.Fatal(err)
	}
	// The read loop is idle now, so the test can queue datagrams itself.
	readAll := func() []int {
		var sizes []int
		_ = c.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		for {
			n, err := c.Read(buf)
			if err != nil {
				_ = c.SetReadDeadline(time.Time{})
				return sizes
			}
			sizes = append(sizes, n)
		}
	}
	for _, tt := range []struct {
		name string
		send []int
		want []int
	}{
		{"small datagrams by count", []int{100, 100, 100, 100, 100}, []int{100, 100, 100, 100}},
		{"one large datagram when empty", []int{60000, 100}, []int{60000}},
		{"large datagrams by bytes", []int{3000, 3000, 3000}, []int{3000, 3000}},
	} {
		for _, n := range tt.send {
			c.enqueue(make([]byte, n))
		}
		if got := readAll(); !slices.Equal(got, tt.want) {
			t.Fatalf("%s: read %v, want %v", tt.name, got, tt.want)
		}
		if q := c.queued.Load(); q != 0 {
			t.Fatalf("%s: %d bytes still counted as queued", tt.name, q)
		}
	}
}

// The accept filter may use the listener: close it, or close one of its
// connections.
func TestPacketListenerFilterMayUseListener(t *testing.T) {
	t.Run("close listener", func(t *testing.T) {
		var self atomic.Pointer[PacketListener]
		closed := make(chan error, 1)
		l := newUDPListener(t, WithAcceptFilter(func(net.Addr) bool {
			closed <- self.Load().Close()
			return true
		}))
		self.Store(l)
		a := dialUDP(t, l)
		_, _ = a.Write([]byte("x"))
		select {
		case <-closed:
		case <-time.After(2 * time.Second):
			t.Fatal("Close called by the accept filter did not return")
		}
		if _, err := l.Accept(); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Accept() after Close = %v, want net.ErrClosed", err)
		}
		done := make(chan struct{})
		go func() {
			_ = l.Close()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("a second Close blocked")
		}
	})
	t.Run("close connection", func(t *testing.T) {
		var first atomic.Pointer[net.Conn]
		l := newUDPListener(t, WithAcceptFilter(func(net.Addr) bool {
			if c := first.Load(); c != nil {
				_ = (*c).Close()
			}
			return true
		}))
		a := dialUDP(t, l)
		_, _ = a.Write([]byte("a"))
		c := acceptWithin(t, l)
		first.Store(&c)
		b := dialUDP(t, l)
		_, _ = b.Write([]byte("b"))
		acceptWithin(t, l)
		if _, err := c.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Read() of the connection the filter closed = %v, want net.ErrClosed", err)
		}
	})
}

// The listener also works on a PacketConn that is not a *net.UDPConn.
func TestPacketListenerGenericPacketConn(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := NewPacketListener(struct{ net.PacketConn }{pc})
	defer func() { _ = l.Close() }()
	a := dialUDP(t, l)
	_, _ = a.Write([]byte("hi"))
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	if n, err := c.Read(buf); err != nil || string(buf[:n]) != "hi" {
		t.Fatalf("Read() = %q, %v", buf[:n], err)
	}
	if _, err := c.Write([]byte("yo")); err != nil {
		t.Fatal(err)
	}
	_ = a.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := a.Read(buf); err != nil || string(buf[:n]) != "yo" {
		t.Fatalf("peer Read() = %q, %v", buf[:n], err)
	}
}

func TestPacketListenerMaxDatagram(t *testing.T) {
	l := newUDPListener(t, WithMaxDatagram(4))
	a := dialUDP(t, l)
	_, _ = a.Write([]byte("truncated"))
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := c.Read(buf); err != nil || string(buf[:n]) != "trun" {
		t.Fatalf("Read() = %q, %v; want the first 4 bytes", buf[:n], err)
	}
}

// failingPacketConn returns err from every read and counts them.
type failingPacketConn struct {
	net.PacketConn
	err   error
	reads atomic.Int64
}

func (f *failingPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	f.reads.Add(1)
	return 0, nil, f.err
}

func TestPacketListenerReadErrors(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pc.Close() }()

	// io.EOF means the packet connection is exhausted: the listener closes.
	l := NewPacketListener(&failingPacketConn{PacketConn: pc, err: io.EOF})
	accepted := make(chan error, 1)
	go func() {
		_, err := l.Accept()
		accepted <- err
	}()
	select {
	case err := <-accepted:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Accept() error = %v, want %v", err, net.ErrClosed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("listener still open after io.EOF")
	}

	// A persistent error is retried with a growing delay, not in a busy loop.
	failing := &failingPacketConn{PacketConn: pc, err: errors.New("broken tunnel")}
	l = NewPacketListener(failing)
	time.Sleep(200 * time.Millisecond)
	_ = l.Close()
	if n := failing.reads.Load(); n > 20 {
		t.Fatalf("%d reads in 200ms, want a backoff", n)
	}
}

func TestPacketListenerClearsExpiredReadDeadline(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = pc.SetReadDeadline(time.Now().Add(-time.Second))
	l := NewPacketListener(pc)
	defer func() { _ = l.Close() }()
	a := dialUDP(t, l)
	if _, err := a.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 1)
	go func() {
		if c, err := l.Accept(); err == nil {
			accepted <- c
		}
	}()
	select {
	case c := <-accepted:
		_ = c.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("no connection: the expired read deadline was kept")
	}
}

func TestPacketListenerIdleTimeoutSparesBacklog(t *testing.T) {
	const idle = 30 * time.Millisecond
	l := newUDPListener(t, WithIdleTimeout(idle))
	a := dialUDP(t, l)
	_, _ = a.Write([]byte("x"))
	// Several sweeps run while the connection waits for Accept.
	time.Sleep(5 * idle)
	c := acceptWithin(t, l)
	if c.(*packetConn).idleAt(time.Now(), idle) {
		t.Fatal("idle clock started before Accept")
	}
	buf := make([]byte, 4)
	n, err := c.Read(buf)
	if err != nil || string(buf[:n]) != "x" {
		t.Fatalf("Read() = %q, %v, want the datagram sent before Accept", buf[:n], err)
	}
	start := time.Now()
	if _, err := c.Read(buf); !errors.Is(err, io.EOF) {
		t.Fatalf("Read() error = %v, want EOF after the idle timeout", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("idle close after %v", d)
	}
}

func TestPacketListenerAcceptSkipsClosedConns(t *testing.T) {
	l := newUDPListener(t)
	a := dialUDP(t, l)
	b := dialUDP(t, l)
	_, _ = a.Write([]byte("a"))
	waitUntil(t, func() bool { return len(l.accept) == 1 })
	l.mu.Lock()
	stale := l.conns[a.LocalAddr().(*net.UDPAddr).AddrPort()]
	l.mu.Unlock()
	if stale == nil {
		t.Fatal("no connection for the first peer")
	}
	stale.shutdown(io.EOF)
	_, _ = b.Write([]byte("b"))
	c := acceptWithin(t, l)
	if got, want := c.RemoteAddr().String(), b.LocalAddr().String(); got != want {
		t.Fatalf("Accept() returned the peer %s, want %s past the closed connection", got, want)
	}
}

func TestPacketConnIdleClockIsMonotonic(t *testing.T) {
	c := &packetConn{}
	c.touch()
	if d := time.Duration(clockOffset(time.Now()) - c.active.Load()); d < 0 || d > time.Second {
		t.Fatalf("activity stamp is %v behind the monotonic clock, want about 0", d)
	}
}

func TestPacketConnReadDoesNotAllocate(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := NewPacketListener(pc)
	defer func() { _ = l.Close() }()
	c := &packetConn{l: l, queue: make(chan *[]byte, 4), closed: make(chan struct{}), readDeadline: makeDeadline(), writeDeadline: makeDeadline()}
	p := make([]byte, 100)
	buf := make([]byte, 2048)
	allocs := testing.AllocsPerRun(1000, func() {
		c.enqueue(p)
		if n, err := c.Read(buf); n != len(p) || err != nil {
			t.Fatalf("Read() = %d, %v", n, err)
		}
	})
	if allocs > 0 {
		t.Fatalf("allocations per queued datagram = %v, want 0", allocs)
	}
}

func waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(2 * time.Second); !cond(); {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached within 2s")
		}
		time.Sleep(time.Millisecond)
	}
}

// acceptWithin returns the next connection of l, failing the test if none
// comes within 2s.
func acceptWithin(t *testing.T, l *PacketListener) net.Conn {
	t.Helper()
	type result struct {
		c   net.Conn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := l.Accept()
		ch <- result{c, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("Accept() error = %v", r.err)
		}
		return r.c
	case <-time.After(2 * time.Second):
		t.Fatal("Accept() returned no connection within 2s")
		return nil
	}
}
