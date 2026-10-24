package netx

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/djylb/netx/internal/dgram"
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

// peerConn returns the connection of l for the peer from, if the read loop
// has started one.
func peerConn(l *PacketListener, from *net.UDPConn) *packetConn {
	c, _ := l.conns.Get(peerKey{ap: from.LocalAddr().(*net.UDPAddr).AddrPort()})
	return c
}

// send writes msg from from until the read loop of l has queued it on the
// peer's connection, since a loopback datagram can be lost on a busy host.
func send(t *testing.T, l *PacketListener, from *net.UDPConn, msg string) {
	t.Helper()
	before := peerConn(l, from)
	queued := 0
	if before != nil {
		queued = before.q.Len()
	}
	for range 5 {
		if _, err := from.Write([]byte(msg)); err != nil {
			t.Fatal(err)
		}
		for wait := time.Now().Add(time.Second); time.Now().Before(wait); time.Sleep(time.Millisecond) {
			if c := peerConn(l, from); c != nil && (c != before || c.q.Len() > queued) {
				return
			}
		}
	}
	t.Fatalf("datagram %q from %v was not queued", msg, from.LocalAddr())
}

// countingPacketConn counts the datagrams its listener has read.
type countingPacketConn struct {
	net.PacketConn
	reads atomic.Int64
}

func (c *countingPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if err == nil {
		c.reads.Add(1)
	}
	return n, addr, err
}

// newCountingUDPListener is newUDPListener over a countingPacketConn, for
// tests of datagrams that the listener drops.
func newCountingUDPListener(t *testing.T, opts ...PacketListenerOption) (*PacketListener, *countingPacketConn) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cpc := &countingPacketConn{PacketConn: pc}
	l := NewPacketListener(cpc, opts...)
	t.Cleanup(func() { _ = l.Close() })
	return l, cpc
}

// sendCounted writes msg from from until the read loop has read one more
// datagram, which it has then delivered or dropped before reading the next.
func sendCounted(t *testing.T, pc *countingPacketConn, from *net.UDPConn, msg string) {
	t.Helper()
	want := pc.reads.Load() + 1
	for range 5 {
		if _, err := from.Write([]byte(msg)); err != nil {
			t.Fatal(err)
		}
		for wait := time.Now().Add(time.Second); time.Now().Before(wait); time.Sleep(time.Millisecond) {
			if pc.reads.Load() >= want {
				return
			}
		}
	}
	t.Fatalf("datagram %q from %v was not read", msg, from.LocalAddr())
}

func TestPacketListenerSplitsPeers(t *testing.T) {
	l := newUDPListener(t)
	a, b := dialUDP(t, l), dialUDP(t, l)

	send(t, l, a, "from a")
	ca := acceptWithin(t, l)
	defer func() { _ = ca.Close() }()
	if ca.RemoteAddr().String() != a.LocalAddr().String() || ca.LocalAddr().String() != l.Addr().String() {
		t.Fatalf("addresses = %v -> %v", ca.RemoteAddr(), ca.LocalAddr())
	}
	send(t, l, b, "from b")
	cb := acceptWithin(t, l)
	defer func() { _ = cb.Close() }()
	send(t, l, a, "again a")

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
	send(t, l, a, "truncated")
	_ = ca.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := ca.Read(buf[:4]); err != nil || string(buf[:n]) != "trun" {
		t.Fatalf("short Read() = %q, %v", buf[:n], err)
	}
}

func TestPacketListenerReopensClosedPeer(t *testing.T) {
	l := newUDPListener(t)
	a := dialUDP(t, l)
	send(t, l, a, "1")
	c1 := acceptWithin(t, l)
	_ = c1.Close()
	if _, err := c1.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Read() after Close error = %v", err)
	}
	if _, err := c1.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Write() after Close error = %v", err)
	}
	send(t, l, a, "2")
	c2 := acceptWithin(t, l)
	if c2 == c1 {
		t.Fatal("Accept() returned the closed connection, want a new one")
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
	l, pc := newCountingUDPListener(t, WithPacketAcceptBacklog(1), WithPacketAcceptFilter(func(peer net.Addr, _ []byte) bool {
		mu.Lock()
		defer mu.Unlock()
		return allowed[peer.String()]
	}))
	a, b, c := dialUDP(t, l), dialUDP(t, l), dialUDP(t, l)
	mu.Lock()
	allowed[a.LocalAddr().String()] = true
	allowed[b.LocalAddr().String()] = true
	mu.Unlock()

	sendCounted(t, pc, c, "filtered")
	sendCounted(t, pc, a, "a")
	sendCounted(t, pc, b, "b") // backlog of one is taken by a
	first := acceptWithin(t, l)
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
	sendCounted(t, pc, b, "b again")
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
	l, pc := newCountingUDPListener(t, WithPacketQueue(2))
	a := dialUDP(t, l)
	for _, m := range []string{"1", "2", "3", "4"} {
		sendCounted(t, pc, a, m)
	}
	// Once another datagram is read, the read loop has dropped 3 and 4.
	sendCounted(t, pc, dialUDP(t, l), "z")
	c := acceptWithin(t, l)
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
	l := newUDPListener(t, WithPacketIdleTimeout(80*time.Millisecond))
	a := dialUDP(t, l)
	send(t, l, a, "x")
	// Before Accept, where the idle time starts, so that a slow host
	// cannot make it look early.
	start := time.Now()
	c := acceptWithin(t, l)
	_, _ = c.Read(make([]byte, 1))
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
	send(t, l, a, "x")
	c := acceptWithin(t, l)
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

func TestPacketConnDeadlinesAfterClose(t *testing.T) {
	l := newUDPListener(t)
	a := dialUDP(t, l)
	send(t, l, a, "x")
	c := acceptWithin(t, l).(*packetConn)
	_ = c.SetDeadline(time.Now().Add(time.Hour))
	_ = c.Close()
	// Setting a deadline on the closed connection fails and starts no timer.
	for _, set := range []func(time.Time) error{c.SetDeadline, c.SetReadDeadline, c.SetWriteDeadline} {
		if err := set(time.Now().Add(time.Hour)); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("setting a deadline after Close = %v, want net.ErrClosed", err)
		}
	}
}

// While the accept backlog is full, a new peer's datagram is dropped before
// the accept filter runs or a connection is allocated.
func TestPacketListenerFullBacklogDropsEarly(t *testing.T) {
	var filtered atomic.Int32
	l := newUDPListener(t, WithPacketAcceptBacklog(1), WithPacketAcceptFilter(func(net.Addr, []byte) bool {
		filtered.Add(1)
		return true
	}))
	a := dialUDP(t, l)
	send(t, l, a, "a")
	waitUntil(t, func() bool { return l.conns.Pending() == 1 })
	for range 3 {
		b := dialUDP(t, l)
		_, _ = b.Write([]byte("b"))
	}
	time.Sleep(50 * time.Millisecond)
	if n := filtered.Load(); n != 1 {
		t.Fatalf("accept filter ran %d times, want 1 (later peers found the backlog full)", n)
	}
	n := l.conns.Len()
	if n != 1 {
		t.Fatalf("%d connections, want 1", n)
	}
}

// As on a socket, an expired read deadline fails Read even while datagrams
// are queued, and they are still there once the deadline is cleared.
func TestPacketConnReadHonorsDeadlineBeforeQueue(t *testing.T) {
	l := newUDPListener(t)
	a := dialUDP(t, l)
	send(t, l, a, "x")
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

// The accept filter may use the listener: close it, or close one of its
// connections.
func TestPacketListenerFilterMayUseListener(t *testing.T) {
	t.Run("close listener", func(t *testing.T) {
		var self atomic.Pointer[PacketListener]
		closed := make(chan error, 1)
		l := newUDPListener(t, WithPacketAcceptFilter(func(net.Addr, []byte) bool {
			closed <- self.Load().Close()
			return true
		}))
		self.Store(l)
		a := dialUDP(t, l)
		ran := false
		for i := 0; i < 5 && !ran; i++ {
			_, _ = a.Write([]byte("x"))
			select {
			case <-closed:
				ran = true
			case <-time.After(time.Second):
			}
		}
		if !ran {
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
		l := newUDPListener(t, WithPacketAcceptFilter(func(net.Addr, []byte) bool {
			if c := first.Load(); c != nil {
				_ = (*c).Close()
			}
			return true
		}))
		a := dialUDP(t, l)
		send(t, l, a, "a")
		c := acceptWithin(t, l)
		first.Store(&c)
		b := dialUDP(t, l)
		send(t, l, b, "b")
		acceptWithin(t, l)
		if _, err := c.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Read() of the connection the filter closed = %v, want net.ErrClosed", err)
		}
	})
}

// Close from the accept filter and Close from another goroutine may run at
// the same time without either waiting for the other forever.
func TestPacketListenerConcurrentCloseFromFilter(t *testing.T) {
	for range 20 {
		var self atomic.Pointer[PacketListener]
		entered := make(chan struct{})
		release := make(chan struct{})
		var once sync.Once
		l := newUDPListener(t, WithPacketAcceptFilter(func(net.Addr, []byte) bool {
			once.Do(func() { close(entered) })
			<-release
			_ = self.Load().Close()
			return true
		}))
		self.Store(l)
		a := dialUDP(t, l)
		// Resend until the filter runs, in case a datagram is lost.
		for sent := false; !sent; {
			_, _ = a.Write([]byte("x"))
			select {
			case <-entered:
				sent = true
			case <-time.After(50 * time.Millisecond):
			}
		}
		closed := make(chan struct{})
		go func() {
			_ = l.Close()
			close(closed)
		}()
		runtime.Gosched()
		close(release)
		select {
		case <-closed:
		case <-time.After(2 * time.Second):
			t.Fatal("Close deadlocked with a Close from the accept filter")
		}
	}
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
	accepted := make(chan net.Conn, 1)
	go func() {
		if c, err := l.Accept(); err == nil {
			accepted <- c
		}
	}()
	var c net.Conn
	for i := 0; i < 5 && c == nil; i++ {
		_, _ = a.Write([]byte("hi"))
		select {
		case c = <-accepted:
		case <-time.After(time.Second):
		}
	}
	if c == nil {
		t.Fatal("Accept() returned no connection")
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
	l := newUDPListener(t, WithPacketMaxDatagram(4))
	a := dialUDP(t, l)
	send(t, l, a, "truncated")
	c := acceptWithin(t, l)
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
	// Long enough that the Read below comes before the sweep on a busy host.
	const idle = 300 * time.Millisecond
	l := newUDPListener(t, WithPacketIdleTimeout(idle))
	a := dialUDP(t, l)
	send(t, l, a, "x")
	// Several sweeps run while the connection waits for Accept.
	time.Sleep(2 * idle)
	c := acceptWithin(t, l)
	if c.(*packetConn).q.IdleAt(dgram.Mono(time.Now()), idle) {
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
	send(t, l, a, "a")
	waitUntil(t, func() bool { return l.conns.Pending() == 1 })
	stale, _ := l.conns.Get(peerKey{ap: a.LocalAddr().(*net.UDPAddr).AddrPort()})
	if stale == nil {
		t.Fatal("no connection for the first peer")
	}
	stale.shutdown(io.EOF)
	send(t, l, b, "b")
	c := acceptWithin(t, l)
	if got, want := c.RemoteAddr().String(), b.LocalAddr().String(); got != want {
		t.Fatalf("Accept() returned the peer %s, want %s past the closed connection", got, want)
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

// feedPacketConn is a PacketConn whose datagrams, from any source, the test
// feeds in.
type feedPacketConn struct {
	in chan feedDatagram
	// last is closed by the read after the one that returned it: the read
	// loop dispatches a datagram before it reads the next.
	last   chan struct{}
	closed chan struct{}
	once   sync.Once
}

type feedDatagram struct {
	from netip.AddrPort
	data []byte
	done chan struct{} // set by feed
}

func newFeedPacketConn() *feedPacketConn {
	return &feedPacketConn{in: make(chan feedDatagram), closed: make(chan struct{})}
}

func (c *feedPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	// Only the read loop calls ReadFrom, so last needs no lock.
	if c.last != nil {
		close(c.last)
		c.last = nil
	}
	select {
	case d := <-c.in:
		c.last = d.done
		return copy(b, d.data), net.UDPAddrFromAddrPort(d.from), nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

// feed hands d to the read loop and waits until it was dispatched: the next
// read has begun.
func (c *feedPacketConn) feed(t *testing.T, d feedDatagram) {
	t.Helper()
	d.done = make(chan struct{})
	c.in <- d
	select {
	case <-d.done:
	case <-time.After(5 * time.Second):
		t.Fatal("the read loop did not dispatch the datagram")
	}
}

func (c *feedPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) { return len(b), nil }
func (c *feedPacketConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}
func (c *feedPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
}
func (c *feedPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *feedPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *feedPacketConn) SetWriteDeadline(time.Time) error { return nil }

// A flood from spoofed sources takes no more than WithPacketMaxConns
// places; the connections there keep receiving, and a place freed by Close
// goes to the next new peer.
func TestPacketListenerMaxConnsSpoofedFlood(t *testing.T) {
	const limit = 4
	pc := newFeedPacketConn()
	var filtered atomic.Int64
	l := NewPacketListener(pc, WithPacketMaxConns(limit), WithPacketAcceptBacklog(1000), WithPacketAcceptFilter(func(net.Addr, []byte) bool {
		filtered.Add(1)
		return true
	}))
	defer func() { _ = l.Close() }()
	src := func(i int) netip.AddrPort {
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, byte(i >> 8), byte(i)}), uint16(1000+i))
	}
	for i := range 500 {
		pc.feed(t, feedDatagram{from: src(i), data: []byte("x")})
	}
	if n, f := l.conns.Len(), filtered.Load(); n != limit || f != limit {
		t.Fatalf("%d connections after the flood, the filter ran %d times; want %d of each", n, f, limit)
	}
	c := acceptWithin(t, l)
	pc.feed(t, feedDatagram{from: src(0), data: []byte("y")})
	buf := make([]byte, 4)
	for _, want := range []string{"x", "y"} {
		if n, err := c.Read(buf); err != nil || string(buf[:n]) != want {
			t.Fatalf("Read() = %q, %v; want %q from a peer that holds a place", buf[:n], err, want)
		}
	}
	if _, err := l.Dial(net.UDPAddrFromAddrPort(src(999))); !errors.Is(err, ErrPacketConnLimit) {
		t.Fatalf("Dial() at the limit = %v, want ErrPacketConnLimit", err)
	}
	_ = c.Close()
	pc.feed(t, feedDatagram{from: src(600), data: []byte("z")})
	if n := l.conns.Len(); n != limit {
		t.Fatalf("%d connections after a place was freed, want %d", n, limit)
	}
	if _, ok := l.conns.Get(peerKey{ap: src(600)}); !ok {
		t.Fatal("the freed place did not go to the next new peer")
	}
}
