package transparent

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"
)

// testFlowListener returns a listener on a loopback socket whose read loop
// does not run: tests hand it datagrams with deliver.
func testFlowListener(t *testing.T, opts ...FlowOption) *FlowListener {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	l := newFlowListener(c, opts)
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func redirectedInfo(src, dst string) PacketInfo {
	return PacketInfo{Src: netip.MustParseAddrPort(src), Dst: netip.MustParseAddrPort(dst), Redirected: true}
}

func acceptFlow(t *testing.T, l *FlowListener) *FlowConn {
	t.Helper()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := l.Accept()
		accepted <- c
	}()
	select {
	case <-time.After(5 * time.Second):
		t.Fatal("Accept timed out")
	case c := <-accepted:
		if c == nil {
			t.Fatal("Accept failed")
		}
		return c.(*FlowConn)
	}
	return nil
}

func readFlow(t *testing.T, f *FlowConn, want string) {
	t.Helper()
	_ = f.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	n, err := f.Read(buf)
	if err != nil || string(buf[:n]) != want {
		t.Fatalf("Read() = %q, %v; want %q", buf[:n], err, want)
	}
}

func TestFlowKeying(t *testing.T) {
	l := testFlowListener(t)
	l.deliver([]byte("a1"), redirectedInfo("192.0.2.1:1000", "198.51.100.1:53"))
	l.deliver([]byte("a2"), redirectedInfo("192.0.2.1:1000", "198.51.100.1:53"))
	l.deliver([]byte("b"), redirectedInfo("192.0.2.1:1000", "198.51.100.2:53"))
	l.deliver([]byte("c"), redirectedInfo("192.0.2.2:1000", "198.51.100.1:53"))
	if n := l.flows.Pending(); n != 3 {
		t.Fatalf("%d flows started, want 3", n)
	}
	for _, want := range []struct{ src, dst, data string }{
		{"192.0.2.1:1000", "198.51.100.1:53", "a1"},
		{"192.0.2.1:1000", "198.51.100.2:53", "b"},
		{"192.0.2.2:1000", "198.51.100.1:53", "c"},
	} {
		f := acceptFlow(t, l)
		if f.RemoteAddr().String() != want.src || f.LocalAddr().String() != want.dst || !f.Redirected() {
			t.Fatalf("flow %v -> %v, redirected %v; want %s -> %s, true", f.RemoteAddr(), f.LocalAddr(), f.Redirected(), want.src, want.dst)
		}
		readFlow(t, f, want.data)
		if want.data == "a1" {
			readFlow(t, f, "a2")
		}
	}
}

func TestFlowDropsDirectDatagrams(t *testing.T) {
	l := testFlowListener(t)
	info := redirectedInfo("192.0.2.1:1000", "127.0.0.1:53")
	info.Redirected = false
	l.deliver([]byte("x"), info)
	if n := l.flows.Pending(); n != 0 {
		t.Fatalf("%d direct flows started, want 0", n)
	}
}

// A direct flow, with WithFlowDirect, is answered from the listening socket.
func TestFlowDirect(t *testing.T) {
	l := testFlowListener(t, WithFlowDirect())
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	lnAddr := l.Addr().(*net.UDPAddr).AddrPort()
	l.deliver([]byte("ping"), PacketInfo{Src: client.LocalAddr().(*net.UDPAddr).AddrPort(), Dst: lnAddr})
	f := acceptFlow(t, l)
	if f.Redirected() {
		t.Fatal("direct flow reports redirected")
	}
	readFlow(t, f, "ping")
	if _, err := f.Write([]byte("pong")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	buf := make([]byte, 16)
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, from, err := client.ReadFromUDPAddrPort(buf)
	if err != nil || string(buf[:n]) != "pong" || from != lnAddr {
		t.Fatalf("client got %q from %v, %v; want pong from %v", buf[:n], from, err, lnAddr)
	}
}

func TestFlowAcceptBacklog(t *testing.T) {
	l := testFlowListener(t, WithFlowAcceptBacklog(2))
	for _, src := range []string{"192.0.2.1:1", "192.0.2.1:2", "192.0.2.1:3"} {
		l.deliver([]byte(src), redirectedInfo(src, "198.51.100.1:53"))
	}
	if n := l.flows.Pending(); n != 2 {
		t.Fatalf("%d flows wait for Accept, want 2", n)
	}
	if _, ok := l.flows.Get(flowKey{src: netip.MustParseAddrPort("192.0.2.1:3"), dst: netip.MustParseAddrPort("198.51.100.1:53")}); ok {
		t.Fatal("a flow beyond the backlog was kept")
	}
	_ = acceptFlow(t, l)
	l.deliver([]byte("4"), redirectedInfo("192.0.2.1:4", "198.51.100.1:53"))
	if n := l.flows.Pending(); n != 2 {
		t.Fatalf("%d flows wait for Accept after one was accepted, want 2", n)
	}
}

func TestFlowQueue(t *testing.T) {
	l := testFlowListener(t, WithFlowQueue(2))
	info := redirectedInfo("192.0.2.1:1000", "198.51.100.1:53")
	for _, p := range []string{"1", "2", "3"} {
		l.deliver([]byte(p), info)
	}
	f := acceptFlow(t, l)
	readFlow(t, f, "1")
	readFlow(t, f, "2")
	_ = f.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if n, err := f.Read(make([]byte, 8)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read() = %d, %v; want the third datagram dropped", n, err)
	}

	// Large datagrams take the room of several: 2 × 2 KiB holds one of 3000
	// bytes, and one more of any size does not fit beside it.
	l.deliver(make([]byte, 3000), info)
	l.deliver([]byte("small"), info)
	_ = f.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4000)
	if n, err := f.Read(buf); err != nil || n != 3000 {
		t.Fatalf("Read() = %d, %v; want 3000", n, err)
	}
	_ = f.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if n, err := f.Read(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read() = %d, %v; want the datagram beyond the room dropped", n, err)
	}
	// An empty queue takes one datagram larger than its room.
	l.deliver(make([]byte, 6000), info)
	_ = f.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := f.Read(make([]byte, 8000)); err != nil || n != 6000 {
		t.Fatalf("Read() = %d, %v; want 6000", n, err)
	}
	// Each Read returns one datagram, truncated to the buffer.
	l.deliver([]byte("truncated"), info)
	readFlowN(t, f, 4, "trun")
}

func readFlowN(t *testing.T, f *FlowConn, size int, want string) {
	t.Helper()
	_ = f.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, size)
	n, err := f.Read(buf)
	if err != nil || string(buf[:n]) != want {
		t.Fatalf("Read() = %q, %v; want %q", buf[:n], err, want)
	}
}

func TestFlowIdleTimeout(t *testing.T) {
	l := testFlowListener(t, WithFlowIdleTimeout(50*time.Millisecond))
	info := redirectedInfo("192.0.2.1:1000", "198.51.100.1:53")
	l.deliver([]byte("1"), info)
	f := acceptFlow(t, l)
	readFlow(t, f, "1")
	_ = f.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := f.Read(make([]byte, 8)); !errors.Is(err, io.EOF) {
		t.Fatalf("Read() of an idle flow error = %v, want io.EOF", err)
	}
	if _, err := f.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Write() of an idle flow error = %v, want net.ErrClosed", err)
	}
	// The next datagram of the flow starts another.
	l.deliver([]byte("2"), info)
	g := acceptFlow(t, l)
	if g == f {
		t.Fatal("the idle flow was reused")
	}
	readFlow(t, g, "2")

	// A flow waiting for Accept is kept however long it waits.
	l.deliver([]byte("3"), redirectedInfo("192.0.2.1:1001", "198.51.100.1:53"))
	time.Sleep(150 * time.Millisecond)
	h := acceptFlow(t, l)
	readFlow(t, h, "3")
}

func TestFlowClose(t *testing.T) {
	l := testFlowListener(t)
	info := redirectedInfo("192.0.2.1:1000", "198.51.100.1:53")
	l.deliver([]byte("1"), info)
	f := acceptFlow(t, l)
	blocked := make(chan error, 1)
	go func() {
		_, err := f.Read(make([]byte, 8))
		if err == nil {
			_, err = f.Read(make([]byte, 8))
		}
		blocked <- err
	}()
	time.Sleep(10 * time.Millisecond)
	if err := f.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := <-blocked; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("blocked Read() error = %v, want net.ErrClosed", err)
	}
	if _, err := f.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Write() error = %v, want net.ErrClosed", err)
	}
	if err := f.SetDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("SetDeadline() error = %v, want net.ErrClosed", err)
	}
	if err := f.Close(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("second Close() error = %v, want net.ErrClosed", err)
	}
	l.deliver([]byte("2"), info)
	readFlow(t, acceptFlow(t, l), "2")
}

func TestFlowListenerClose(t *testing.T) {
	l := testFlowListener(t)
	l.deliver([]byte("1"), redirectedInfo("192.0.2.1:1", "198.51.100.1:53"))
	l.deliver([]byte("2"), redirectedInfo("192.0.2.1:2", "198.51.100.1:53"))
	accepted := acceptFlow(t, l)
	waiting, _ := l.flows.Get(flowKey{src: netip.MustParseAddrPort("192.0.2.1:2"), dst: netip.MustParseAddrPort("198.51.100.1:53")})
	if err := l.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	for _, f := range []*FlowConn{accepted, waiting} {
		if _, err := f.Read(make([]byte, 8)); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Read() after listener Close error = %v, want net.ErrClosed", err)
		}
	}
	if _, err := l.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept() error = %v, want net.ErrClosed", err)
	}
	l.deliver([]byte("3"), redirectedInfo("192.0.2.1:3", "198.51.100.1:53"))
	if l.flows.Pending() != 0 || l.flows.Len() != 0 {
		t.Fatal("a closed listener started a flow")
	}
}

// Accept skips a flow closed while it waited.
func TestFlowAcceptSkipsClosed(t *testing.T) {
	l := testFlowListener(t)
	l.deliver([]byte("1"), redirectedInfo("192.0.2.1:1", "198.51.100.1:53"))
	l.deliver([]byte("2"), redirectedInfo("192.0.2.1:2", "198.51.100.1:53"))
	first, _ := l.flows.Get(flowKey{src: netip.MustParseAddrPort("192.0.2.1:1"), dst: netip.MustParseAddrPort("198.51.100.1:53")})
	_ = first.Close()
	c, err := l.Accept()
	if err != nil || c.RemoteAddr().String() != "192.0.2.1:2" {
		t.Fatalf("Accept() = %v, %v; want the open flow", c, err)
	}
}

func TestFlowReadDeadline(t *testing.T) {
	l := testFlowListener(t)
	info := redirectedInfo("192.0.2.1:1000", "198.51.100.1:53")
	l.deliver([]byte("1"), info)
	f := acceptFlow(t, l)
	readFlow(t, f, "1")
	_ = f.SetReadDeadline(time.Now().Add(-time.Second))
	if _, err := f.Read(make([]byte, 8)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read() past the deadline error = %v", err)
	}
	// Extending the deadline lets a waiting Read go on.
	_ = f.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	got := make(chan error, 1)
	go func() {
		_, err := f.Read(make([]byte, 8))
		got <- err
	}()
	time.Sleep(5 * time.Millisecond)
	_ = f.SetReadDeadline(time.Time{})
	time.Sleep(60 * time.Millisecond)
	l.deliver([]byte("2"), info)
	if err := <-got; err != nil {
		t.Fatalf("Read() after clearing the deadline error = %v", err)
	}
}

// Flows and listeners leave no goroutines or descriptors behind.
func TestFlowNoLeaks(t *testing.T) {
	fds := openFDs(t)
	goroutines := runtime.NumGoroutine()
	for range 20 {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		l := newFlowListener(c, []FlowOption{WithFlowIdleTimeout(time.Millisecond), WithFlowDirect()})
		for i := range 10 {
			l.deliver([]byte("x"), PacketInfo{Src: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(1000+i)), Dst: c.LocalAddr().(*net.UDPAddr).AddrPort()})
		}
		// Some flows are closed, some time out, the rest close with l.
		for i := range 5 {
			f, err := l.Accept()
			if err != nil {
				t.Fatal(err)
			}
			_, _ = f.Write([]byte("y"))
			if i%2 == 0 {
				_ = f.Close()
			}
		}
		_ = l.Close()
	}
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > goroutines && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > goroutines {
		t.Errorf("%d goroutines, want at most %d", n, goroutines)
	}
	if n := openFDs(t); n > fds {
		t.Errorf("%d open descriptors, want at most %d", n, fds)
	}
}

// openFDs counts the descriptors of this process. It first starts the
// runtime's network poller, whose descriptors stay open for the life of the
// process, so a count taken before the first socket is comparable to one
// taken after.
func openFDs(t *testing.T) int {
	t.Helper()
	if pc, err := net.ListenPacket("udp", "127.0.0.1:0"); err == nil {
		_ = pc.Close()
	}
	entries, err := os.ReadDir("/dev/fd")
	if err != nil {
		t.Skipf("cannot count descriptors: %v", err)
	}
	return len(entries)
}

// A flow leaves its listener before it closes, so that a datagram arriving
// while it closes starts a new flow instead of being dropped.
func TestFlowShutdownRemovesFirst(t *testing.T) {
	l := testFlowListener(t)
	info := redirectedInfo("192.0.2.1:1000", "198.51.100.1:53")
	l.deliver([]byte("1"), info)
	f := acceptFlow(t, l)
	var open bool
	testHookFlowShutdown = func(g *FlowConn) {
		if g == f {
			open = !f.q.Closed()
			l.deliver([]byte("2"), info)
		}
	}
	defer func() { testHookFlowShutdown = nil }()
	_ = f.Close()
	if !open {
		t.Fatal("the flow was closed before it left the listener")
	}
	g := acceptFlow(t, l)
	if g == f {
		t.Fatal("the datagram went to the closing flow")
	}
	readFlow(t, g, "2")
}

// A flood of spoofed sources takes no more than WithFlowMaxConns places;
// the flows there keep receiving, and a place freed by Close goes to the
// next new flow.
func TestFlowMaxConnsSpoofedFlood(t *testing.T) {
	const limit = 4
	l := testFlowListener(t, WithFlowMaxConns(limit), WithFlowAcceptBacklog(1000))
	src := func(i int) string {
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, byte(i >> 8), byte(i)}), 1000).String()
	}
	for i := range 500 {
		l.deliver([]byte("x"), redirectedInfo(src(i), "198.51.100.1:53"))
	}
	if n := l.flows.Len(); n != limit {
		t.Fatalf("%d flows after the flood, want %d", n, limit)
	}
	f := acceptFlow(t, l)
	l.deliver([]byte("y"), redirectedInfo(src(0), "198.51.100.1:53"))
	readFlow(t, f, "x")
	readFlow(t, f, "y")
	_ = f.Close()
	l.deliver([]byte("z"), redirectedInfo(src(600), "198.51.100.1:53"))
	if _, ok := l.flows.Get(flowKey{src: netip.MustParseAddrPort(src(600)), dst: netip.MustParseAddrPort("198.51.100.1:53")}); !ok || l.flows.Len() != limit {
		t.Fatal("the freed place did not go to the next new flow")
	}
}

// As on a socket, an expired read deadline fails Read even while datagrams
// are queued.
func TestFlowReadHonorsDeadlineBeforeQueue(t *testing.T) {
	l := testFlowListener(t)
	info := redirectedInfo("192.0.2.1:1000", "198.51.100.1:53")
	l.deliver([]byte("1"), info)
	f := acceptFlow(t, l)
	_ = f.SetReadDeadline(time.Now().Add(-time.Second))
	for range 3 {
		if _, err := f.Read(make([]byte, 8)); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("Read() past the deadline = %v, want ErrDeadlineExceeded", err)
		}
	}
	_ = f.SetReadDeadline(time.Time{})
	readFlow(t, f, "1")
}
