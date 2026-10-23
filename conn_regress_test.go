package netx

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/djylb/netx/internal/dgram"
)

// WrapConn without a parent takes addresses and deadlines from rwc itself
// when it is a net.Conn, not from the connection beneath its wrappers.
func TestWrapConnNilParentKeepsRWCWrappers(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	override := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 4242}
	c := WrapConn(NewAddrOverrideConn(a, nil, override), nil)
	if got := c.RemoteAddr(); got != override {
		t.Fatalf("RemoteAddr() = %v, want the override %v", got, override)
	}
	if raw := InnermostConn(c); raw != a {
		t.Fatalf("InnermostConn() = %v, want the pipe", raw)
	}
	var nilConn *net.TCPConn
	if got := WrapConn(nilConn, nil); got.LocalAddr() != nil {
		t.Fatalf("WrapConn(nil *TCPConn) LocalAddr() = %v, want nil", got.LocalAddr())
	}
}

func TestPrefixConnNilState(t *testing.T) {
	var nilPrefix *PrefixConn
	for name, c := range map[string]*PrefixConn{
		"NewPrefixConn(nil)": NewPrefixConn(nil, []byte("x")),
		"nil *PrefixConn":    nilPrefix,
		"zero PrefixConn":    {},
	} {
		assertClosedConnState(t, name, c)
	}
}

// A stream Read cut short by a deadline does not keep the timeout once the
// deadline has moved: the next Read returns the rest of the frame.
func TestFramedConnShortReadTimeoutNotKept(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()
	fc := NewFramedConn(client)
	buf := make([]byte, 64)

	wrote, done := make(chan struct{}), make(chan error, 1)
	go func() { _, _ = server.Write([]byte{0, 4, 'a', 'b'}); close(wrote) }()
	go func() {
		n, err := fc.Read(buf)
		if err == nil && string(buf[:n]) != "ab" {
			err = errors.New("read " + string(buf[:n]))
		}
		done <- err
	}()
	<-wrote
	_ = fc.SetReadDeadline(time.Now())
	if err := <-done; err != nil {
		t.Fatalf("first Read: %v", err)
	}
	_ = fc.SetReadDeadline(time.Time{})
	go func() { _, _ = server.Write([]byte("cd")) }()
	if n, err := fc.Read(buf); err != nil || string(buf[:n]) != "cd" {
		t.Fatalf("Read() after clearing the deadline = %q, %v, want %q", buf[:n], err, "cd")
	}
}

// An AddrOverrideConn passes its data through unchanged, so Relay looks
// through it for splicing and WriteTo copies the wrapped connection.
func TestAddrOverrideConnPassesDataThrough(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	c := NewAddrOverrideConn(a, nil, &net.TCPAddr{Port: 1})
	if got := newRelaySource(c).base; got != a {
		t.Fatalf("relay source base = %v, want the wrapped conn", got)
	}
	if got := sinkWriter(NewPrefixConn(c, nil)); got != a {
		t.Fatalf("relay sink writer = %v, want the wrapped conn", got)
	}
	go func() { _, _ = b.Write([]byte("hello")); _ = b.Close() }()
	var out bytes.Buffer
	if n, err := c.WriteTo(&out); err != nil || n != 5 || out.String() != "hello" {
		t.Fatalf("WriteTo() = %d, %v, %q", n, err, out.String())
	}
	var nilConn *AddrOverrideConn
	if _, err := nilConn.WriteTo(io.Discard); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("nil WriteTo() error = %v, want %v", err, net.ErrClosed)
	}
}

// InnermostConn returns nil, not a nil pointer in an interface, for a nil
// connection, so that callers can check the result against nil.
func TestInnermostConnNilPointer(t *testing.T) {
	var tcp *net.TCPConn
	if got := InnermostConn(tcp); got != nil {
		t.Fatalf("InnermostConn(nil *net.TCPConn) = %#v, want nil", got)
	}
	if got := InnermostConn(NewPrefixConn(tcp, nil)); got != nil {
		t.Fatalf("InnermostConn(PrefixConn over nil) = %#v, want nil", got)
	}
}

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
		for !dgram.IsClosed(l.conns.Done()) {
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

// deadlineRaceConn returns part of a frame with a timeout from an expired
// deadline, as a Read does when a concurrent SetReadDeadline extends the
// deadline just after the timeout woke it.
type deadlineRaceConn struct {
	byteBufferConn
	fc   *FramedConn
	step int
}

func (c *deadlineRaceConn) Read(p []byte) (int, error) {
	c.step++
	switch c.step {
	case 1:
		return copy(p, []byte{0, 4}), nil
	case 2:
		p[0] = 'a'
		_ = c.fc.SetReadDeadline(time.Now().Add(time.Hour))
		return 1, &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}
	default:
		return copy(p, "bcd"), nil
	}
}

func TestFramedConnDropsTimeoutOfDeadlineSetDuringRead(t *testing.T) {
	raw := &deadlineRaceConn{}
	fc := NewFramedConn(raw)
	raw.fc = fc
	buf := make([]byte, 8)
	if n, err := fc.Read(buf); n != 1 || err != nil {
		t.Fatalf("first Read() = %d, %v, want 1 byte", n, err)
	}
	n, err := fc.Read(buf)
	if err != nil || string(buf[:n]) != "bcd" {
		t.Fatalf("second Read() = %q, %v, want the rest of the frame: the deadline was moved an hour ahead", buf[:n], err)
	}
}

// unexpectedEOFConn ends after a frame header with the io.ErrUnexpectedEOF
// that a TLS connection returns when TCP ends inside a record.
type unexpectedEOFConn struct {
	byteBufferConn
	step int
}

func (c *unexpectedEOFConn) Read(p []byte) (int, error) {
	c.step++
	if c.step == 1 {
		return copy(p, []byte{0, 5}), nil
	}
	return 0, io.ErrUnexpectedEOF
}

func TestFramedConnUnexpectedEOFInsideFrameDesyncs(t *testing.T) {
	for _, mode := range []string{"ReadFrame", "datagram", "datagram discard", "stream"} {
		var err error
		switch mode {
		case "ReadFrame":
			_, err = NewFramedConn(&unexpectedEOFConn{}).ReadFrame()
		case "datagram":
			_, err = NewFramedConn(&unexpectedEOFConn{}, WithFramedDatagrams()).Read(make([]byte, 8))
		case "datagram discard":
			// An empty buffer discards the whole payload.
			_, err = NewFramedConn(&unexpectedEOFConn{}, WithFramedDatagrams()).Read(nil)
		case "stream":
			_, err = NewFramedConn(&unexpectedEOFConn{}).Read(make([]byte, 8))
		}
		if !errors.Is(err, ErrFrameDesync) && (mode != "stream" || !errors.Is(err, io.EOF)) {
			t.Errorf("%s: error = %v, want ErrFrameDesync", mode, err)
		}
	}
}

// cyclicThroughNetx is a wrapper whose RawConn returns one of this package's
// wrappers around itself.
type cyclicThroughNetx struct {
	countedCloseConn
	outer net.Conn
}

func (c *cyclicThroughNetx) NetConn() net.Conn { return c.outer }

func TestInnermostConnStopsOnCyclesThroughWrappers(t *testing.T) {
	c := &cyclicThroughNetx{}
	c.outer = NewTimeoutConn(c, time.Second)
	if got := InnermostConn(c); got == nil {
		t.Fatal("InnermostConn(cycle) = nil, want a conn from the cycle")
	}
	parent := &countedCloseConn{}
	if err := WrapConn(c, parent, WithWrapParentClose()).Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if readsDatagrams(NewPrefixConn(c.outer, nil)) {
		t.Fatal("readsDatagrams(cycle) = true, want false")
	}
}

// Chains of this package's wrappers unwrap to the innermost connection
// however deep they are, and a wrapper pointed back at itself stops.
func TestInnermostConnDeepAndSelfReferentialWrappers(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	deep := a
	for range 40 {
		deep = NewTimeoutConn(NewPrefixConn(deep, nil), time.Second)
	}
	if got := InnermostConn(deep); got != a {
		t.Fatalf("InnermostConn(80 wrappers) = %T, want the pipe", got)
	}
	self := NewPrefixConn(nil, nil)
	self.conn = self
	if got := InnermostConn(self); got == nil {
		t.Fatal("InnermostConn(self-referential wrapper) = nil, want a conn from the cycle")
	}
}

// overridingConn embeds a wrapper of this package but has a RawConn of its
// own, which unwrapping must follow.
type overridingConn struct {
	*TimeoutConn
	alt net.Conn
}

func (c overridingConn) NetConn() net.Conn { return c.alt }

func TestInnermostConnFollowsEmbeddingTypesRawConn(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	c := overridingConn{TimeoutConn: NewTimeoutConn(a, time.Second), alt: b}
	if got := InnermostConn(c); got != b {
		t.Fatalf("InnermostConn() = %v, want the connection its RawConn returns", got)
	}
}

// ConnAs finds a connection of a type beneath wrappers, also through NetConn
// methods of other packages' wrappers.
func TestConnAs(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	timeout := NewTimeoutConn(a, time.Minute)
	c := NewPrefixConn(WrapConn(&netConnOnly{timeout}, nil), nil)
	if got, ok := ConnAs[*TimeoutConn](c); !ok || got != timeout {
		t.Fatalf("ConnAs[*TimeoutConn]() = %v, %v", got, ok)
	}
	if got, ok := ConnAs[*PrefixConn](c); !ok || got != c {
		t.Fatalf("ConnAs[*PrefixConn]() = %v, %v; want c itself", got, ok)
	}
	if _, ok := ConnAs[*FramedConn](c); ok {
		t.Fatal("ConnAs[*FramedConn]() found one that is not there")
	}
	if got, ok := ConnAs[interface{ CloseWrite() error }](c); !ok || got == nil {
		t.Fatal("ConnAs[interface] did not find a CloseWrite")
	}
	if InnermostConn(c) != a {
		t.Fatal("InnermostConn() is not the pipe")
	}
}

// netConnOnly is another package's wrapper that only shows what it wraps
// through NetConn.
type netConnOnly struct{ c net.Conn }

func (n *netConnOnly) Read(b []byte) (int, error)  { return n.c.Read(b) }
func (n *netConnOnly) Write(b []byte) (int, error) { return n.c.Write(b) }
func (n *netConnOnly) Close() error                { return n.c.Close() }
func (n *netConnOnly) NetConn() net.Conn           { return n.c }
