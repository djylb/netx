package netx

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"
)

// WrapConn without a parent takes addresses and deadlines from rwc itself
// when it is a net.Conn, not from the connection beneath its wrappers.
func TestWrapConnNilParentKeepsRWCWrappers(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	override := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 4242}
	c := WrapConn(NewAddrOverrideConn(a, override, nil), nil)
	if got := c.RemoteAddr(); got != override {
		t.Fatalf("RemoteAddr() = %v, want the override %v", got, override)
	}
	if raw := RawConnOf(c); raw != a {
		t.Fatalf("RawConnOf() = %v, want the pipe", raw)
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
	c := NewAddrOverrideConn(a, &net.TCPAddr{Port: 1}, nil)
	if got := unwrapPrefix(c); got != a {
		t.Fatalf("unwrapPrefix() = %v, want the wrapped conn", got)
	}
	if got := unwrapPrefixWriter(NewPrefixConn(c, nil)); got != a {
		t.Fatalf("unwrapPrefixWriter() = %v, want the wrapped conn", got)
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

// RawConnOf returns nil, not a nil pointer in an interface, for a nil
// connection, so that callers can check the result against nil.
func TestRawConnOfNilPointer(t *testing.T) {
	var tcp *net.TCPConn
	if got := RawConnOf(tcp); got != nil {
		t.Fatalf("RawConnOf(nil *net.TCPConn) = %#v, want nil", got)
	}
	if got := RawConnOf(NewPrefixConn(tcp, nil)); got != nil {
		t.Fatalf("RawConnOf(PrefixConn over nil) = %#v, want nil", got)
	}
}

// Close must not wait for the accept filter when it runs concurrently with
// it, or a caller that holds a lock the filter takes, such as one guarding an
// allow list, deadlocks with the read loop. Here Close runs just before the
// filter would.
func TestPacketListenerCloseHoldingFilterLock(t *testing.T) {
	var mu sync.Mutex
	closed := make(chan struct{})
	testHookBeforeFilter = func(l *PacketListener) {
		testHookBeforeFilter = nil
		go func() {
			mu.Lock()
			_ = l.Close()
			mu.Unlock()
			close(closed)
		}()
		for !isClosedChan(l.done) {
			runtime.Gosched()
		}
	}
	defer func() { testHookBeforeFilter = nil }()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	filtered := make(chan struct{}, 1)
	NewPacketListener(pc, WithAcceptFilter(func(net.Addr) bool {
		filtered <- struct{}{}
		mu.Lock()
		defer mu.Unlock()
		return true
	}))
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

// A datagram that races with the connection's Close must not stay queued,
// holding its pooled buffer, on the closed connection.
func TestPacketConnEnqueueAfterShutdownReleasesBuffer(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := NewPacketListener(pc)
	defer func() { _ = l.Close() }()
	for i := range 200 {
		c := &packetConn{l: l, peer: &net.UDPAddr{Port: 1}, queue: make(chan *[]byte, 4),
			closed: make(chan struct{}), readDeadline: makeDeadline(), writeDeadline: makeDeadline()}
		c.shutdown(net.ErrClosed)
		c.enqueue([]byte("y"))
		if n := len(c.queue); n != 0 {
			t.Fatalf("attempt %d: %d datagrams queued on a closed connection", i, n)
		}
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
			_, err = NewFramedConn(&unexpectedEOFConn{}, WithDatagramReads()).Read(make([]byte, 8))
		case "datagram discard":
			// An empty buffer discards the whole payload.
			_, err = NewFramedConn(&unexpectedEOFConn{}, WithDatagramReads()).Read(nil)
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

func (c *cyclicThroughNetx) RawConn() net.Conn { return c.outer }

func TestRawConnOfStopsOnCyclesThroughWrappers(t *testing.T) {
	c := &cyclicThroughNetx{}
	c.outer = NewTimeoutConn(c, time.Second)
	if got := RawConnOf(c); got == nil {
		t.Fatal("RawConnOf(cycle) = nil, want a conn from the cycle")
	}
	parent := &countedCloseConn{}
	if err := WrapConn(c, parent, WithParentClose()).Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if datagramReader(NewPrefixConn(c.outer, nil)) {
		t.Fatal("datagramReader(cycle) = true, want false")
	}
}

// Chains of this package's wrappers unwrap to the innermost connection
// however deep they are, and a wrapper pointed back at itself stops.
func TestRawConnOfDeepAndSelfReferentialWrappers(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	deep := a
	for range 40 {
		deep = NewTimeoutConn(NewPrefixConn(deep, nil), time.Second)
	}
	if got := RawConnOf(deep); got != a {
		t.Fatalf("RawConnOf(80 wrappers) = %T, want the pipe", got)
	}
	self := NewPrefixConn(nil, nil)
	self.Conn = self
	if got := RawConnOf(self); got == nil {
		t.Fatal("RawConnOf(self-referential wrapper) = nil, want a conn from the cycle")
	}
}

// overridingConn embeds a wrapper of this package but has a RawConn of its
// own, which unwrapping must follow.
type overridingConn struct {
	*TimeoutConn
	alt net.Conn
}

func (c overridingConn) RawConn() net.Conn { return c.alt }

func TestRawConnOfFollowsEmbeddingTypesRawConn(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	c := overridingConn{TimeoutConn: NewTimeoutConn(a, time.Second), alt: b}
	if got := RawConnOf(c); got != b {
		t.Fatalf("RawConnOf() = %v, want the connection its RawConn returns", got)
	}
}
