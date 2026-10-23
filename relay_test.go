package netx

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"runtime/debug"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/djylb/netx/internal/dgram"
	"github.com/djylb/netx/internal/netutil"
	"github.com/djylb/netx/proxyproto"
)

func tcpPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer func() { _ = ln.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	server = <-accepted
	if server == nil {
		_ = client.Close()
		t.Fatal("Accept() failed")
	}
	// Also when a test fails before closing them.
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return client, server
}

func TestRelayCopiesBothDirections(t *testing.T) {
	userA, relayA := tcpPair(t)
	relayB, userB := tcpPair(t)
	defer func() { _ = userA.Close() }()
	defer func() { _ = userB.Close() }()

	type result struct {
		aToB, bToA int64
		err        error
	}
	done := make(chan result, 1)
	go func() {
		aToB, bToA, err := Relay(context.Background(), relayA, relayB)
		done <- result{aToB, bToA, err}
	}()

	request := bytes.Repeat([]byte("a"), 100_000)
	response := bytes.Repeat([]byte("b"), 70_000)
	go func() { _, _ = userA.Write(request) }()
	got := make([]byte, len(request))
	if _, err := io.ReadFull(userB, got); err != nil || !bytes.Equal(got, request) {
		t.Fatalf("userB read error = %v", err)
	}
	go func() { _, _ = userB.Write(response) }()
	got = make([]byte, len(response))
	if _, err := io.ReadFull(userA, got); err != nil || !bytes.Equal(got, response) {
		t.Fatalf("userA read error = %v", err)
	}

	_ = userA.Close()
	select {
	case r := <-done:
		if r.err != nil || r.aToB != int64(len(request)) || r.bToA != int64(len(response)) {
			t.Fatalf("Relay(context.Background()) = %d, %d, %v", r.aToB, r.bToA, r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Relay(context.Background()) did not return after one side closed")
	}
	// Relay closed relayB, so userB sees EOF.
	if _, err := userB.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("userB Read() error = %v, want EOF", err)
	}
}

type failingRWC struct {
	readErr error
	closed  chan struct{}
}

func (f *failingRWC) Read([]byte) (int, error) { return 0, f.readErr }
func (f *failingRWC) Write(b []byte) (int, error) {
	return len(b), nil
}
func (f *failingRWC) Close() error {
	select {
	case <-f.closed:
	default:
		close(f.closed)
	}
	return nil
}

// blockingRWC blocks reads until closed, then fails them like a closed socket.
type blockingRWC struct {
	closed chan struct{}
}

func (b *blockingRWC) Read([]byte) (int, error) {
	<-b.closed
	return 0, net.ErrClosed
}
func (b *blockingRWC) Write(p []byte) (int, error) { return len(p), nil }
func (b *blockingRWC) Close() error {
	select {
	case <-b.closed:
	default:
		close(b.closed)
	}
	return nil
}

func TestRelayReportsFirstError(t *testing.T) {
	boom := errors.New("boom")
	a := &failingRWC{readErr: boom, closed: make(chan struct{})}
	b := &blockingRWC{closed: make(chan struct{})}
	_, _, err := Relay(context.Background(), a, b)
	if !errors.Is(err, boom) {
		t.Fatalf("Relay(context.Background()) error = %v, want %v", err, boom)
	}
	select {
	case <-b.closed:
	default:
		t.Fatal("Relay(context.Background()) did not close b")
	}
}

// With WithRelayHalfClose a client can shut down its sending side and still read
// the answer, which the backend sends after it has seen EOF.
func TestRelayHalfClose(t *testing.T) {
	testRelayHalfClose(t, func(c net.Conn) net.Conn { return c })
}

// Half-close and the byte counts work when only one end is a raw TCPConn.
func TestRelayHalfCloseMixedEnds(t *testing.T) {
	testRelayHalfClose(t, func(c net.Conn) net.Conn { return NewTimeoutConn(c, 5*time.Second) })
}

// testRelayHalfClose relays between a client and an echo backend that
// answers after EOF, with the backend's end of the relay passed through wrap.
func testRelayHalfClose(t *testing.T, wrap func(net.Conn) net.Conn) {
	t.Helper()
	client, relayA := tcpPair(t)
	relayB, backend := tcpPair(t)
	defer func() { _ = client.Close() }()
	defer func() { _ = backend.Close() }()

	go func() {
		request, _ := io.ReadAll(backend) // until the relayed EOF
		_, _ = backend.Write(append([]byte("echo:"), request...))
		_ = backend.(*net.TCPConn).CloseWrite()
	}()
	done := make(chan error, 1)
	var up, down int64
	go func() {
		var err error
		up, down, err = Relay(context.Background(), relayA, wrap(relayB), WithRelayHalfClose())
		done <- err
	}()

	_, _ = client.Write([]byte("ping"))
	_ = client.(*net.TCPConn).CloseWrite()
	answer, err := io.ReadAll(client)
	if err != nil || string(answer) != "echo:ping" {
		t.Fatalf("answer = %q, %v", answer, err)
	}
	if err := <-done; err != nil || up != 4 || down != 9 {
		t.Fatalf("Relay(context.Background()) = %d, %d, %v", up, down, err)
	}
}

// Without CloseWrite support the half-close option falls back to closing both.
func TestRelayHalfCloseFallsBackToClose(t *testing.T) {
	client, a := net.Pipe()
	b, backend := net.Pipe()
	go func() { _, _ = io.Copy(io.Discard, backend) }()
	done := make(chan error, 1)
	go func() {
		_, _, err := Relay(context.Background(), a, b, WithRelayHalfClose())
		done <- err
	}()
	_ = client.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Relay(context.Background()) error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Relay(context.Background()) did not return")
	}
}

// plainReader hides every method of its reader but Read.
type plainReader struct{ io.Reader }

// A direction with one raw *net.TCPConn end cannot splice; it must copy
// through the pooled buffer instead of one that TCPConn.ReadFrom allocates.
func TestRelayCopyPoolsBufferWithOneTCPEnd(t *testing.T) {
	client, server := tcpPair(t)
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()
	go func() {
		buf := make([]byte, 64<<10)
		for {
			if _, err := server.Read(buf); err != nil {
				return
			}
		}
	}()
	payload := make([]byte, 1024)
	copyOnce := func() {
		if n, err := copyPlain(client, plainReader{bytes.NewReader(payload)}); n != int64(len(payload)) || err != nil {
			t.Fatalf("copyPlain() = %d, %v", n, err)
		}
	}
	copyOnce() // warm up the pool
	const runs = 100
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for range runs {
		copyOnce()
	}
	runtime.ReadMemStats(&after)
	// The race detector drops a quarter of the pool's Puts, so allow some.
	if perCopy := (after.TotalAlloc - before.TotalAlloc) / runs; perCopy >= relayBufSize/2 {
		t.Fatalf("copyPlain() allocates %d bytes per copy, want the pooled buffer reused", perCopy)
	}
}

func TestRelayCanSplice(t *testing.T) {
	tcpA, tcpB := tcpPair(t)
	defer func() { _ = tcpA.Close() }()
	defer func() { _ = tcpB.Close() }()
	pipeA, pipeB := net.Pipe()
	defer func() { _ = pipeA.Close() }()
	defer func() { _ = pipeB.Close() }()
	tests := []struct {
		name string
		dst  io.Writer
		src  io.Reader
		want bool
	}{
		{"tcp to tcp", tcpA, tcpB, netutil.SpliceOS},
		{"prefixed tcp to tcp", tcpA, NewPrefixConn(NewPrefixConn(tcpB, []byte("a")), nil), netutil.SpliceOS},
		{"pipe to tcp", tcpA, pipeA, false},
		{"tcp to pipe", pipeA, tcpB, false},
		{"tcp to timeout tcp", NewTimeoutConn(tcpA, time.Second), tcpB, netutil.SpliceOS},
		{"timeout tcp to tcp", tcpA, NewPrefixConn(NewTimeoutConn(tcpB, time.Second), nil), netutil.SpliceOS},
		{"tcp to observed tcp", ObserveConn(tcpA, nil, func(int64) error { return nil }), tcpB, false},
		{"prefixed pipe to tcp", tcpA, NewPrefixConn(pipeA, nil), false},
		{"nil prefix conn to tcp", tcpA, (*PrefixConn)(nil), false},
	}
	for _, tt := range tests {
		if got := spliceable(tt.dst, tt.src); got != tt.want {
			t.Errorf("%s: spliceable() = %t, want %t", tt.name, got, tt.want)
		}
	}
}

// datagramConn returns one queued message per Read, truncated to b like a UDP
// socket, and records the size of each Write.
type datagramConn struct {
	mu     sync.Mutex
	msgs   [][]byte
	writes []int
}

func (c *datagramConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.msgs) == 0 {
		return 0, io.EOF
	}
	m := c.msgs[0]
	c.msgs = c.msgs[1:]
	return copy(b, m), nil
}

func (c *datagramConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes = append(c.writes, len(b))
	return len(b), nil
}

func (c *datagramConn) sizes() []int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]int(nil), c.writes...)
}

func (*datagramConn) Close() error                     { return nil }
func (*datagramConn) LocalAddr() net.Addr              { return &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 2} }
func (*datagramConn) RemoteAddr() net.Addr             { return &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1} }
func (*datagramConn) SetDeadline(time.Time) error      { return nil }
func (*datagramConn) SetReadDeadline(time.Time) error  { return nil }
func (*datagramConn) SetWriteDeadline(time.Time) error { return nil }

// oneConnListener accepts c once and then blocks until closed.
type oneConnListener struct {
	c    net.Conn
	once sync.Once
	done chan struct{}
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() { c = l.c })
	if c != nil {
		return c, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *oneConnListener) Close() error   { close(l.done); return nil }
func (l *oneConnListener) Addr() net.Addr { return l.c.LocalAddr() }

// A datagram larger than the pooled buffer reaches the other end whole through
// the WriteTo of a PROXY protocol datagram connection.
func TestRelayKeepsLargeProxyprotoDatagram(t *testing.T) {
	src := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 5}
	dst := &net.UDPAddr{IP: net.IPv4(6, 7, 8, 9), Port: 10}
	const size = 40000
	h, err := proxyproto.NewHeader(proxyproto.V1, src, dst)
	if err != nil {
		t.Fatal(err)
	}
	header, err := h.AppendBinary(nil)
	if err != nil {
		t.Fatal(err)
	}
	raw := &datagramConn{msgs: [][]byte{header, make([]byte, size), make([]byte, 7)}}
	ln := &proxyproto.Listener{Listener: &oneConnListener{c: raw, done: make(chan struct{})}, Config: proxyproto.Config{Datagram: true}}
	defer func() { _ = ln.Close() }()
	c, err := ln.Accept()
	if err != nil {
		t.Fatalf("Accept() error = %v", err)
	}
	if got := c.RemoteAddr().String(); got != src.String() {
		t.Fatalf("RemoteAddr() = %s, want %s", got, src)
	}
	sink := &datagramConn{}
	aToB, _, err := Relay(context.Background(), c, sink)
	if err != nil || aToB != size+7 {
		t.Fatalf("Relay(context.Background()) = %d, %v, want %d, nil", aToB, err, size+7)
	}
	if got := sink.sizes(); len(got) != 2 || got[0] != size || got[1] != 7 {
		t.Fatalf("datagrams written = %v, want [%d 7]", got, size)
	}
}

// customWriterTo counts the bytes it writes with its own WriteTo.
type customWriterTo struct {
	io.Reader
	calls int
}

func (c *customWriterTo) WriteTo(w io.Writer) (int64, error) {
	c.calls++
	return io.Copy(w, plainReader{c.Reader})
}

// customReaderFrom counts its ReadFrom calls.
type customReaderFrom struct {
	bytes.Buffer
	calls int
}

func (c *customReaderFrom) ReadFrom(r io.Reader) (int64, error) {
	c.calls++
	return c.Buffer.ReadFrom(r)
}

func TestRelayCopyUsesCustomWriterToAndReaderFrom(t *testing.T) {
	tcpA, tcpB := tcpPair(t)
	defer func() { _ = tcpA.Close() }()
	defer func() { _ = tcpB.Close() }()
	go func() { _, _ = io.Copy(io.Discard, tcpB) }()

	payload := bytes.Repeat([]byte("x"), 100<<10)
	for _, dst := range []io.Writer{tcpA, &bytes.Buffer{}} {
		src := &customWriterTo{Reader: bytes.NewReader(payload)}
		if n, err := copyPlain(dst, src); n != int64(len(payload)) || err != nil {
			t.Fatalf("copyPlain(%T) = %d, %v", dst, n, err)
		}
		if src.calls != 1 {
			t.Fatalf("copyPlain(%T) called WriteTo %d times, want 1", dst, src.calls)
		}
	}

	// Beneath a PrefixConn, the custom WriteTo is still reached.
	inner := &customWriterTo{Reader: bytes.NewReader(payload)}
	pc := NewPrefixConn(writerToConn{customWriterTo: inner}, []byte("head"))
	var out bytes.Buffer
	if n, err := copyPlain(&out, pc); n != int64(len(payload)+4) || err != nil || out.Len() != len(payload)+4 {
		t.Fatalf("copyPlain(prefix) = %d, %v, wrote %d", n, err, out.Len())
	}
	if inner.calls != 1 {
		t.Fatalf("copyPlain(prefix) called WriteTo %d times, want 1", inner.calls)
	}

	rf := &customReaderFrom{}
	if n, err := copyPlain(rf, plainReader{bytes.NewReader(payload)}); n != int64(len(payload)) || err != nil {
		t.Fatalf("copyPlain(ReaderFrom) = %d, %v", n, err)
	}
	if rf.calls != 1 || rf.Len() != len(payload) {
		t.Fatalf("ReadFrom calls = %d, buffered %d", rf.calls, rf.Len())
	}
}

// writerToConn is a net.Conn whose reads and WriteTo come from a customWriterTo.
type writerToConn struct {
	net.Conn
	*customWriterTo
}

func (c writerToConn) Read(b []byte) (int, error) { return c.customWriterTo.Read(b) }

// A PrefixConn that would end up in the fallback WriteTo or ReadFrom of a
// *net.TCPConn copies through the pooled buffer instead: over a raw TCPConn
// that cannot splice into dst, and over a connection without WriteTo into a
// TCPConn.
func TestRelayCopyPoolsBufferFromPrefixConn(t *testing.T) {
	if raceEnabled {
		// A copy from a socket gets the buffer again after each short read.
		t.Skip("the race detector makes sync.Pool drop buffers")
	}
	outClient, outServer := tcpPair(t)
	defer func() { _ = outClient.Close() }()
	defer func() { _ = outServer.Close() }()
	pipeA, pipeB := net.Pipe()
	defer func() { _ = pipeA.Close() }()
	defer func() { _ = pipeB.Close() }()
	drain := func(c net.Conn) {
		buf := make([]byte, 64<<10)
		for {
			if _, err := c.Read(buf); err != nil {
				return
			}
		}
	}
	go drain(pipeB)
	go drain(outServer)
	payload := make([]byte, 1024)

	// Each source holds the payload followed by EOF.
	tests := []struct {
		name   string
		dst    io.Writer
		source func() net.Conn
	}{
		{"prefixed tcp to pipe", pipeA, func() net.Conn {
			feed, c := tcpPair(t)
			t.Cleanup(func() { _ = c.Close() })
			_, _ = feed.Write(payload)
			_ = feed.Close()
			return c
		}},
		{"prefixed pipe to tcp", outClient, func() net.Conn {
			c, feed := net.Pipe()
			t.Cleanup(func() { _ = c.Close() })
			go func() {
				_, _ = feed.Write(payload)
				_ = feed.Close()
			}()
			return c
		}},
	}
	const runs = 50
	for _, tt := range tests {
		srcs := make([]io.Reader, runs+1)
		for i := range srcs {
			srcs[i] = NewPrefixConn(tt.source(), []byte("p"))
		}
		copyFrom := func(src io.Reader) {
			if n, err := copyPlain(tt.dst, src); n != int64(len(payload)+1) || err != nil {
				t.Fatalf("%s: copyPlain() = %d, %v", tt.name, n, err)
			}
		}
		copyFrom(srcs[runs]) // warm up the pool
		// A collection empties the pool, and a busy host collects more often.
		gc := debug.SetGCPercent(-1)
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		for _, src := range srcs[:runs] {
			copyFrom(src)
		}
		runtime.ReadMemStats(&after)
		debug.SetGCPercent(gc)
		// The race detector drops a quarter of the pool's Puts, so allow some.
		if perCopy := (after.TotalAlloc - before.TotalAlloc) / runs; perCopy >= relayBufSize/2 {
			t.Fatalf("%s: copyPlain() allocates %d bytes per copy, want the pooled buffer reused", tt.name, perCopy)
		}
	}
}

// datagramSink records the size of each datagram written to it and blocks
// reads until it is closed.
type datagramSink struct {
	datagramConn
	done chan struct{}
	once sync.Once
}

func (s *datagramSink) Read([]byte) (int, error) {
	<-s.done
	return 0, io.EOF
}

func (s *datagramSink) Close() error {
	s.once.Do(func() { close(s.done) })
	return nil
}

// Sources that return one datagram per Read relay datagrams larger than the
// 32 KiB stream buffer whole.
func TestRelayKeepsLargeDatagrams(t *testing.T) {
	const size = 40000
	relayOne := func(t *testing.T, src io.ReadWriteCloser) {
		t.Helper()
		sink := &datagramSink{done: make(chan struct{})}
		done := make(chan struct{})
		go func() {
			_, _, _ = Relay(context.Background(), src, sink)
			close(done)
		}()
		waitUntil(t, func() bool { return len(sink.sizes()) > 0 })
		_ = src.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("Relay(context.Background()) did not return after its source was closed")
		}
		if got := sink.sizes(); len(got) != 1 || got[0] != size {
			t.Fatalf("datagrams relayed = %v, want [%d]", got, size)
		}
	}
	// macOS refuses to send a datagram larger than the socket's send
	// buffer, 9 KiB by default.
	const sendBuffer = 64 << 10
	t.Run("PacketListener", func(t *testing.T) {
		l := newUDPListener(t)
		client := dialUDP(t, l)
		_ = client.SetWriteBuffer(sendBuffer)
		if _, err := client.Write(make([]byte, size)); err != nil {
			t.Fatal(err)
		}
		relayOne(t, acceptWithin(t, l))
	})
	t.Run("UDPConn", func(t *testing.T) {
		server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Skipf("ListenUDP: %v", err)
		}
		defer func() { _ = server.Close() }()
		_ = server.SetWriteBuffer(sendBuffer)
		client, err := net.DialUDP("udp", nil, server.LocalAddr().(*net.UDPAddr))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := server.WriteTo(make([]byte, size), client.LocalAddr()); err != nil {
			t.Fatal(err)
		}
		relayOne(t, client)
	})
	t.Run("FramedConn", func(t *testing.T) {
		a, b := net.Pipe()
		defer func() { _ = b.Close() }()
		go func() { _ = NewFramedConn(b).WriteFrame(make([]byte, size)) }()
		relayOne(t, NewFramedConn(a, WithFramedDatagrams()))
	})
	// The wrappers of this package are looked through.
	for _, tt := range []struct {
		name string
		wrap func(net.Conn) net.Conn
	}{
		{"TimeoutConn", func(c net.Conn) net.Conn { return NewTimeoutConn(c, time.Minute) }},
		{"ObserveConn", func(c net.Conn) net.Conn {
			return ObserveConn(c, func(int64) error { return nil }, nil)
		}},
		{"RecordingConn", func(c net.Conn) net.Conn { return NewRecordingConn(c, 0) }},
		{"PrefixConn", func(c net.Conn) net.Conn { return NewPrefixConn(c, nil) }},
		{"AddrOverrideConn", func(c net.Conn) net.Conn { return NewAddrOverrideConn(c, nil, nil) }},
	} {
		t.Run("FramedConn beneath "+tt.name, func(t *testing.T) {
			a, b := net.Pipe()
			defer func() { _ = b.Close() }()
			go func() { _ = NewFramedConn(b).WriteFrame(make([]byte, size)) }()
			relayOne(t, tt.wrap(NewFramedConn(a, WithFramedDatagrams())))
		})
	}
}

// Empty datagrams are relayed too.
func TestRelayPassesEmptyDatagrams(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	go func() {
		w := NewFramedConn(b)
		for _, frame := range []string{"", "x", ""} {
			_ = w.WriteFrame([]byte(frame))
		}
	}()
	sink := &datagramSink{done: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		_, _, _ = Relay(context.Background(), NewFramedConn(a, WithFramedDatagrams()), sink)
		close(done)
	}()
	waitUntil(t, func() bool { return len(sink.sizes()) >= 3 })
	_ = a.Close()
	<-done
	if got := sink.sizes(); !slices.Equal(got, []int{0, 1, 0}) {
		t.Fatalf("datagrams relayed = %v, want [0 1 0]", got)
	}
}

// A PrefixConn on the writing side does not keep a direction from splicing.
func TestRelayLooksThroughWritingPrefixConn(t *testing.T) {
	client, server := tcpPair(t)
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()
	dst := sinkWriter(NewPrefixConn(NewPrefixConn(server, []byte("x")), nil))
	if dst != server {
		t.Fatalf("relay sink writer = %T, want the TCP connection", dst)
	}
	if netutil.SpliceOS && !spliceable(dst, client) {
		t.Fatal("spliceable() = false beneath a writing PrefixConn")
	}
}

// readFromSink is a datagramSink with a ReadFrom of its own, which copies
// through a buffer it allocates, as an *os.File does.
type readFromSink struct{ *datagramSink }

func (s readFromSink) ReadFrom(r io.Reader) (int64, error) {
	return io.Copy(writerOnly{s.datagramSink}, r)
}

// A datagram source keeps its datagrams whole, empty ones included, also
// when the writing end has a ReadFrom.
func TestRelayDatagramsIntoReaderFrom(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	go func() {
		w := NewFramedConn(b)
		for _, frame := range [][]byte{make([]byte, 40000), {}, []byte("x")} {
			_ = w.WriteFrame(frame)
		}
	}()
	sink := readFromSink{&datagramSink{done: make(chan struct{})}}
	done := make(chan struct{})
	go func() {
		_, _, _ = Relay(context.Background(), NewFramedConn(a, WithFramedDatagrams()), sink)
		close(done)
	}()
	waitUntil(t, func() bool { return len(sink.sizes()) >= 3 })
	_ = a.Close()
	<-done
	if got := sink.sizes(); !slices.Equal(got, []int{40000, 0, 1}) {
		t.Fatalf("datagrams relayed = %v, want [40000 0 1]", got)
	}
}

// writerOnly hides every method but Write.
type writerOnly struct{ io.Writer }

// udpFlowConn is a connection of another package with one datagram per Read,
// known to Relay only by its UDP address.
type udpFlowConn struct{ *datagramConn }

func (udpFlowConn) LocalAddr() net.Addr { return &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 2} }

// Relay copies such a connection as datagrams, whole above its stream buffer.
func TestRelayDatagramsByNetwork(t *testing.T) {
	src := udpFlowConn{&datagramConn{msgs: [][]byte{make([]byte, 40000), {}, make([]byte, 7)}}}
	if !readsDatagrams(src) {
		t.Fatal("a connection on a UDP address is not read as datagrams")
	}
	if readsDatagrams(plainReader{}) {
		t.Fatal("a reader without an address is read as datagrams")
	}
}

// queueConn stands for a connection of another package of this module whose
// datagrams are in a dgram.Queue, such as a transparent.FlowConn.
type queueConn struct {
	q dgram.Queue
	source
}

type source = dgram.Source

func newQueueConn() *queueConn {
	c := &queueConn{}
	c.q.Init(4)
	c.source = dgram.NewSource(c, &c.q)
	return c
}

func (c *queueConn) Read(b []byte) (int, error) { return c.q.Read(b) }

// Relay takes the queued datagrams of such a connection whole, but not
// through a type of another package that embeds it, which may read
// otherwise.
func TestRelayQueueSource(t *testing.T) {
	c := newQueueConn()
	if s := newRelaySource(c); s.datagrams == nil || !s.readsDatagrams() {
		t.Fatal("the queue of a connection of this module is not handed over")
	}
	embedding := struct{ *queueConn }{c}
	if s := newRelaySource(embedding); s.datagrams != nil {
		t.Fatal("the queue of an embedded connection is handed over")
	}
	var nilConn *queueConn
	if s := newRelaySource(nilConn); s.datagrams != nil {
		t.Fatal("a nil connection's queue is handed over")
	}
	c.q.Enqueue([]byte("one"))
	c.q.Close(io.EOF)
	var buf bytes.Buffer
	if n, err := Copy(context.Background(), &buf, c, nil); n != 0 || err != nil {
		t.Fatalf("Copy() of a closed queue = %d, %v", n, err)
	}
}
