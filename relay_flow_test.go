package netx

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// readSizesConn reads from data, recording the size of each Read buffer, and
// collects what is written to it.
type readSizesConn struct {
	mu    sync.Mutex
	data  []byte
	reads []int
	out   bytes.Buffer
}

func (c *readSizesConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reads = append(c.reads, len(b))
	if len(c.data) == 0 {
		return 0, io.EOF
	}
	n := copy(b, c.data)
	c.data = c.data[n:]
	return n, nil
}

func (c *readSizesConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.out.Write(b)
}

func (c *readSizesConn) Close() error { return nil }

// blockingSink collects what is written to it, and its Reads block until it
// is closed.
type blockingSink struct {
	blockingRWC
	mu  sync.Mutex
	out bytes.Buffer
}

func (s *blockingSink) Write(b []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.out.Write(b)
}

// A stream is read for at most what Wait allows, and Done sees every byte
// written, in the order they pass.
func TestRelayFlowPacesStream(t *testing.T) {
	src := &readSizesConn{data: bytes.Repeat([]byte("x"), 1000)}
	dst := &blockingSink{blockingRWC: blockingRWC{closed: make(chan struct{})}}
	var waits, done atomic.Int64
	flow := RelayFlow{
		Wait: func(_ context.Context, limit int64) (int64, error) {
			waits.Add(1)
			if limit < 100 {
				t.Errorf("Wait(max %d), want at least 100", limit)
			}
			return 100, nil
		},
		Done: func(n int64) error {
			done.Add(n)
			return nil
		},
	}
	aToB, _, err := Relay(context.Background(), src, dst, WithRelayFlows(flow, RelayFlow{}))
	if err != nil || aToB != 1000 || done.Load() != 1000 || dst.out.Len() != 1000 {
		t.Fatalf("Relay(context.Background()) = %d, %v; Done saw %d, wrote %d; want 1000 each", aToB, err, done.Load(), dst.out.Len())
	}
	for _, size := range src.reads {
		if size > 100 {
			t.Fatalf("source read with a %d byte buffer, want at most what Wait allowed", size)
		}
	}
	if waits.Load() < 10 {
		t.Fatalf("Wait called %d times, want one per read", waits.Load())
	}
}

// Errors from Wait and Done end the relay and are returned.
func TestRelayFlowErrorsEndRelay(t *testing.T) {
	errQuota := errors.New("quota used up")
	for name, flow := range map[string]RelayFlow{
		"Wait": {Wait: func(context.Context, int64) (int64, error) { return 0, errQuota }},
		"Done": {Done: func(int64) error { return errQuota }},
	} {
		src := &readSizesConn{data: []byte("data")}
		// The other direction blocks until the relay ends.
		_, _, err := Relay(context.Background(), src, &blockingRWC{closed: make(chan struct{})}, WithRelayFlows(flow, RelayFlow{}))
		if !errors.Is(err, errQuota) {
			t.Fatalf("%s: Relay(context.Background()) error = %v, want the flow's error", name, err)
		}
	}
}

// A Wait that blocks until its context ends returns once the other
// direction ends the relay, and its error is not reported.
func TestRelayFlowWaitEndsWithRelay(t *testing.T) {
	a, b := tcpPair(t)
	c, d := tcpPair(t)
	blocking := RelayFlow{Wait: func(ctx context.Context, _ int64) (int64, error) {
		<-ctx.Done()
		return 0, ctx.Err()
	}}
	done := make(chan error, 1)
	go func() {
		_, _, err := Relay(context.Background(), b, c, WithRelayFlows(RelayFlow{}, blocking))
		done <- err
	}()
	_ = a.Close() // b reaches EOF, ending the relay
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Relay(context.Background()) error = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Relay(context.Background()) did not return while a Wait was blocked")
	}
	_ = d.Close()
}

// WithRelayContext ends a relay whose ends are idle and returns the cause.
func TestRelayWithContextEndsIdleRelay(t *testing.T) {
	errDisabled := errors.New("service disabled")
	for _, early := range []bool{false, true} {
		a, b := tcpPair(t)
		c, d := tcpPair(t)
		ctx, cancel := context.WithCancelCause(context.Background())
		t.Cleanup(func() { cancel(nil) })
		if early {
			cancel(errDisabled)
		}
		done := make(chan error, 1)
		go func() {
			_, _, err := Relay(ctx, b, c)
			done <- err
		}()
		if !early {
			time.Sleep(20 * time.Millisecond)
			cancel(errDisabled)
		}
		select {
		case err := <-done:
			if !errors.Is(err, errDisabled) {
				t.Fatalf("early %t: Relay(context.Background()) error = %v, want the context's cause", early, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("early %t: Relay(context.Background()) did not end with its context", early)
		}
		_ = a.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := a.Read(make([]byte, 1)); err == nil {
			t.Fatalf("early %t: the relayed connection stayed open", early)
		}
		_ = d.Close()
	}
}

// Over TCP, also where splice copies, Done sees bytes as they pass, not
// only once a large piece has, and a prefix comes first.
func TestRelayFlowCountsTCPAsItPasses(t *testing.T) {
	for _, withWait := range []bool{false, true} {
		a, b := tcpPair(t)
		c, d := tcpPair(t)
		var counted atomic.Int64
		flow := RelayFlow{Done: func(n int64) error {
			counted.Add(n)
			return nil
		}}
		if withWait {
			flow.Wait = func(_ context.Context, limit int64) (int64, error) { return limit, nil }
		}
		done := make(chan struct{})
		go func() {
			_, _, _ = Relay(context.Background(), NewPrefixConn(b, []byte("pre:")), c, WithRelayFlows(flow, RelayFlow{}))
			close(done)
		}()
		if _, err := a.Write([]byte("abc")); err != nil {
			t.Fatal(err)
		}
		waitUntil(t, func() bool { return counted.Load() == 7 })
		_ = d.SetReadDeadline(time.Now().Add(5 * time.Second))
		got := make([]byte, 7)
		if _, err := io.ReadFull(d, got); err != nil || string(got) != "pre:abc" {
			t.Fatalf("wait %t: relayed %q, %v; want the prefix first", withWait, got, err)
		}
		_ = d.SetReadDeadline(time.Time{})
		copied := make(chan int64, 1)
		go func() {
			n, _ := io.Copy(io.Discard, d)
			copied <- n
		}()
		if _, err := a.Write(bytes.Repeat([]byte("y"), 3<<20)); err != nil {
			t.Fatal(err)
		}
		_ = a.Close()
		if n := <-copied; n != 3<<20 {
			t.Fatalf("wait %t: relayed %d bytes, want %d", withWait, n, 3<<20)
		}
		<-done
		if counted.Load() != 7+3<<20 {
			t.Fatalf("wait %t: Done saw %d bytes, want %d", withWait, counted.Load(), 7+3<<20)
		}
	}
}

// Datagrams are read whole whatever Wait allows.
func TestRelayFlowKeepsDatagramsWhole(t *testing.T) {
	l := newUDPListener(t)
	client := dialUDP(t, l)
	send(t, l, client, string(bytes.Repeat([]byte("d"), 300)))
	src := acceptWithin(t, l)
	sink := &datagramSink{done: make(chan struct{})}
	flow := RelayFlow{Wait: func(context.Context, int64) (int64, error) { return 1, nil }}
	done := make(chan struct{})
	go func() {
		_, _, _ = Relay(context.Background(), src, sink, WithRelayFlows(flow, RelayFlow{}))
		close(done)
	}()
	waitUntil(t, func() bool { return len(sink.sizes()) > 0 })
	_ = src.Close()
	<-done
	if got := sink.sizes(); len(got) != 1 || got[0] != 300 {
		t.Fatalf("datagrams relayed = %v, want one of 300 bytes", got)
	}
}

func TestConnGroup(t *testing.T) {
	var g ConnGroup
	a, b, c := &countedCloseConn{}, &countedCloseConn{}, &countedCloseConn{}
	removeA, _ := g.Add(a)
	_, _ = g.Add(b)
	if g.Len() != 2 {
		t.Fatalf("Len() = %d, want 2", g.Len())
	}
	removeA()
	removeA()
	if err := g.CloseMembers(nil); err != nil {
		t.Fatal(err)
	}
	if a.Calls() != 0 || b.Calls() != 1 || g.Len() != 0 {
		t.Fatalf("after CloseMembers: closes %d, %d, Len %d; want 0, 1, 0", a.Calls(), b.Calls(), g.Len())
	}
	if _, err := g.Add(c); err != nil || g.Len() != 1 {
		t.Fatal("CloseMembers stopped the group taking connections")
	}
	_ = g.Close()
	d := &countedCloseConn{}
	if _, err := g.Add(d); !errors.Is(err, ErrGroupClosed) || d.Calls() != 0 || c.Calls() != 1 {
		t.Fatalf("after Close: Add error %v, closes %d, %d; want ErrGroupClosed, 0, 1", err, d.Calls(), c.Calls())
	}
}

// A group in a group: closing the outer one's members closes the inner
// one's and leaves it open; closing the outer one closes the inner one.
func TestConnGroupNested(t *testing.T) {
	var outer, inner ConnGroup
	_, _ = outer.Add(&inner)
	c := &countedCloseConn{}
	_, _ = inner.Add(c)
	_ = outer.CloseMembers(nil)
	if c.Calls() != 1 {
		t.Fatal("the inner group's member was not closed")
	}
	if _, err := inner.Add(&countedCloseConn{}); err != nil {
		t.Fatalf("CloseMembers of the outer group closed the inner one: %v", err)
	}
	_, _ = outer.Add(&inner)
	_ = outer.Close()
	if _, err := inner.Add(&countedCloseConn{}); !errors.Is(err, ErrGroupClosed) {
		t.Fatalf("Close of the outer group left the inner one open: %v", err)
	}
}

// A relay that a group closes with a cause returns both.
func TestRelayGroupCause(t *testing.T) {
	_, b := tcpPair(t)
	c, _ := tcpPair(t)
	var g ConnGroup
	done := make(chan error, 1)
	go func() {
		_, _, err := Relay(context.Background(), b, c, WithRelayGroup(&g))
		done <- err
	}()
	waitUntil(t, func() bool { return g.Len() == 1 })
	errQuota := errors.New("quota used up")
	_ = g.CloseMembers(errQuota)
	if err := <-done; !errors.Is(err, ErrRelayGroupClosed) || !errors.Is(err, errQuota) {
		t.Fatalf("Relay(context.Background()) error = %v, want ErrRelayGroupClosed and the cause", err)
	}
}

// Adds, removes and closes from many goroutines leave nothing behind.
func TestConnGroupConcurrent(t *testing.T) {
	var g ConnGroup
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 200 {
				remove, _ := g.Add(&countedCloseConn{})
				remove()
			}
		})
	}
	wg.Go(func() {
		for range 50 {
			_ = g.CloseMembers(nil)
		}
	})
	wg.Wait()
	if g.Len() != 0 {
		t.Fatalf("Len() = %d, want 0", g.Len())
	}
}

// A PrefixConn made without NewPrefixConn holds no prefix, and its relay
// ends with its connection.
func TestRelayLiteralPrefixConnEnds(t *testing.T) {
	a, b := tcpPair(t)
	c, d := tcpPair(t)
	done := make(chan struct{})
	go func() {
		_, _, _ = Relay(context.Background(), &PrefixConn{conn: b}, c, WithRelayHalfClose())
		close(done)
	}()
	_, _ = a.Write([]byte("x"))
	_ = a.(interface{ CloseWrite() error }).CloseWrite()
	_ = d.SetReadDeadline(time.Now().Add(5 * time.Second))
	if got, err := io.ReadAll(d); string(got) != "x" || err != nil {
		t.Fatalf("relayed %q, %v; want x and the end", got, err)
	}
	_ = d.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Relay(context.Background()) did not return")
	}
}

// Nothing passes once the context is done.
func TestRelayWithDoneContextPassesNothing(t *testing.T) {
	errDone := errors.New("done before")
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(errDone)
	src := &readSizesConn{data: []byte("data")}
	dst := &blockingSink{blockingRWC: blockingRWC{closed: make(chan struct{})}}
	if _, _, err := Relay(ctx, src, dst); !errors.Is(err, errDone) {
		t.Fatalf("Relay(context.Background()) error = %v, want the cause", err)
	}
	if dst.out.Len() != 0 {
		t.Fatalf("%d bytes passed after the context was done", dst.out.Len())
	}
}

// groupClosingConn closes a group when it is closed, as a connection whose
// end tears down the others of its client does.
type groupClosingConn struct {
	net.Conn
	g *ConnGroup
}

func (c groupClosingConn) Close() error {
	_ = c.g.CloseMembers(nil)
	return c.Conn.Close()
}

// An end whose Close closes the relay's own group does not deadlock the
// relay, and a closed group ends a relay at once.
func TestRelayWithGroup(t *testing.T) {
	a, b := tcpPair(t)
	c, d := tcpPair(t)
	var g ConnGroup
	done := make(chan error, 1)
	go func() {
		_, _, err := Relay(context.Background(), groupClosingConn{b, &g}, c, WithRelayGroup(&g, &g, nil))
		done <- err
	}()
	waitUntil(t, func() bool { return g.Len() == 1 })
	_ = a.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Relay(context.Background()) error = %v, want nil at EOF", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Relay(context.Background()) deadlocked when an end closed its group")
	}
	_ = d.Close()
	if g.Len() != 0 {
		t.Fatalf("Len() = %d after the relay ended, want 0", g.Len())
	}

	var closed ConnGroup
	_ = closed.Close()
	src := &readSizesConn{data: []byte("data")}
	dst := &blockingSink{blockingRWC: blockingRWC{closed: make(chan struct{})}}
	if _, _, err := Relay(context.Background(), src, dst, WithRelayGroup(&g, &closed)); !errors.Is(err, ErrRelayGroupClosed) || dst.out.Len() != 0 {
		t.Fatalf("on a closed group: Relay(context.Background()) error = %v, passed %d bytes", err, dst.out.Len())
	}
	if g.Len() != 0 {
		t.Fatalf("a relay ended by a closed group stayed in another group")
	}
}

// A relay that a closed group ends while another of its groups closes it
// too reports one of their errors, without a race.
func TestRelayWithGroupsClosingTogether(t *testing.T) {
	var closed ConnGroup
	_ = closed.Close()
	for range 200 {
		var open ConnGroup
		go func() { _ = open.CloseMembers(nil) }()
		src := &readSizesConn{data: []byte("data")}
		dst := &blockingSink{blockingRWC: blockingRWC{closed: make(chan struct{})}}
		if _, _, err := Relay(context.Background(), src, dst, WithRelayGroup(&open, &closed)); !errors.Is(err, ErrRelayGroupClosed) {
			t.Fatalf("Relay(context.Background()) error = %v, want ErrRelayGroupClosed", err)
		}
	}
}

// Copies from PacketListener connections and datagram FramedConns hold no
// buffer while idle: the datagrams come in buffers of their own.
func TestRelayIdleDatagramSourcesHoldNoBuffer(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector adds to every allocation")
	}
	const n = 100
	for _, kind := range []string{"PacketListener", "FramedConn"} {
		var srcs []io.ReadWriteCloser
		var peers []io.Closer
		for range n {
			switch kind {
			case "PacketListener":
				l := newUDPListener(t)
				c := dialUDP(t, l)
				send(t, l, c, "hello")
				srcs = append(srcs, acceptWithin(t, l))
				peers = append(peers, c)
			default:
				a, b := tcpPair(t)
				_ = NewFramedConn(a).WriteFrame([]byte("hello"))
				srcs = append(srcs, NewFramedConn(b, WithFramedDatagrams()))
				peers = append(peers, a)
			}
		}
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		var wg sync.WaitGroup
		var got atomic.Int64
		for _, src := range srcs {
			wg.Go(func() {
				_, _ = copyDatagrams(context.Background(), writerFunc(func(b []byte) (int, error) {
					got.Add(1)
					return len(b), nil
				}), src, nil)
			})
		}
		waitUntil(t, func() bool { return got.Load() == n })
		time.Sleep(50 * time.Millisecond)
		runtime.ReadMemStats(&after)
		for i, src := range srcs {
			_ = src.Close()
			_ = peers[i].Close()
		}
		wg.Wait()
		if per := int64(after.HeapAlloc-before.HeapAlloc) / n; per >= relayDatagramBufSize/4 {
			t.Fatalf("%s: an idle relay holds %d bytes, want no %d byte buffer", kind, per, relayDatagramBufSize)
		}
	}
}

// A datagram FramedConn that loses its frame boundaries reports it through
// a relay too.
func TestRelayFramedDatagramDesync(t *testing.T) {
	sink := &datagramSink{done: make(chan struct{})}
	_, _, err := Relay(context.Background(), NewFramedConn(&unexpectedEOFConn{}, WithFramedDatagrams()), sink)
	if !errors.Is(err, ErrFrameDesync) {
		t.Fatalf("Relay(context.Background()) error = %v, want ErrFrameDesync", err)
	}
}

// writerFunc is a Writer made of a function.
type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(b []byte) (int, error) { return f(b) }

// First sees each direction's first bytes once, before they pass, over TCP
// where splice copies the rest too, after a prefix, from other streams and
// for datagrams; a direction that ends without data never calls it.
func TestRelayFlowFirst(t *testing.T) {
	record := func() (*RelayFlow, func() []string) {
		var mu sync.Mutex
		var seen []string
		return &RelayFlow{First: func(b []byte) {
			mu.Lock()
			seen = append(seen, string(b))
			mu.Unlock()
		}}, func() []string {
			mu.Lock()
			defer mu.Unlock()
			return append([]string(nil), seen...)
		}
	}
	t.Run("TCP", func(t *testing.T) {
		for _, prefix := range []string{"", "pre:"} {
			a, b := tcpPair(t)
			c, d := tcpPair(t)
			f, seen := record()
			var src io.ReadWriteCloser = b
			if prefix != "" {
				src = NewPrefixConn(b, []byte(prefix))
			}
			go func() { _, _, _ = Relay(context.Background(), src, c, WithRelayFlows(*f, RelayFlow{})) }()
			_, _ = a.Write([]byte("GET / HTTP/1.1\r\n"))
			_ = d.SetReadDeadline(time.Now().Add(5 * time.Second))
			want := prefix + "GET / HTTP/1.1\r\n"
			got := make([]byte, len(want))
			if _, err := io.ReadFull(d, got); err != nil || string(got) != want {
				t.Fatalf("relayed %q, %v", got, err)
			}
			_ = d.SetReadDeadline(time.Time{})
			copied := make(chan int64, 1)
			go func() {
				n, _ := io.Copy(io.Discard, d)
				copied <- n
			}()
			_, _ = a.Write(bytes.Repeat([]byte("x"), 1<<20))
			_ = a.Close()
			if n := <-copied; n != 1<<20 {
				t.Fatalf("relayed %d more bytes, want %d", n, 1<<20)
			}
			first := prefix
			if first == "" {
				first = "GET / HTTP/1.1\r\n"
			}
			if s := seen(); len(s) != 1 || s[0] != first {
				t.Fatalf("prefix %q: First saw %q, want once %q", prefix, s, first)
			}
		}
	})
	t.Run("other streams", func(t *testing.T) {
		f, seen := record()
		src := &readSizesConn{data: []byte("hello")}
		dst := &blockingSink{blockingRWC: blockingRWC{closed: make(chan struct{})}}
		if n, _, err := Relay(context.Background(), src, dst, WithRelayFlows(*f, RelayFlow{})); err != nil || n != 5 {
			t.Fatalf("Relay(context.Background()) = %d, %v; want 5 bytes", n, err)
		}
		if s := seen(); len(s) != 1 || s[0] != "hello" || dst.out.String() != "hello" {
			t.Fatalf("First saw %q, relayed %q", s, dst.out.String())
		}
	})
	t.Run("datagrams", func(t *testing.T) {
		l := newUDPListener(t)
		client := dialUDP(t, l)
		send(t, l, client, "one")
		send(t, l, client, "two")
		src := acceptWithin(t, l)
		sink := &datagramSink{done: make(chan struct{})}
		f, seen := record()
		done := make(chan struct{})
		go func() {
			_, _, _ = Relay(context.Background(), src, sink, WithRelayFlows(*f, RelayFlow{}))
			close(done)
		}()
		waitUntil(t, func() bool { return len(sink.sizes()) == 2 })
		_ = src.Close()
		<-done
		if s := seen(); len(s) != 1 || s[0] != "one" {
			t.Fatalf("First saw %q, want the first datagram once", s)
		}
	})
	t.Run("no data", func(t *testing.T) {
		a, b := tcpPair(t)
		c, d := tcpPair(t)
		f, seen := record()
		done := make(chan struct{})
		go func() {
			_, _, _ = Relay(context.Background(), b, c, WithRelayFlows(*f, RelayFlow{}))
			close(done)
		}()
		_ = a.Close()
		<-done
		_ = d.Close()
		if s := seen(); len(s) != 0 {
			t.Fatalf("First saw %q for a direction without data", s)
		}
	})
}

// Track removes a connection from its group when it is closed, and Relay
// looks through it.
func TestConnGroupTrack(t *testing.T) {
	var g ConnGroup
	a, b := tcpPair(t)
	tc, err := g.Track(a)
	if err != nil || g.Len() != 1 {
		t.Fatalf("Track() = %v, Len() = %d", err, g.Len())
	}
	if InnermostConn(tc) != a || (spliceOS && !canSplice(tc, b)) {
		t.Fatal("the tracked connection hides the one beneath")
	}
	if err := tc.Close(); err != nil || g.Len() != 0 {
		t.Fatalf("Close() = %v, Len() = %d; want it removed", err, g.Len())
	}
	_ = g.Close()
	if _, err := g.Track(b); !errors.Is(err, ErrGroupClosed) {
		t.Fatalf("Track() on a closed group = %v", err)
	}
}
