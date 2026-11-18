package netx

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"
)

// fakeStream is an in-memory ReadNotifier, as a stream of a multiplexed
// connection would be. Data and its end are fed by the test; what Relay
// writes to it is kept. Notifications are delivered on the feeding
// goroutine, as a connection's read loop would, or on a goroutine of their
// own with async.
type fakeStream struct {
	end      error // io.EOF, a reset or net.ErrClosed once the stream ended
	reg      *fakeReg
	gate     chan struct{} // if not nil, each Write waits for a token
	closed   chan struct{}
	cond     *sync.Cond
	buf      []byte
	written  bytes.Buffer
	mu       sync.Mutex
	tryReads int // under mu
	reads    int // under mu
	regs     int // under mu
	async    bool
	wrClosed bool // under mu
}

type fakeReg struct{ f func() }

func newFakeStream(async bool) *fakeStream {
	s := &fakeStream{async: async, closed: make(chan struct{})}
	s.cond = sync.NewCond(&s.mu)
	return s
}

func (s *fakeStream) readableLocked() bool { return len(s.buf) > 0 || s.end != nil }

func (s *fakeStream) TryRead(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tryReads++
	return s.readLocked(p)
}

func (s *fakeStream) readLocked(p []byte) (int, error) {
	if len(s.buf) > 0 {
		n := copy(p, s.buf)
		s.buf = s.buf[n:]
		return n, nil
	}
	if s.end != nil {
		return 0, s.end
	}
	return 0, ErrWouldBlock
}

func (s *fakeStream) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads++
	for !s.readableLocked() {
		s.cond.Wait()
	}
	return s.readLocked(p)
}

func (s *fakeStream) NotifyReadable(f func()) func() bool {
	s.mu.Lock()
	if s.reg != nil {
		s.mu.Unlock()
		panic("fakeStream: two pending notifications")
	}
	s.regs++
	r := &fakeReg{f: f}
	s.reg = r
	ready := s.readableLocked()
	s.mu.Unlock()
	if ready {
		s.fire()
	}
	return func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.reg == r {
			s.reg = nil
			return true
		}
		return false
	}
}

// fire calls the pending notification, if any.
func (s *fakeStream) fire() {
	s.mu.Lock()
	r := s.reg
	s.reg = nil
	s.cond.Broadcast()
	s.mu.Unlock()
	switch {
	case r == nil:
	case s.async:
		go r.f()
	default:
		r.f()
	}
}

func (s *fakeStream) pending() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reg != nil
}

func (s *fakeStream) counts() (tryReads, reads, regs int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tryReads, s.reads, s.regs
}

func (s *fakeStream) feed(b []byte) {
	s.mu.Lock()
	s.buf = append(s.buf, b...)
	s.mu.Unlock()
	s.fire()
}

// finish ends the stream with err: io.EOF for the peer's end, or a reset.
func (s *fakeStream) finish(err error) {
	s.mu.Lock()
	if s.end == nil {
		s.end = err
	}
	s.mu.Unlock()
	s.fire()
}

func (s *fakeStream) Write(p []byte) (int, error) {
	if s.gate != nil {
		select {
		case <-s.gate:
		case <-s.closed:
			return 0, net.ErrClosed
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.written.Write(p)
}

func (s *fakeStream) CloseWrite() error {
	s.mu.Lock()
	s.wrClosed = true
	s.mu.Unlock()
	return nil
}

func (s *fakeStream) Close() error {
	s.mu.Lock()
	if s.end == nil || s.end == io.EOF {
		s.end = net.ErrClosed
	}
	select {
	case <-s.closed:
	default:
		close(s.closed)
	}
	s.mu.Unlock()
	s.fire()
	return nil
}

func (s *fakeStream) writtenString() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.written.String()
}

func readN(t *testing.T, r io.Reader, n int) string {
	t.Helper()
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(buf)
}

// fireModes name the ways notifications are delivered: on the feeding
// goroutine, as a connection's read loop would, and on goroutines of their own.
var fireModes = []struct {
	name  string
	async bool
}{{name: "inline", async: false}, {name: "async", async: true}}

func startRelay(a, b io.ReadWriteCloser, opts ...RelayOption) <-chan error {
	done := make(chan error, 1)
	go func() {
		_, _, err := Relay(context.Background(), a, b, opts...)
		done <- err
	}()
	return done
}

func waitRelay(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("Relay did not return")
		return nil
	}
}

// A ReadNotifier is copied through TryRead alone, in both directions'
// orders of ends, and is left registered while idle.
func TestRelayNotifierCopies(t *testing.T) {
	for _, mode := range fireModes {
		async := mode.async
		t.Run(mode.name, func(t *testing.T) {
			for _, first := range []bool{true, false} {
				s := newFakeStream(async)
				c1, c2 := tcpPair(t)
				var done <-chan error
				if first {
					done = startRelay(s, c1)
				} else {
					done = startRelay(c1, s)
				}
				waitFor(t, "registration", s.pending)
				for i := range 3 {
					msg := "ping" + strconv.Itoa(i)
					s.feed([]byte(msg))
					if got := readN(t, c2, len(msg)); got != msg {
						t.Fatalf("got %q, want %q", got, msg)
					}
					waitFor(t, "registration", s.pending)
				}
				if _, err := c2.Write([]byte("pong")); err != nil {
					t.Fatal(err)
				}
				waitFor(t, "the reply", func() bool { return s.writtenString() == "pong" })
				_ = c2.Close()
				if err := waitRelay(t, done); err != nil {
					t.Fatal(err)
				}
				if _, reads, _ := s.counts(); reads != 0 {
					t.Fatalf("%d blocking Reads, want none", reads)
				}
			}
		})
	}
}

// Data that is there before Relay starts is copied at once.
func TestRelayNotifierReadableAtStart(t *testing.T) {
	for _, mode := range fireModes {
		async := mode.async
		t.Run(mode.name, func(t *testing.T) {
			s := newFakeStream(async)
			s.feed([]byte("early"))
			c1, c2 := tcpPair(t)
			done := startRelay(s, c1)
			if got := readN(t, c2, 5); got != "early" {
				t.Fatalf("got %q", got)
			}
			_ = c2.Close()
			if err := waitRelay(t, done); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// With half-close, the stream's end is passed on with CloseWrite and the
// other direction goes on.
func TestRelayNotifierHalfClose(t *testing.T) {
	for _, mode := range fireModes {
		async := mode.async
		t.Run(mode.name, func(t *testing.T) {
			s := newFakeStream(async)
			c1, c2 := tcpPair(t)
			done := startRelay(s, c1, WithRelayHalfClose())
			s.feed([]byte("last"))
			s.finish(io.EOF)
			if got := readN(t, c2, 4); got != "last" {
				t.Fatalf("got %q", got)
			}
			if n, err := c2.Read(make([]byte, 1)); n != 0 || err != io.EOF {
				t.Fatalf("after the end: %d, %v, want EOF", n, err)
			}
			if _, err := c2.Write([]byte("more")); err != nil {
				t.Fatal(err)
			}
			waitFor(t, "the reply", func() bool { return s.writtenString() == "more" })
			_ = c2.(*net.TCPConn).CloseWrite()
			if err := waitRelay(t, done); err != nil {
				t.Fatal(err)
			}
			s.mu.Lock()
			wr := s.wrClosed
			s.mu.Unlock()
			if !wr {
				t.Fatal("the TCP end was not passed on to the stream")
			}
		})
	}
}

// A reset of the stream ends the relay with its error, also while the
// TCP side is idle.
func TestRelayNotifierReset(t *testing.T) {
	errReset := errors.New("stream reset")
	for _, mode := range fireModes {
		async := mode.async
		t.Run(mode.name, func(t *testing.T) {
			s := newFakeStream(async)
			c1, _ := tcpPair(t)
			done := startRelay(c1, s, WithRelayHalfClose())
			waitFor(t, "registration", s.pending)
			s.finish(errReset)
			if err := waitRelay(t, done); !errors.Is(err, errReset) {
				t.Fatalf("Relay() = %v, want the reset", err)
			}
		})
	}
}

// The end of the context closes the stream, whose notification ends its
// direction.
func TestRelayNotifierContext(t *testing.T) {
	for _, mode := range fireModes {
		async := mode.async
		t.Run(mode.name, func(t *testing.T) {
			s := newFakeStream(async)
			c1, _ := tcpPair(t)
			ctx, cancel := context.WithCancelCause(context.Background())
			errStop := errors.New("stop")
			done := make(chan error, 1)
			go func() {
				_, _, err := Relay(ctx, s, c1)
				done <- err
			}()
			waitFor(t, "registration", s.pending)
			cancel(errStop)
			if err := waitRelay(t, done); !errors.Is(err, errStop) {
				t.Fatalf("Relay() = %v, want the cause", err)
			}
			if s.pending() {
				t.Fatal("a notification is still pending")
			}
		})
	}
}

// With both ends ReadNotifiers, Relay copies both ways without a goroutine
// of its own.
func TestRelayNotifierBothEnds(t *testing.T) {
	for _, mode := range fireModes {
		async := mode.async
		t.Run(mode.name, func(t *testing.T) {
			a, b := newFakeStream(async), newFakeStream(async)
			done := startRelay(a, b)
			a.feed([]byte("ab"))
			b.feed([]byte("ba"))
			waitFor(t, "the data", func() bool { return a.writtenString() == "ba" && b.writtenString() == "ab" })
			a.finish(io.EOF)
			if err := waitRelay(t, done); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// A blocked write holds the stream back: the task does not read on, and
// all of the data arrives in order once the writer drains.
func TestRelayNotifierBackPressure(t *testing.T) {
	for _, mode := range fireModes {
		async := mode.async
		t.Run(mode.name, func(t *testing.T) {
			src := newFakeStream(async)
			dst := newFakeStream(async)
			dst.gate = make(chan struct{})
			done := startRelay(src, dst)
			data := bytes.Repeat([]byte("0123456789abcdef"), 3*relayBufSize/16)
			src.feed(data)
			waitFor(t, "a blocked write", func() bool { tr, _, _ := src.counts(); return tr > 0 })
			time.Sleep(10 * time.Millisecond)
			if tr, _, _ := src.counts(); tr != 1 {
				t.Fatalf("%d TryReads behind a blocked write, want 1", tr)
			}
			// Hand out write tokens until all of the data has arrived.
			deadline := time.Now().Add(5 * time.Second)
			for dst.writtenString() != string(data) {
				if time.Now().After(deadline) {
					t.Fatal("the copy stalled")
				}
				select {
				case dst.gate <- struct{}{}:
				case <-time.After(time.Millisecond):
				}
			}
			src.finish(io.EOF)
			if err := waitRelay(t, done); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Feeds, ends, resets and closes race the notifications; Relay always
// returns, and each stream ends with no notification pending.
func TestRelayNotifierRaces(t *testing.T) {
	errReset := errors.New("stream reset")
	for _, mode := range fireModes {
		async := mode.async
		t.Run(mode.name, func(t *testing.T) {
			for i := range 200 {
				a, b := newFakeStream(async), newFakeStream(async)
				done := startRelay(a, b, WithRelayHalfClose())
				var wg sync.WaitGroup
				wg.Go(func() {
					for range 5 {
						a.feed([]byte("x"))
					}
				})
				wg.Go(func() { b.feed([]byte("y")) })
				wg.Go(func() {
					switch i % 3 {
					case 0:
						a.finish(io.EOF)
						b.finish(io.EOF)
					case 1:
						a.finish(errReset)
					default:
						_ = b.Close()
					}
				})
				wg.Wait()
				_ = waitRelay(t, done)
				if a.pending() || b.pending() {
					t.Fatal("a notification is still pending")
				}
			}
		})
	}
}

// Copy waits on a ReadNotifier without a buffer, and its context cancels
// the pending notification.
func TestCopyNotifierContext(t *testing.T) {
	for _, mode := range fireModes {
		async := mode.async
		t.Run(mode.name, func(t *testing.T) {
			s := newFakeStream(async)
			var dst bytes.Buffer
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() {
				_, err := Copy(ctx, &dst, s, nil)
				done <- err
			}()
			waitFor(t, "registration", s.pending)
			cancel()
			if err := waitRelay(t, done); !errors.Is(err, context.Canceled) {
				t.Fatalf("Copy() = %v, want context.Canceled", err)
			}
			if s.pending() {
				t.Fatal("the notification was not stopped")
			}
			if _, reads, _ := s.counts(); reads != 0 {
				t.Fatalf("%d blocking Reads, want none", reads)
			}
		})
	}
}

// The notification that arrives during arm is taken by arm's caller, and one
// that arrives later starts a task; neither is lost or doubled.
func TestNotifyCopyInterleavings(t *testing.T) {
	for _, mode := range fireModes {
		async := mode.async
		t.Run(mode.name, func(t *testing.T) {
			s := newFakeStream(async)
			var (
				mu    sync.Mutex
				dst   bytes.Buffer
				ended = make(chan error, 1)
			)
			w := writerFunc(func(p []byte) (int, error) {
				mu.Lock()
				defer mu.Unlock()
				return dst.Write(p)
			})
			c := newNotifyCopy(context.Background(), w, s, nil, nil, func(_ int64, err error) { ended <- err })
			if c == nil {
				t.Fatal("no notifyCopy for a ReadNotifier")
			}
			s.feed([]byte("a")) // readable before the first registration
			c.start()
			for _, m := range []string{"b", "c", "d"} {
				waitFor(t, "registration", s.pending)
				s.feed([]byte(m))
			}
			waitFor(t, "the data", func() bool { mu.Lock(); defer mu.Unlock(); return dst.String() == "abcd" })
			s.finish(io.EOF)
			select {
			case err := <-ended:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the copy did not end")
			}
			select {
			case err := <-ended:
				t.Fatalf("end called twice, again with %v", err)
			default:
			}
		})
	}
}

// blockingStream is a fakeStream without TryRead and NotifyReadable, read
// with a blocking Read.
type blockingStream struct{ s *fakeStream }

func (b blockingStream) Read(p []byte) (int, error)  { return b.s.Read(p) }
func (b blockingStream) Write(p []byte) (int, error) { return b.s.Write(p) }
func (b blockingStream) Close() error                { return b.s.Close() }

// An idle relay between a ReadNotifier and a TCP connection keeps only the
// goroutine that called Relay.
func TestRelayNotifierIdleGoroutines(t *testing.T) {
	s := newFakeStream(false)
	c1, c2 := tcpPair(t)
	before := runtime.NumGoroutine()
	done := startRelay(s, c1)
	waitFor(t, "registration", s.pending)
	waitFor(t, "one goroutine", func() bool { return runtime.NumGoroutine()-before == 1 })
	_ = c2.Close()
	if err := waitRelay(t, done); err != nil {
		t.Fatal(err)
	}
}

// BenchmarkIdleRelayStreamTCP reports the goroutines and memory that an idle
// relay between a stream and a TCP connection holds, with a stream that is
// a ReadNotifier and with one read by a blocking Read.
func BenchmarkIdleRelayStreamTCP(b *testing.B) {
	const n = 200
	for _, notify := range []bool{true, false} {
		b.Run("notifier="+strconv.FormatBool(notify), func(b *testing.B) {
			for b.Loop() {
				var ln net.ListenConfig
				l, err := ln.Listen(context.Background(), "tcp", "127.0.0.1:0")
				if err != nil {
					b.Fatal(err)
				}
				peers := make([]net.Conn, 0, n)
				conns := make([]net.Conn, 0, n)
				for range n {
					var d net.Dialer
					c, err := d.DialContext(context.Background(), "tcp", l.Addr().String())
					if err != nil {
						b.Fatal(err)
					}
					sc, err := l.Accept()
					if err != nil {
						b.Fatal(err)
					}
					peers, conns = append(peers, c), append(conns, sc)
				}
				_ = l.Close()
				streams := make([]*fakeStream, n)
				for i := range streams {
					streams[i] = newFakeStream(false)
				}
				var before, after runtime.MemStats
				runtime.GC()
				runtime.GC()
				runtime.ReadMemStats(&before)
				g0 := runtime.NumGoroutine()
				var wg sync.WaitGroup
				for i := range n {
					var end io.ReadWriteCloser = streams[i]
					if !notify {
						end = blockingStream{streams[i]}
					}
					wg.Go(func() { _, _, _ = Relay(context.Background(), end, conns[i]) })
				}
				for _, s := range streams {
					for {
						_, reads, regs := s.counts()
						if (notify && regs > 0) || (!notify && reads > 0) {
							break
						}
						runtime.Gosched()
					}
				}
				time.Sleep(10 * time.Millisecond)
				g1 := runtime.NumGoroutine()
				runtime.GC()
				runtime.ReadMemStats(&after)
				b.ReportMetric(float64(g1-g0)/n, "goroutines/relay")
				b.ReportMetric(float64(int64(after.HeapInuse+after.StackInuse)-int64(before.HeapInuse+before.StackInuse))/n, "B/relay")
				for _, c := range peers {
					_ = c.Close()
				}
				wg.Wait()
			}
		})
	}
}
