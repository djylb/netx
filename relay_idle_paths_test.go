package netx

import (
	"context"
	"errors"
	"io"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/djylb/timeshim"
)

// blockingEnd is an end whose reads block until it is closed or data is
// fed; data written to it is counted. It has WriteTo, ReadFrom and
// WaitReadable as its fields say.
type blockingEnd struct {
	feed     chan []byte
	closed   chan struct{}
	written  atomic.Int64
	writeTos atomic.Int64
	waits    atomic.Int64
	reads    atomic.Int64
	// readBeforeWait counts reads that no WaitReadable preceded.
	readBeforeWait atomic.Int64
	once           sync.Once
	waited         atomic.Bool
}

func newBlockingEnd() *blockingEnd {
	return &blockingEnd{feed: make(chan []byte, 16), closed: make(chan struct{})}
}

func (e *blockingEnd) Read(p []byte) (int, error) {
	e.reads.Add(1)
	if !e.waited.Swap(false) {
		e.readBeforeWait.Add(1)
	}
	select {
	case b := <-e.feed:
		return copy(p, b), nil
	case <-e.closed:
		return 0, io.EOF
	}
}

func (e *blockingEnd) Write(p []byte) (int, error) {
	e.written.Add(int64(len(p)))
	return len(p), nil
}

func (e *blockingEnd) Close() error {
	e.once.Do(func() { close(e.closed) })
	return nil
}

// writerToEnd adds WriteTo, which copies the fed data to w.
type writerToEnd struct{ *blockingEnd }

func (e writerToEnd) WriteTo(w io.Writer) (int64, error) {
	e.writeTos.Add(1)
	var n int64
	for {
		select {
		case b := <-e.feed:
			m, err := w.Write(b)
			n += int64(m)
			if err != nil {
				return n, err
			}
		case <-e.closed:
			return n, nil
		}
	}
}

// readerFromEnd adds ReadFrom, reading the source through a small buffer.
type readerFromEnd struct {
	*blockingEnd
	readFroms *atomic.Int64
}

func (e readerFromEnd) ReadFrom(r io.Reader) (int64, error) {
	e.readFroms.Add(1)
	var buf [16]byte
	var n int64
	for {
		m, err := r.Read(buf[:])
		if m > 0 {
			k, _ := e.Write(buf[:m])
			n += int64(k)
		}
		if err != nil {
			return n, eofNil(err)
		}
	}
}

// waiterEnd adds WaitReadable, which waits for fed data without taking it.
type waiterEnd struct{ *blockingEnd }

func (e waiterEnd) WaitReadable(ctx context.Context) error {
	e.waits.Add(1)
	for {
		if len(e.feed) > 0 {
			e.waited.Store(true)
			return nil
		}
		select {
		case <-e.closed:
			e.waited.Store(true)
			return nil
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Millisecond):
		}
	}
}

// recordPaths records the paths relayCopy takes until the test ends.
func recordPaths(t *testing.T) func() []string {
	t.Helper()
	var (
		mu    sync.Mutex
		paths []string
	)
	f := func(p string) {
		mu.Lock()
		paths = append(paths, p)
		mu.Unlock()
	}
	relayPath.Store(&f)
	t.Cleanup(func() { relayPath.Store(nil) })
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), paths...)
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !cond(); time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

// With an idle timeout, a source's own WriteTo still copies, and the data
// it writes counts as activity.
func TestRelayIdleKeepsWriteTo(t *testing.T) {
	paths := recordPaths(t)
	clock := timeshim.NewFake(time.Unix(1000, 0))
	a, b := writerToEnd{newBlockingEnd()}, writerToEnd{newBlockingEnd()}
	done := make(chan error, 1)
	go func() {
		_, _, err := Relay(context.Background(), a, b, WithRelayIdleTimeout(time.Minute), WithRelayClock(clock))
		done <- err
	}()
	waitFor(t, "both WriteTo calls", func() bool { return a.writeTos.Load() == 1 && b.writeTos.Load() == 1 })
	clock.Advance(45 * time.Second)
	a.feed <- []byte("ping")
	waitFor(t, "the data", func() bool { return b.written.Load() == 4 })
	clock.Advance(45 * time.Second) // 45s after the data
	select {
	case err := <-done:
		t.Fatalf("Relay ended %v while active", err)
	default:
	}
	clock.Advance(20 * time.Second)
	select {
	case err := <-done:
		if !errors.Is(err, ErrRelayIdle) {
			t.Fatalf("Relay() = %v, want ErrRelayIdle", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("an idle relay did not end")
	}
	for _, p := range paths() {
		if p != "writeto" {
			t.Fatalf("paths = %v, want writeto only", paths())
		}
	}
}

// With an idle timeout, the destination's own ReadFrom still copies.
func TestRelayIdleKeepsReadFrom(t *testing.T) {
	paths := recordPaths(t)
	var readFroms atomic.Int64
	a, b := readerFromEnd{newBlockingEnd(), &readFroms}, readerFromEnd{newBlockingEnd(), &readFroms}
	done := make(chan error, 1)
	go func() {
		_, _, err := Relay(context.Background(), a, b, WithRelayIdleTimeout(time.Hour))
		done <- err
	}()
	waitFor(t, "both ReadFrom calls", func() bool { return readFroms.Load() == 2 })
	a.feed <- []byte("ping")
	waitFor(t, "the data", func() bool { return b.written.Load() == 4 })
	_ = a.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := paths(); len(got) != 2 || got[0] != "readfrom" || got[1] != "readfrom" {
		t.Fatalf("paths = %v, want readfrom twice", got)
	}
}

// A ReadableWaiter source is waited on before each read, with an idle
// timeout too, so that the copy takes its buffer only for data.
func TestRelayWaitsOnReadableWaiter(t *testing.T) {
	paths := recordPaths(t)
	a, b := waiterEnd{newBlockingEnd()}, waiterEnd{newBlockingEnd()}
	done := make(chan error, 1)
	go func() {
		_, _, err := Relay(context.Background(), a, b, WithRelayIdleTimeout(time.Hour))
		done <- err
	}()
	waitFor(t, "a wait", func() bool { return a.waits.Load() > 0 })
	for range 3 {
		a.feed <- []byte("ping")
	}
	waitFor(t, "the data", func() bool { return b.written.Load() == 12 })
	_ = a.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if n := a.readBeforeWait.Load(); n != 0 {
		t.Fatalf("%d of %d reads were not waited for", n, a.reads.Load())
	}
	if got := paths(); len(got) == 0 || got[0] != "stream" {
		t.Fatalf("paths = %v, want stream", got)
	}
}

// Between TCP connections, an idle timeout keeps splice where Relay splices.
func TestRelayIdleKeepsSplice(t *testing.T) {
	paths := recordPaths(t)
	a1, a2 := tcpPair(t)
	b1, b2 := tcpPair(t)
	done := make(chan error, 1)
	go func() {
		_, _, err := Relay(context.Background(), a2, b1, WithRelayIdleTimeout(time.Hour))
		done <- err
	}()
	if _, err := a1.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(b2, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("read %q, %v", buf, err)
	}
	_ = a1.Close()
	<-done
	want := "stream" // a TCP connection's WriteTo would use a buffer of its own
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		want = "splice"
	}
	for _, p := range paths() {
		if p != want {
			t.Fatalf("paths = %v, want %s", paths(), want)
		}
	}
}

// BenchmarkIdleRelayMemory reports the heap that an idle relay with an idle
// timeout holds, between ends with WriteTo.
func BenchmarkIdleRelayMemory(b *testing.B) {
	for _, n := range []int{10, 10000} {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			for b.Loop() {
				var before, after runtime.MemStats
				runtime.GC() // twice, to empty the pools' victim caches
				runtime.GC()
				runtime.ReadMemStats(&before)
				ends := make([]io.Closer, 0, 2*n)
				var wg sync.WaitGroup
				for range n {
					x, y := writerToEnd{newBlockingEnd()}, writerToEnd{newBlockingEnd()}
					ends = append(ends, x, y)
					wg.Go(func() { _, _, _ = Relay(context.Background(), x, y, WithRelayIdleTimeout(time.Hour)) })
				}
				for _, e := range ends {
					for x := e.(writerToEnd); x.writeTos.Load()+x.reads.Load() == 0; {
						runtime.Gosched()
					}
				}
				runtime.GC()
				runtime.ReadMemStats(&after)
				b.ReportMetric(float64(after.HeapInuse+after.StackInuse-before.HeapInuse-before.StackInuse)/float64(n), "B/relay")
				for _, e := range ends {
					_ = e.Close()
				}
				wg.Wait()
			}
		})
	}
}
