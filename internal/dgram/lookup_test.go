package dgram

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var errTestBusy = errors.New("busy")

// testLookups resolves "fail*" names to an error and others to their
// length, after release is closed when it is not nil, and records what it
// sends.
type testLookups struct {
	release chan struct{}
	sent    chan string
	calls   atomic.Int32
}

func newTestLookups(t *testing.T, block bool) (*Lookups[int], *testLookups) {
	t.Helper()
	tl := &testLookups{sent: make(chan string, 1024)}
	if block {
		tl.release = make(chan struct{})
	}
	l := NewLookups(time.Minute, errTestBusy, tl.resolve, func(p []byte, _ string, v int, port uint16) {
		tl.sent <- string(p) + "@" + strconv.Itoa(v) + ":" + strconv.Itoa(int(port))
	})
	t.Cleanup(l.Close)
	return l, tl
}

func (tl *testLookups) resolve(ctx context.Context, name string) (int, error) {
	tl.calls.Add(1)
	if tl.release != nil {
		select {
		case <-tl.release:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	if len(name) >= 4 && name[:4] == "fail" {
		return 0, errors.New("no such host")
	}
	return len(name), nil
}

func (tl *testLookups) next(t *testing.T) string {
	t.Helper()
	select {
	case s := <-tl.sent:
		return s
	case <-time.After(5 * time.Second):
		t.Fatal("nothing sent")
	}
	return ""
}

func (tl *testLookups) none(t *testing.T) {
	t.Helper()
	select {
	case s := <-tl.sent:
		t.Fatalf("sent %q", s)
	default:
	}
}

func waitRunning[V any](t *testing.T, l *Lookups[V]) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for l.Running() > 0 {
		if time.Now().After(deadline) {
			t.Fatalf("%d lookups still run", l.Running())
		}
		time.Sleep(time.Millisecond)
	}
}

// Datagrams to a name are held while it is looked up, then sent in order,
// also those that come while they are sent; the result is cached.
func TestLookupsHoldAndSend(t *testing.T) {
	l, tl := newTestLookups(t, true)
	for _, p := range []string{"a", "b", "c"} {
		if _, held, err := l.Route([]byte(p), "name.test", 53); !held || err != nil {
			t.Fatalf("Route = %v, %v; want held", held, err)
		}
	}
	tl.none(t)
	close(tl.release)
	for _, p := range []string{"a", "b", "c"} {
		if got := tl.next(t); got != p+"@9:53" {
			t.Fatalf("sent %q; want %q", got, p+"@9:53")
		}
	}
	waitRunning(t, l)
	if v, held, err := l.Route([]byte("d"), "name.test", 53); v != 9 || held || err != nil {
		t.Fatalf("cached Route = %d, %v, %v", v, held, err)
	}
	if n := tl.calls.Load(); n != 1 {
		t.Fatalf("%d lookups", n)
	}
	if l.Held() != 0 {
		t.Fatalf("%d bytes held", l.Held())
	}
}

// A failed lookup drops its datagrams and is cached.
func TestLookupsFailureCached(t *testing.T) {
	l, tl := newTestLookups(t, false)
	if _, held, err := l.Route([]byte("x"), "fail.test", 1); !held || err != nil {
		t.Fatalf("Route = %v, %v; want held", held, err)
	}
	waitRunning(t, l)
	if _, held, err := l.Route([]byte("x"), "fail.test", 1); held || err == nil {
		t.Fatalf("Route = %v, %v; want the cached failure", held, err)
	}
	if _, err := l.Resolve("fail.test"); err == nil {
		t.Fatal("Resolve: no cached failure")
	}
	if n := tl.calls.Load(); n != 1 {
		t.Fatalf("%d lookups", n)
	}
	tl.none(t)
}

// The datagrams held and the lookups run are bounded, and Close ends the
// lookups, dropping their datagrams.
func TestLookupsBounds(t *testing.T) {
	l, tl := newTestLookups(t, true)
	for i := range MaxLookupQueue {
		if _, held, err := l.Route([]byte("x"), "slow.test", 9); !held || err != nil {
			t.Fatalf("Route %d = %v, %v; want held", i, held, err)
		}
	}
	if _, _, err := l.Route([]byte("x"), "slow.test", 9); !errors.Is(err, errTestBusy) {
		t.Fatalf("Route beyond the queue = %v; want busy", err)
	}
	// Other names, each with its own lookup, until the bytes run out.
	big := make([]byte, 60000)
	held := 0
	for i := 0; ; i++ {
		_, _, err := l.Route(big, "big"+strconv.Itoa(i), 9)
		if err != nil {
			if !errors.Is(err, errTestBusy) {
				t.Fatal(err)
			}
			break
		}
		held++
	}
	if want := (MaxLookupHeld - MaxLookupQueue) / len(big); held != want {
		t.Fatalf("%d large datagrams held, want %d", held, want)
	}
	// Then names until the lookups run out.
	for i := 0; ; i++ {
		_, _, err := l.Route([]byte("x"), "n"+strconv.Itoa(i), 9)
		if err != nil {
			if !errors.Is(err, errTestBusy) {
				t.Fatal(err)
			}
			break
		}
	}
	if n := l.Running(); n != MaxLookups {
		t.Fatalf("%d lookups run, want %d", n, MaxLookups)
	}
	l.Close()
	if _, _, err := l.Route([]byte("x"), "after.test", 9); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Route after Close = %v; want net.ErrClosed", err)
	}
	waitRunning(t, l)
	if l.Held() != 0 {
		t.Fatalf("%d bytes held after Close", l.Held())
	}
	tl.none(t)
}

// Close ends a lookup in progress, which is not cached; the cache is
// bounded.
func TestLookupsResolve(t *testing.T) {
	l, _ := newTestLookups(t, true)
	var wg sync.WaitGroup
	var err error
	wg.Go(func() { _, err = l.Resolve("slow.test") })
	time.Sleep(20 * time.Millisecond)
	l.Close()
	wg.Wait()
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Resolve after Close = %v; want net.ErrClosed", err)
	}
	if len(l.names) != 0 {
		t.Fatal("a lookup that Close ended was cached")
	}

	l, tl := newTestLookups(t, false)
	for i := range MaxCachedNames + 10 {
		if _, err := l.Resolve("n" + strconv.Itoa(i)); err != nil {
			t.Fatal(err)
		}
	}
	if len(l.names) > MaxCachedNames {
		t.Fatalf("%d names cached", len(l.names))
	}
	if n := tl.calls.Load(); n != MaxCachedNames+10 {
		t.Fatalf("%d lookups", n)
	}
}

// A datagram to a cached name is routed without allocating.
func TestLookupsRouteAllocs(t *testing.T) {
	l, _ := newTestLookups(t, false)
	if _, err := l.Resolve("name.test"); err != nil {
		t.Fatal(err)
	}
	p := []byte("x")
	if n := testing.AllocsPerRun(100, func() {
		if _, held, err := l.Route(p, "name.test", 1); held || err != nil {
			t.Fatal(held, err)
		}
	}); n != 0 {
		t.Fatalf("%v allocations", n)
	}
}
