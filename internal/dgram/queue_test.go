package dgram

import (
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/djylb/netx/internal/bufpool"
	"github.com/djylb/netx/internal/clock"
)

func newQueue(n int) *Queue {
	q := new(Queue)
	q.Init(n, nil)
	return q
}

// The queue is bounded in bytes too, so large datagrams cannot hold 64 KiB
// per slot.
func TestQueueBoundsBytes(t *testing.T) {
	q := newQueue(4) // 4 datagrams, 8 KiB
	buf := make([]byte, bufpool.MaxDatagram)
	readAll := func() []int {
		var sizes []int
		for q.Len() > 0 {
			n, err := q.Read(buf)
			if err != nil {
				t.Fatal(err)
			}
			sizes = append(sizes, n)
		}
		return sizes
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
			q.Enqueue(make([]byte, n))
		}
		if got := readAll(); !slices.Equal(got, tt.want) {
			t.Fatalf("%s: read %v, want %v", tt.name, got, tt.want)
		}
		if n := q.queued; n != 0 {
			t.Fatalf("%s: %d bytes still counted as queued", tt.name, n)
		}
	}
}

// As on a socket, an expired deadline fails reads even while datagrams are
// queued, and a closed queue fails them with its error, holding nothing.
func TestQueueDeadlineAndClose(t *testing.T) {
	q := newQueue(4)
	q.Enqueue([]byte("x"))
	q.SetReadDeadline(time.Now().Add(-time.Second))
	if _, err := q.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read() past the deadline = %v, want ErrDeadlineExceeded", err)
	}
	q.SetReadDeadline(time.Time{})
	if n, err := q.Read(make([]byte, 1)); n != 1 || err != nil {
		t.Fatalf("Read() = %d, %v, want the queued datagram", n, err)
	}
	q.SetReadDeadline(time.Now().Add(time.Hour))
	q.Enqueue([]byte("y"))
	q.Close(io.EOF)
	q.SetReadDeadline(clock.Past) // as by a setter racing with Close
	if clock.IsClosed(q.readDeadline.Wait()) {
		t.Fatal("a stopped deadline was reset after Close")
	}
	if q.Len() != 0 {
		t.Fatal("datagrams kept by a closed queue")
	}
	// A datagram racing with Close does not stay queued, holding its buffer.
	if q.Enqueue([]byte("z")) || q.Len() != 0 {
		t.Fatal("a closed queue took a datagram")
	}
	if _, err := q.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("Read() after Close = %v, want its error", err)
	}
}

// A read racing with Close returns the close error rather than data.
func TestQueueReadRacingClose(t *testing.T) {
	for range 200 {
		q := newQueue(4)
		q.Enqueue([]byte("y"))
		go q.Close(net.ErrClosed)
		if _, err := q.Read(make([]byte, 1)); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Read() = %v", err)
		}
		<-q.Done()
		if _, err := q.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Read() after Close = %v, want net.ErrClosed", err)
		}
	}
}

func TestQueueActivityIsMonotonic(t *testing.T) {
	q := newQueue(1)
	q.Accepted()
	if d := time.Duration(clock.RealEpoch.Now() - q.active.Load()); d < 0 || d > time.Second {
		t.Fatalf("activity stamp is %v behind the monotonic clock, want about 0", d)
	}
	if last, accepted := q.Activity(); !accepted || last > clock.RealEpoch.Now() || last < clock.RealEpoch.At(time.Now().Add(-time.Hour)) {
		t.Fatal("Activity does not follow the activity stamp")
	}
}

func TestQueueDoesNotAllocate(t *testing.T) {
	q := newQueue(4)
	p := make([]byte, 100)
	buf := make([]byte, bufpool.SmallSize)
	allocs := testing.AllocsPerRun(1000, func() {
		q.Enqueue(p)
		if n, err := q.Read(buf); n != len(p) || err != nil {
			t.Fatalf("Read() = %d, %v", n, err)
		}
	})
	if allocs > 0 {
		t.Fatalf("allocations per queued datagram = %v, want 0", allocs)
	}
}

// The ring grows with the datagrams queued, keeping the bound, and a burst's
// room is let go once it is read.
func TestQueueGrowsOnDemand(t *testing.T) {
	q := newQueue(128)
	if q.ring != nil {
		t.Fatalf("a new queue holds %d slots, want none", len(q.ring))
	}
	q.Enqueue([]byte("x"))
	if len(q.ring) > minRing {
		t.Fatalf("one datagram holds %d slots, want at most %d", len(q.ring), minRing)
	}
	accepted := 1
	for range 200 {
		if q.Enqueue([]byte("x")) {
			accepted++
		}
	}
	if accepted != 128 || q.Len() != 128 {
		t.Fatalf("queued %d (Len %d), want the bound of 128", accepted, q.Len())
	}
	buf := make([]byte, 8)
	for range 128 {
		if _, err := q.Read(buf); err != nil {
			t.Fatal(err)
		}
	}
	if len(q.ring) > minRing {
		t.Fatalf("a drained queue holds %d slots, want at most %d", len(q.ring), minRing)
	}
}

// Several readers take every datagram, also when they are queued faster
// than one wake-up each.
func TestQueueSeveralReaders(t *testing.T) {
	q := newQueue(1024)
	const total = 1000
	var got atomic.Int64
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			buf := make([]byte, 8)
			for {
				if _, err := q.Read(buf); err != nil {
					return
				}
				if got.Add(1) == total {
					q.Close(net.ErrClosed)
				}
			}
		})
	}
	for range total {
		for !q.Enqueue([]byte("x")) {
			runtime.Gosched()
		}
	}
	wg.Wait()
	if n := got.Load(); n != total {
		t.Fatalf("read %d datagrams, want %d", n, total)
	}
}

// BenchmarkIdleQueueMemory reports the memory of the queue of an idle flow
// with the default bound, after one datagram passed.
func BenchmarkIdleQueueMemory(b *testing.B) {
	for _, n := range []int{10, 1 << 20} {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			buf := make([]byte, 8)
			for b.Loop() {
				var before, after runtime.MemStats
				runtime.GC()
				runtime.GC()
				runtime.ReadMemStats(&before)
				qs := make([]Queue, n)
				for i := range qs {
					qs[i].Init(128, nil)
					qs[i].Enqueue(buf)
					_, _ = qs[i].Read(buf)
				}
				runtime.GC()
				runtime.ReadMemStats(&after)
				b.ReportMetric(float64(after.HeapInuse-before.HeapInuse)/float64(n), "B/flow")
				runtime.KeepAlive(qs)
			}
		})
	}
}

// The ring grows to the bound, which need not be a power of two, and no
// further.
func TestQueueRingKeepsToBound(t *testing.T) {
	q := newQueue(100)
	for range 150 {
		q.Enqueue([]byte("x"))
	}
	if q.Len() != 100 || len(q.ring) != 100 {
		t.Fatalf("Len %d, ring %d, want 100 and 100", q.Len(), len(q.ring))
	}
}
