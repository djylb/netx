package dgram

import (
	"errors"
	"io"
	"net"
	"os"
	"slices"
	"testing"
	"time"
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
	buf := make([]byte, MaxDatagram)
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
		if n := q.queued.Load(); n != 0 {
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
	if q.readDeadline.timer != nil {
		t.Fatal("deadline timer still pending after Close")
	}
	q.SetReadDeadline(time.Now().Add(time.Hour)) // as by a setter racing with Close
	if q.readDeadline.timer != nil {
		t.Fatal("a stopped deadline started a timer")
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
	if d := time.Duration(RealEpoch.Now() - q.active.Load()); d < 0 || d > time.Second {
		t.Fatalf("activity stamp is %v behind the monotonic clock, want about 0", d)
	}
	if q.IdleAt(RealEpoch.Now(), time.Hour) || !q.IdleAt(RealEpoch.At(time.Now().Add(time.Hour)), time.Hour) {
		t.Fatal("IdleAt does not follow the activity stamp")
	}
}

func TestQueueDoesNotAllocate(t *testing.T) {
	q := newQueue(4)
	p := make([]byte, 100)
	buf := make([]byte, SmallSize)
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
