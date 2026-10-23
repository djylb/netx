package transparent

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/djylb/netx"
	"github.com/djylb/netx/internal/dgram"
)

var errBenchDone = errors.New("bench done")

// BenchmarkFlowRead queues a datagram on a flow and Reads it: the
// listener's dispatch and queue, and the connection's Read.
func BenchmarkFlowRead(b *testing.B) {
	l := benchFlowListener(b)
	info := redirectedInfo("192.0.2.1:1000", "198.51.100.1:53")
	msg := make([]byte, 1200)
	l.deliver(msg, info)
	f := benchAccept(b, l)
	buf := make([]byte, 2048)
	if _, err := f.Read(buf); err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(msg)))
	b.ReportAllocs()
	for b.Loop() {
		l.deliver(msg, info)
		if _, err := f.Read(buf); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkFlowCopy copies the queued datagrams of a flow with netx.Copy,
// as a relay of a TPROXY UDP flow does.
func BenchmarkFlowCopy(b *testing.B) {
	l := benchFlowListener(b, WithFlowQueue(64))
	info := redirectedInfo("192.0.2.1:1000", "198.51.100.1:53")
	msg := make([]byte, 1200)
	l.deliver(msg, info)
	f := benchAccept(b, l)
	if _, err := f.Read(make([]byte, 2048)); err != nil {
		b.Fatal(err)
	}
	const datagrams = 32
	var left int
	flow := netx.RelayFlow{Wait: func(_ context.Context, n int64) (int64, error) {
		if left == 0 {
			return 0, errBenchDone
		}
		left--
		return n, nil
	}}
	b.SetBytes(int64(len(msg)) * datagrams)
	b.ReportAllocs()
	for b.Loop() {
		for range datagrams {
			l.deliver(msg, info)
		}
		left = datagrams
		if _, err := netx.Copy(context.Background(), io.Discard, f, &flow); !errors.Is(err, errBenchDone) {
			b.Fatal(err)
		}
	}
}

func benchFlowListener(b *testing.B, opts ...FlowOption) *FlowListener {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		b.Fatal(err)
	}
	l := newFlowListener(c, opts)
	b.Cleanup(func() { _ = l.Close() })
	return l
}

func benchAccept(b *testing.B, l *FlowListener) *FlowConn {
	c, err := l.Accept()
	if err != nil {
		b.Fatal(err)
	}
	return c.(*FlowConn)
}

// netx.Relay and netx.Copy find the flow's queue, and take its datagrams
// whole from it, but not through a type that embeds the flow.
func TestFlowConnHandsQueueToRelay(t *testing.T) {
	l := testFlowListener(t)
	info := redirectedInfo("192.0.2.1:1000", "198.51.100.1:53")
	l.deliver([]byte("one"), info)
	f := acceptFlow(t, l)
	if dgram.QueueOf(f) != &f.q {
		t.Fatal("the flow's queue is not found")
	}
	if dgram.QueueOf(struct{ *FlowConn }{f}) != nil {
		t.Fatal("the queue of an embedded flow is found")
	}
	l.deliver([]byte("two"), info)
	var got []string
	stop := errors.New("stop")
	flow := &netx.RelayFlow{Wait: func(_ context.Context, n int64) (int64, error) {
		if len(got) == 2 {
			return 0, stop
		}
		return n, nil
	}}
	w := writerFunc(func(b []byte) (int, error) { got = append(got, string(b)); return len(b), nil })
	if _, err := netx.Copy(context.Background(), w, f, flow); !errors.Is(err, stop) || len(got) != 2 || got[0] != "one" || got[1] != "two" {
		t.Fatalf("Copy() = %v, wrote %q", err, got)
	}
}

type writerFunc func([]byte) (int, error)

func (w writerFunc) Write(b []byte) (int, error) { return w(b) }
