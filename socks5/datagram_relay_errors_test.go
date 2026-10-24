//go:build !plan9

package socks5

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/djylb/netx"
)

// scriptedPacketConn takes every datagram sent and returns the replies and
// errors of reads in turn, then repeats the last one forever.
type scriptedPacketConn struct {
	reads  chan scriptedRead
	last   scriptedRead
	sent   atomic.Int32
	done   chan struct{}
	closed atomic.Bool
}

type scriptedRead struct {
	payload string
	err     error
}

func newScriptedPacketConn() *scriptedPacketConn {
	return &scriptedPacketConn{reads: make(chan scriptedRead, 16), done: make(chan struct{})}
}

func (c *scriptedPacketConn) WriteTo(p []byte, _ netx.Addr) (int, error) {
	c.sent.Add(1)
	return len(p), nil
}

func (c *scriptedPacketConn) ReadFrom(p []byte) (int, netx.Addr, error) {
	if c.last.err == nil || len(c.reads) > 0 {
		select {
		case c.last = <-c.reads:
		case <-c.done:
			return 0, netx.Addr{}, net.ErrClosed
		}
	}
	if c.last.err != nil {
		return 0, netx.Addr{}, c.last.err
	}
	return copy(p, c.last.payload), netx.Addr{IP: netip.MustParseAddr("127.0.0.1"), Port: 9}, nil
}

func (c *scriptedPacketConn) Close() error {
	if !c.closed.Swap(true) {
		close(c.done)
	}
	return nil
}

// icmpErr is the error of a UDP socket's read for an ICMP report.
func icmpErr(errno syscall.Errno) error {
	return &net.OpError{Op: "read", Net: "udp", Err: os.NewSyscallError("recvfrom", errno)}
}

// A UDP socket's ICMP errors are skipped, one per datagram sent, and the
// relay goes on; one more ends it instead of looping on it.
func TestDatagramRelaySkipsICMPErrorsPerDatagram(t *testing.T) {
	checkGoroutines(t)
	out := newScriptedPacketConn()
	s := newFakeStream()
	var reported atomic.Int32
	done := runRelay(t, t.Context(), &DatagramRelay{OnError: func(error) { reported.Add(1) }}, s, out)
	dst := netx.Addr{Name: "x.test", Port: 9}
	for range 3 {
		s.send(t, dst, "x")
	}
	for out.sent.Load() < 3 {
		time.Sleep(time.Millisecond)
	}
	out.reads <- scriptedRead{err: icmpErr(syscall.ECONNREFUSED)}
	out.reads <- scriptedRead{err: icmpErr(syscall.ECONNRESET)}
	out.reads <- scriptedRead{err: icmpErr(syscall.ECONNREFUSED)}
	out.reads <- scriptedRead{payload: "reply"}
	if _, got := s.recv(t); got != "reply" {
		t.Fatalf("reply = %q", got)
	}
	if n := reported.Load(); n != 3 {
		t.Fatalf("%d errors reported, want 3", n)
	}
	// Sticky from now on: one more than the datagrams sent.
	out.reads <- scriptedRead{err: icmpErr(syscall.ECONNRESET)}
	if err := waitRelay(t, done); !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("Relay() = %v, want the reset", err)
	}
	if n := reported.Load(); n != 3 {
		t.Fatalf("%d errors reported, want 3", n)
	}
}

// A PacketConn that keeps returning a reset, as one over a broken tunnel
// does, ends the relay at once, whether the error reads like a reset or
// carries the errno without being a UDP socket's.
func TestDatagramRelayEndsOnStickyResetError(t *testing.T) {
	for _, err := range []error{
		errors.New("read tcp: connection reset by peer"),
		&net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("read", syscall.ECONNRESET)},
		icmpErr(syscall.ECONNRESET), // with no datagram sent
	} {
		t.Run(err.Error(), func(t *testing.T) {
			checkGoroutines(t)
			out := newScriptedPacketConn()
			out.reads <- scriptedRead{err: err}
			s := newFakeStream()
			var reported atomic.Int32
			done := runRelay(t, t.Context(), &DatagramRelay{OnError: func(error) { reported.Add(1) }}, s, out)
			if got := waitRelay(t, done); !errors.Is(got, err) {
				t.Fatalf("Relay() = %v, want %v", got, err)
			}
			if n := reported.Load(); n != 0 {
				t.Fatalf("OnError called %d times", n)
			}
		})
	}
}

// Invalid datagrams are not reported by a Server's relay, and do not keep
// an idle relay going.
func TestDatagramRelayInvalidDatagrams(t *testing.T) {
	checkGoroutines(t)
	var reported atomic.Int32
	d := &datagramRelay{stream: &oneDatagram{b: []byte{0, 0, 1, 1, 127, 0, 0, 1, 0, 9}}, out: &recordingPacketConn{}, onError: func(error) { reported.Add(1) }}
	if err := d.requests(); err != nil || reported.Load() != 0 {
		t.Fatalf("requests() = %v with %d reports, want nil and none", err, reported.Load())
	}

	out := newScriptedPacketConn()
	s := newFakeStream()
	const idle = 150 * time.Millisecond
	done := runRelay(t, t.Context(), &DatagramRelay{IdleTimeout: idle, Allow: func(netx.Addr) bool { return false }}, s, out)
	frag := []byte{0, 0, 1, 1, 127, 0, 0, 1, 0, 9}
	start := time.Now()
	for {
		select {
		case err := <-done:
			if !errors.Is(err, netx.ErrRelayIdle) {
				t.Fatalf("Relay() = %v, want netx.ErrRelayIdle", err)
			}
			if out.sent.Load() != 0 {
				t.Fatal("a refused datagram was sent")
			}
			return
		case <-time.After(idle / 10):
		}
		if time.Since(start) > 10*idle {
			t.Fatal("invalid and refused datagrams kept the relay going")
		}
		select {
		case s.in <- frag:
		default:
		}
		s.send(t, netx.Addr{Name: "refused.test", Port: 9}, "x")
	}
}
