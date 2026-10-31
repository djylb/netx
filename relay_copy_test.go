package netx

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/djylb/timeshim"
)

// endRecord records the calls of RelayFlow.End.
type endRecord struct {
	calls atomic.Int32
	n     atomic.Int64
	err   atomic.Value // errBox
}

type errBox struct{ err error }

func (r *endRecord) flow() RelayFlow {
	return RelayFlow{End: func(n int64, err error) {
		r.calls.Add(1)
		r.n.Store(n)
		r.err.Store(errBox{err})
	}}
}

func (r *endRecord) get() (int32, int64, error) {
	box, _ := r.err.Load().(errBox)
	return r.calls.Load(), r.n.Load(), box.err
}

// Copy stops at EOF with nil, closes neither end and calls End once.
func TestCopy(t *testing.T) {
	peer, c := tcpPair(t)
	var rec endRecord
	f := rec.flow()
	go func() {
		_, _ = peer.Write([]byte("hello"))
		_ = peer.(*net.TCPConn).CloseWrite()
	}()
	var buf bytes.Buffer
	n, err := Copy(context.Background(), &buf, c, &f)
	if n != 5 || err != nil || buf.String() != "hello" {
		t.Fatalf("Copy() = %d, %v, %q", n, err, buf.String())
	}
	if calls, en, eerr := rec.get(); calls != 1 || en != 5 || eerr != nil {
		t.Fatalf("End calls %d with %d, %v", calls, en, eerr)
	}
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatalf("Copy() closed its source: %v", err)
	}
	// Without a flow, through the copy without hooks.
	peer2, c2 := tcpPair(t)
	go func() { _, _ = peer2.Write([]byte("abc")); _ = peer2.Close() }()
	buf.Reset()
	if n, err := Copy(context.Background(), &buf, c2, nil); n != 3 || err != nil {
		t.Fatalf("Copy(nil flow) = %d, %v", n, err)
	}
}

// A done context interrupts a Copy blocked in a read with deadlines, and the
// cause is returned.
func TestCopyContextInterrupts(t *testing.T) {
	errStop := errors.New("stop")
	for _, wrap := range []bool{false, true} {
		peer, c := tcpPair(t)
		src := c
		if wrap {
			src = NewTimeoutConn(c, time.Hour)
		}
		ctx, cancel := context.WithCancelCause(context.Background())
		var rec endRecord
		f := rec.flow()
		done := make(chan error, 1)
		go func() {
			_, err := Copy(ctx, io.Discard, src, &f)
			done <- err
		}()
		time.Sleep(20 * time.Millisecond)
		cancel(errStop)
		select {
		case err := <-done:
			if !errors.Is(err, errStop) {
				t.Fatalf("wrap %t: Copy() error = %v, want the cause", wrap, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("wrap %t: Copy() did not end with its context", wrap)
		}
		if calls, _, eerr := rec.get(); calls != 1 || !errors.Is(eerr, errStop) {
			t.Fatalf("wrap %t: End calls %d with %v", wrap, calls, eerr)
		}
		// Still open: the deadline only needs resetting.
		_ = src.SetReadDeadline(time.Time{})
		_, _ = peer.Write([]byte("z"))
		if _, err := io.ReadFull(src, make([]byte, 1)); err != nil {
			t.Fatalf("wrap %t: read after Copy() = %v", wrap, err)
		}
		// An already done context copies nothing.
		if n, err := Copy(ctx, io.Discard, src, nil); n != 0 || !errors.Is(err, errStop) {
			t.Fatalf("wrap %t: Copy(done ctx) = %d, %v", wrap, n, err)
		}
	}
}

// End is called for each direction, before the end is passed on with
// CloseWrite, and reports net.ErrClosed for a direction the relay cut short.
func TestRelayFlowEnd(t *testing.T) {
	t.Run("half close", func(t *testing.T) {
		userA, relayA := tcpPair(t)
		relayB, userB := tcpPair(t)
		var up, down endRecord
		upFlow, downFlow := up.flow(), down.flow()
		var endedBeforeEOF atomic.Bool
		inner := upFlow.End
		upFlow.End = func(n int64, err error) {
			inner(n, err)
			endedBeforeEOF.Store(true)
		}
		done := make(chan error, 1)
		go func() {
			_, _, err := Relay(context.Background(), relayA, relayB, WithRelayHalfClose(), WithRelayFlows(&upFlow, &downFlow))
			done <- err
		}()
		_, _ = userA.Write([]byte("ab"))
		_ = userA.(*net.TCPConn).CloseWrite()
		if got, err := io.ReadAll(userB); err != nil || string(got) != "ab" {
			t.Fatalf("userB read %q, %v", got, err)
		}
		if !endedBeforeEOF.Load() {
			t.Fatal("End ran after the end was passed on")
		}
		_, _ = userB.Write([]byte("xyz"))
		_ = userB.(*net.TCPConn).CloseWrite()
		if got, _ := io.ReadAll(userA); string(got) != "xyz" {
			t.Fatalf("userA read %q", got)
		}
		if err := <-done; err != nil {
			t.Fatalf("Relay(context.Background()) error = %v", err)
		}
		if calls, n, err := up.get(); calls != 1 || n != 2 || err != nil {
			t.Fatalf("up End: %d calls, %d, %v", calls, n, err)
		}
		if calls, n, err := down.get(); calls != 1 || n != 3 || err != nil {
			t.Fatalf("down End: %d calls, %d, %v", calls, n, err)
		}
	})
	t.Run("cut short", func(t *testing.T) {
		userA, relayA := tcpPair(t)
		relayB, _ := tcpPair(t)
		var up, down endRecord
		done := make(chan error, 1)
		go func() {
			_, _, err := Relay(context.Background(), relayA, relayB, WithRelayFlows(new(up.flow()), new(down.flow())))
			done <- err
		}()
		_ = userA.Close()
		if err := <-done; err != nil {
			t.Fatalf("Relay(context.Background()) error = %v", err)
		}
		if calls, _, err := up.get(); calls != 1 || err != nil {
			t.Fatalf("up End: %d calls, %v; want nil at EOF", calls, err)
		}
		if calls, _, err := down.get(); calls != 1 || !errors.Is(err, net.ErrClosed) {
			t.Fatalf("down End: %d calls, %v; want net.ErrClosed", calls, err)
		}
	})
}

// A TimeoutConn does not keep Relay from splicing or waiting without a
// buffer, and its idle timeout still holds: traffic in one direction keeps
// both directions alive, and idleness ends the relay.
func TestRelayThroughTimeoutConn(t *testing.T) {
	const idle = 150 * time.Millisecond
	userA, relayA := tcpPair(t)
	relayB, userB := tcpPair(t)
	done := make(chan error, 1)
	start := time.Now()
	go func() {
		_, _, err := Relay(context.Background(), NewTimeoutConn(relayA, idle), NewTimeoutConn(relayB, idle))
		done <- err
	}()
	go func() { _, _ = io.Copy(io.Discard, userB) }()
	for range 10 {
		if _, err := userA.Write([]byte("tick")); err != nil {
			t.Fatalf("Write() error = %v", err)
		}
		time.Sleep(idle / 3)
	}
	select {
	case err := <-done:
		t.Fatalf("Relay(context.Background()) ended while in use after %v: %v", time.Since(start), err)
	default:
	}
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("Relay(context.Background()) error = %v, want the idle timeout", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Relay(context.Background()) did not time out when idle")
	}
}

// A relay through TimeoutConns that never sees a byte times out too.
func TestRelayThroughTimeoutConnIdleFromStart(t *testing.T) {
	const idle = 100 * time.Millisecond
	_, relayA := tcpPair(t)
	relayB, _ := tcpPair(t)
	done := make(chan error, 1)
	go func() {
		_, _, err := Relay(context.Background(), NewTimeoutConn(relayA, idle), NewTimeoutConn(relayB, idle))
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("Relay(context.Background()) error = %v, want the idle timeout", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Relay(context.Background()) did not time out when idle")
	}
}

// A busy stream through TimeoutConns, which Relay may read many times
// without waiting, outlasts the idle timeout.
func TestRelayThroughTimeoutConnBusy(t *testing.T) {
	// Long enough that no single write, slowed down by the race detector,
	// blocks for it.
	const idle = 300 * time.Millisecond
	userA, relayA := tcpPair(t)
	relayB, userB := tcpPair(t)
	done := make(chan error, 1)
	go func() {
		_, _, err := Relay(context.Background(), NewTimeoutConn(relayA, idle), NewTimeoutConn(relayB, idle))
		done <- err
	}()
	go func() { _, _ = io.Copy(io.Discard, userB) }()
	chunk := make([]byte, 256<<10)
	for end := time.Now().Add(4 * idle); time.Now().Before(end); {
		if _, err := userA.Write(chunk); err != nil {
			t.Fatalf("Write() error = %v; Relay(context.Background()) = %v", err, <-done)
		}
	}
	select {
	case err := <-done:
		t.Fatalf("Relay(context.Background()) ended while busy: %v", err)
	default:
	}
}

// WithRelayIdleTimeout ends an idle relay with ErrRelayIdle, over sockets
// and over ends without deadlines, while traffic in one direction keeps it
// alive.
func TestRelayIdleTimeout(t *testing.T) {
	const idle = time.Minute
	t.Run("conns", func(t *testing.T) {
		fake := timeshim.NewFake(time.Now())
		userA, relayA := tcpPair(t)
		relayB, userB := tcpPair(t)
		touched := make(chan struct{}, 1)
		flow := RelayFlow{Done: func(int64) error { touched <- struct{}{}; return nil }}
		done := make(chan error, 1)
		go func() {
			_, _, err := Relay(context.Background(), relayA, relayB, WithRelayIdleTimeout(idle), WithRelayClock(fake), WithRelayFlows(&flow, nil))
			done <- err
		}()
		go func() { _, _ = io.Copy(io.Discard, userB) }()
		waitPending(t, fake, 1)
		for range 4 {
			fake.Advance(idle / 2)
			_, _ = userA.Write([]byte("tick"))
			select {
			case <-touched: // the activity is recorded at this time
			case <-time.After(5 * time.Second):
				t.Fatal("no data passed")
			}
		}
		fake.Advance(idle - time.Nanosecond)
		select {
		case err := <-done:
			t.Fatalf("Relay() ended while in use: %v", err)
		default:
		}
		fake.Advance(time.Nanosecond)
		select {
		case err := <-done:
			if !errors.Is(err, ErrRelayIdle) {
				t.Fatalf("Relay() error = %v, want ErrRelayIdle", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Relay() did not end when idle")
		}
	})
	t.Run("ends without deadlines", func(t *testing.T) {
		fake := timeshim.NewFake(time.Now())
		a, b := &blockingRWC{closed: make(chan struct{})}, &blockingRWC{closed: make(chan struct{})}
		done := make(chan error, 1)
		go func() {
			_, _, err := Relay(context.Background(), a, b, WithRelayIdleTimeout(idle), WithRelayClock(fake))
			done <- err
		}()
		waitPending(t, fake, 1)
		fake.Advance(idle - time.Nanosecond)
		select {
		case err := <-done:
			t.Fatalf("Relay() = %v before the idle timeout", err)
		default:
		}
		fake.Advance(time.Nanosecond)
		select {
		case err := <-done:
			if !errors.Is(err, ErrRelayIdle) {
				t.Fatalf("Relay() = %v, want ErrRelayIdle", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Relay() did not end when idle")
		}
	})
}

// The idle timeout counts from the time of the clock it is given, also of a
// fake one at the zero time, and one large Advance ends the relay.
func TestRelayIdleTimeoutZeroTimeClock(t *testing.T) {
	const idle = time.Second
	fake := timeshim.NewFake(time.Time{})
	a, b := &blockingRWC{closed: make(chan struct{})}, &blockingRWC{closed: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		_, _, err := Relay(context.Background(), a, b, WithRelayIdleTimeout(idle), WithRelayClock(fake))
		done <- err
	}()
	waitPending(t, fake, 1)
	fake.Advance(10 * idle)
	select {
	case err := <-done:
		if !errors.Is(err, ErrRelayIdle) {
			t.Fatalf("Relay() = %v, want ErrRelayIdle", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Relay() did not end when idle")
	}
}

// noDeadlineConn is a connection without deadline support, as an SSH
// channel is.
type noDeadlineConn struct{ net.Conn }

func (noDeadlineConn) SetDeadline(time.Time) error      { return errors.ErrUnsupported }
func (noDeadlineConn) SetReadDeadline(time.Time) error  { return errors.ErrUnsupported }
func (noDeadlineConn) SetWriteDeadline(time.Time) error { return errors.ErrUnsupported }

// The idle timeout works without deadlines, leaves the ends' own deadlines
// in effect, and does not count a blocked Wait as idleness.
func TestRelayIdleTimeoutLeavesDeadlines(t *testing.T) {
	const idle = 150 * time.Millisecond
	t.Run("no deadline support", func(t *testing.T) {
		userA, relayA := net.Pipe()
		relayB, userB := net.Pipe()
		defer func() { _ = userA.Close(); _ = userB.Close() }()
		done := make(chan error, 1)
		go func() {
			_, _, err := Relay(context.Background(), noDeadlineConn{relayA}, relayB, WithRelayIdleTimeout(idle))
			done <- err
		}()
		go func() { _, _ = io.Copy(io.Discard, userB) }()
		if _, err := userA.Write([]byte("x")); err != nil {
			t.Fatalf("Write() = %v", err)
		}
		if err := <-done; !errors.Is(err, ErrRelayIdle) {
			t.Fatalf("Relay() = %v, want ErrRelayIdle", err)
		}
	})
	t.Run("own deadline", func(t *testing.T) {
		userA, relayA := tcpPair(t)
		relayB, userB := tcpPair(t)
		_ = relayA.SetDeadline(time.Now().Add(300 * time.Millisecond))
		done := make(chan error, 1)
		go func() {
			_, _, err := Relay(context.Background(), relayA, relayB, WithRelayIdleTimeout(5*time.Second))
			done <- err
		}()
		go func() { _, _ = io.Copy(io.Discard, userB) }()
		stopTicks := make(chan struct{})
		defer close(stopTicks)
		go func() {
			for {
				select {
				case <-stopTicks:
					return
				case <-time.After(50 * time.Millisecond):
					_, _ = userA.Write([]byte("tick"))
				}
			}
		}()
		select {
		case err := <-done:
			if !errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, ErrRelayIdle) {
				t.Fatalf("Relay() = %v, want the end's own deadline", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("the end's own deadline was lifted")
		}
	})
	t.Run("blocked wait", func(t *testing.T) {
		userA, relayA := tcpPair(t)
		relayB, userB := tcpPair(t)
		release := make(chan struct{})
		flow := RelayFlow{Wait: func(ctx context.Context, n int64) (int64, error) {
			select {
			case <-release:
				return n, nil
			case <-ctx.Done():
				return 0, ctx.Err()
			}
		}}
		done := make(chan error, 1)
		go func() {
			_, _, err := Relay(context.Background(), relayA, relayB, WithRelayIdleTimeout(idle), WithRelayFlows(&flow, nil))
			done <- err
		}()
		_, _ = userA.Write([]byte("x"))
		time.Sleep(3 * idle)
		select {
		case err := <-done:
			t.Fatalf("Relay() ended while Wait blocked: %v", err)
		default:
		}
		close(release)
		if _, err := io.ReadFull(userB, make([]byte, 1)); err != nil {
			t.Fatalf("read after Wait = %v", err)
		}
		if err := <-done; !errors.Is(err, ErrRelayIdle) {
			t.Fatalf("Relay() = %v, want ErrRelayIdle", err)
		}
	})
}
