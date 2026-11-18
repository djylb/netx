//go:build unix

package netx

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// A copy from an idle socket holds no buffer while it waits.
func TestCopyStreamIdleSocketHoldsNoBuffer(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector adds to every allocation")
	}
	const n = 200
	var wg sync.WaitGroup
	conns := make([][2]io.Closer, 0, n)
	for range n {
		a, b := tcpPair(t)
		conns = append(conns, [2]io.Closer{a, b})
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for _, c := range conns {
		src := c[1].(io.Reader)
		wg.Go(func() { _, _ = copyStream(context.Background(), io.Discard, newRelaySource(src), nil) })
	}
	time.Sleep(200 * time.Millisecond) // let every copy block
	runtime.ReadMemStats(&after)
	for _, c := range conns {
		_ = c[0].Close()
	}
	wg.Wait()
	if per := int64(after.HeapAlloc-before.HeapAlloc) / n; per >= relayBufSize/2 {
		t.Fatalf("an idle copy holds %d bytes, want no %d byte buffer", per, relayBufSize)
	}
}

// A reset that arrives while a relay waits for an idle socket is reported,
// not taken for a clean end: peeking at the socket clears its error on Linux.
func TestRelayReportsResetOfIdleSocket(t *testing.T) {
	a, b := tcpPair(t)
	c, d := tcpPair(t)
	defer func() { _ = d.Close() }()
	done := make(chan error, 1)
	go func() {
		// A TimeoutConn end cannot splice, so the copy from b waits on it.
		_, _, err := Relay(context.Background(), b, NewTimeoutConn(c, time.Minute))
		done <- err
	}()
	time.Sleep(50 * time.Millisecond) // let the relay wait
	_ = a.(*net.TCPConn).SetLinger(0)
	_ = a.Close() // sends a reset
	select {
	case err := <-done:
		if !IsConnReset(err) {
			t.Fatalf("Relay(context.Background()) error = %v, want the reset", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Relay(context.Background()) did not end after the reset")
	}
}

// Closing a relay's ends from outside, as ConnGroup.CloseMembers does, ends it
// also while its Waits would block, as for a used up allowance.
func TestRelayEndsWhenClosedWhileWaitWouldBlock(t *testing.T) {
	for _, dstTimeout := range []bool{false, true} {
		_, b := tcpPair(t)
		c, _ := tcpPair(t)
		blocked := RelayFlow{Wait: func(ctx context.Context, _ int64) (int64, error) {
			<-ctx.Done()
			return 0, ctx.Err()
		}}
		var dst io.ReadWriteCloser = c
		if dstTimeout {
			dst = NewTimeoutConn(c, time.Minute) // copied through the buffer
		}
		done := make(chan struct{})
		go func() {
			_, _, _ = Relay(context.Background(), b, dst, WithRelayFlows(&blocked, &blocked))
			close(done)
		}()
		time.Sleep(50 * time.Millisecond)
		_ = b.Close()
		_ = c.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("timeout end %t: Relay(context.Background()) did not end after its ends were closed", dstTimeout)
		}
	}
}

// heldPerCopy runs n copies from sockets fed by feed, waits until each
// stalls, and returns the heap each holds.
func heldPerCopy(t *testing.T, n int, feed func(peer io.Writer), flow func() *RelayFlow, stalled func() bool) int64 {
	t.Helper()
	var wg sync.WaitGroup
	peers := make([]io.Closer, 0, n)
	srcs := make([]io.Reader, 0, n)
	for range n {
		a, b := tcpPair(t)
		peers = append(peers, a)
		srcs = append(srcs, b)
		feed(a)
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for _, src := range srcs {
		f := flow()
		wg.Go(func() { _, _ = copyStream(context.Background(), io.Discard, newRelaySource(src), f) })
	}
	waitUntil(t, stalled)
	time.Sleep(100 * time.Millisecond)
	runtime.ReadMemStats(&after)
	for _, p := range peers {
		_ = p.Close()
	}
	return int64(after.HeapAlloc-before.HeapAlloc) / int64(n)
}

// A copy holds no buffer while its Wait blocks, as when a limiter waits out
// a debt after a full read.
func TestCopyStreamBlockedWaitHoldsNoBuffer(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector adds to every allocation")
	}
	const n = 200
	release := make(chan struct{})
	var blocked atomic.Int64
	paced := func() *RelayFlow {
		calls := 0
		return &RelayFlow{Wait: func(ctx context.Context, _ int64) (int64, error) {
			if calls++; calls > 1 {
				// The read before filled its 100 bytes; wait out a debt.
				blocked.Add(1)
				select {
				case <-release:
				case <-ctx.Done():
				}
				return 0, errors.New("stopped")
			}
			return 100, nil
		}}
	}
	per := heldPerCopy(t, n, func(peer io.Writer) { _, _ = peer.Write(make([]byte, 1000)) }, paced,
		func() bool { return blocked.Load() == n })
	close(release)
	if per >= relayBufSize/2 {
		t.Fatalf("a copy blocked in Wait holds %d bytes, want no %d byte buffer", per, relayBufSize)
	}
}

// A copy whose last read filled the buffer holds none once the socket is
// idle.
func TestCopyStreamIdleAfterFullReadHoldsNoBuffer(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector adds to every allocation")
	}
	const n = 200
	var copied atomic.Int64
	count := func() *RelayFlow {
		return &RelayFlow{Done: func(m int64) error {
			copied.Add(m)
			return nil
		}}
	}
	per := heldPerCopy(t, n, func(peer io.Writer) { _, _ = peer.Write(make([]byte, relayBufSize)) }, count,
		func() bool { return copied.Load() >= n*relayBufSize })
	if per >= relayBufSize/2 {
		t.Fatalf("an idle copy after a full read holds %d bytes, want no %d byte buffer", per, relayBufSize)
	}
}

// blockAfterFirst returns a flow whose first Wait allows first bytes and
// whose later Waits block until ctx is done, as for a used up allowance;
// blocked counts the blocked Waits.
func blockAfterFirst(first int64, blocked *atomic.Int64) RelayFlow {
	calls := 0
	return RelayFlow{Wait: func(ctx context.Context, _ int64) (int64, error) {
		if calls++; calls > 1 {
			blocked.Add(1)
			<-ctx.Done()
			return 0, ctx.Err()
		}
		return first, nil
	}}
}

// A group ends a relay whose Waits block with data pending, which closing
// its ends cannot.
func TestRelayWithGroupEndsBlockedWaits(t *testing.T) {
	for _, dstTimeout := range []bool{false, true} {
		a, b := tcpPair(t)
		c, d := tcpPair(t)
		var blocked atomic.Int64
		var g ConnGroup
		var dst io.ReadWriteCloser = c
		if dstTimeout {
			dst = NewTimeoutConn(c, time.Minute)
		}
		done := make(chan error, 1)
		go func() {
			_, _, err := Relay(context.Background(), b, dst, WithRelayGroup(&g), WithRelayFlows(new(blockAfterFirst(100, &blocked)), new(blockAfterFirst(100, &blocked))))
			done <- err
		}()
		_, _ = a.Write(make([]byte, 1000))
		_, _ = d.Write(make([]byte, 1000))
		waitUntil(t, func() bool { return blocked.Load() == 2 })
		_ = g.CloseMembers(nil)
		select {
		case err := <-done:
			if !errors.Is(err, ErrRelayGroupClosed) {
				t.Fatalf("timeout end %t: Relay(context.Background()) error = %v, want ErrRelayGroupClosed", dstTimeout, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("timeout end %t: Relay(context.Background()) did not end with its group", dstTimeout)
		}
		if g.Len() != 0 {
			t.Fatalf("the ended relay stayed in its group")
		}
	}
	// A closed group ends a relay at once.
	var g ConnGroup
	_ = g.Close()
	src := &readSizesConn{data: []byte("data")}
	dst := &blockingSink{blockingRWC: blockingRWC{closed: make(chan struct{})}}
	if _, _, err := Relay(context.Background(), src, dst, WithRelayGroup(&g)); !errors.Is(err, ErrRelayGroupClosed) || dst.out.Len() != 0 {
		t.Fatalf("on a closed group: Relay(context.Background()) error = %v, passed %d bytes", err, dst.out.Len())
	}
}

// The end of a socket passes on without Wait also after a read that took
// all Wait allowed, so that a blocked Wait does not hold it up.
func TestRelayPassesEndAfterFullReadWithoutWait(t *testing.T) {
	for _, dstTimeout := range []bool{false, true} {
		a, b := tcpPair(t)
		c, d := tcpPair(t)
		var blocked atomic.Int64
		var dst io.ReadWriteCloser = c
		if dstTimeout {
			dst = NewTimeoutConn(c, time.Minute)
		}
		go func() {
			_, _, _ = Relay(context.Background(), b, dst, WithRelayHalfClose(), WithRelayFlows(new(blockAfterFirst(100, &blocked)), nil))
		}()
		_, _ = a.Write(make([]byte, 100))
		_ = a.(*net.TCPConn).CloseWrite()
		_ = d.SetReadDeadline(time.Now().Add(5 * time.Second))
		if got, err := io.ReadAll(d); len(got) != 100 || err != nil {
			t.Fatalf("timeout end %t: relayed %d bytes, %v; want 100 and the end", dstTimeout, len(got), err)
		}
		if n := blocked.Load(); n != 0 {
			t.Fatalf("timeout end %t: %d Waits ran for the end", dstTimeout, n)
		}
		_ = d.Close()
	}
}

// A datagram direction holds no buffer while its Wait blocks.
func TestCopyDatagramsBlockedWaitHoldsNoBuffer(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector adds to every allocation")
	}
	const n = 100
	var blocked atomic.Int64
	release := make(chan struct{})
	var wg sync.WaitGroup
	var peers []io.Closer
	var srcs []io.Reader
	for range n {
		a, b := tcpPair(t)
		peers = append(peers, a)
		_ = NewFramedConn(a).WriteFrame([]byte("datagram"))
		srcs = append(srcs, NewFramedConn(b, WithFramedDatagrams()))
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for _, src := range srcs {
		calls := 0
		f := &RelayFlow{Wait: func(ctx context.Context, limit int64) (int64, error) {
			if calls++; calls > 1 {
				blocked.Add(1)
				<-release
				return 0, errors.New("stopped")
			}
			return limit, nil
		}}
		wg.Go(func() { _, _ = copyDatagrams(context.Background(), io.Discard, newRelaySource(src), f) })
	}
	waitUntil(t, func() bool { return blocked.Load() == n })
	runtime.ReadMemStats(&after)
	close(release)
	for _, p := range peers {
		_ = p.Close()
	}
	wg.Wait()
	if per := int64(after.HeapAlloc-before.HeapAlloc) / n; per >= largeBufSize/2 {
		t.Fatalf("a datagram copy blocked in Wait holds %d bytes, want no %d byte buffer", per, largeBufSize)
	}
}

// A passed deadline seen while waiting for a socket is reported as a read
// reports it.
func TestCopyStreamReportsWaitErrorsAsReads(t *testing.T) {
	_, b := tcpPair(t)
	_ = b.SetReadDeadline(time.Now().Add(-time.Second))
	_, err := copyStream(context.Background(), io.Discard, newRelaySource(b), nil)
	var oe *net.OpError
	if !IsTimeout(err) || !errors.As(err, &oe) || oe.Op != "read" {
		t.Fatalf("copyStream() error = %v, want a read timeout", err)
	}
}

// readFromConn is a connection whose ReadFrom reads its source through a
// buffer of its own, as a multiplexed stream that reads into its send
// space does, and counts its calls and those in progress.
type readFromConn struct {
	net.Conn
	calls, inFlight *atomic.Int64
}

func (c readFromConn) ReadFrom(r io.Reader) (int64, error) {
	c.calls.Add(1)
	c.inFlight.Add(1)
	defer c.inFlight.Add(-1)
	buf := make([]byte, 1024)
	var n int64
	for {
		m, err := r.Read(buf)
		if m > 0 {
			k, werr := c.Write(buf[:m])
			n += int64(k)
			if werr != nil {
				return n, werr
			}
		}
		if err == io.EOF {
			return n, nil
		}
		if err != nil {
			return n, err
		}
	}
}

func (c readFromConn) CloseWrite() error { return c.Conn.(*net.TCPConn).CloseWrite() }

// From a socket, the destination's ReadFrom runs only while the socket has
// data, so that what it holds is not held while the direction is idle, and
// EOF still half-closes the destination.
func TestRelayReadFromOnlyWhileReadable(t *testing.T) {
	paths := recordPaths(t)
	client, src := tcpPair(t)
	dstConn, peer := tcpPair(t)
	var calls, inFlight atomic.Int64
	dst := readFromConn{dstConn, &calls, &inFlight}
	done := make(chan error, 1)
	go func() {
		_, _, err := Relay(context.Background(), src, dst, WithRelayHalfClose())
		done <- err
	}()
	buf := make([]byte, 5)
	for i := range 3 {
		if _, err := client.Write([]byte("hello")); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(peer, buf); err != nil || string(buf) != "hello" {
			t.Fatalf("round %d: read %q, %v", i, buf, err)
		}
		waitFor(t, "ReadFrom to return", func() bool { return inFlight.Load() == 0 })
	}
	if n := calls.Load(); n < 3 {
		t.Fatalf("ReadFrom called %d times, want one per burst", n)
	}
	// EOF half-closes the destination; the other direction goes on.
	_ = client.(*net.TCPConn).CloseWrite()
	if n, err := peer.Read(buf); n != 0 || err != io.EOF {
		t.Fatalf("peer Read() = %d, %v, want EOF", n, err)
	}
	if _, err := peer.Write([]byte("back!")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(client, buf); err != nil || string(buf) != "back!" {
		t.Fatalf("client read %q, %v", buf, err)
	}
	_ = peer.Close()
	if err := <-done; err != nil {
		t.Fatalf("Relay() = %v", err)
	}
	if got := paths(); !slices.Contains(got, "readfrom") {
		t.Fatalf("paths = %v, want readfrom among them", got)
	}
}

// A reset of the socket ends a copy into ReadFrom with the error, and the
// end of the context ends an idle one.
func TestRelayReadFromErrors(t *testing.T) {
	t.Run("reset", func(t *testing.T) {
		client, src := tcpPair(t)
		dstConn, _ := tcpPair(t)
		var calls, inFlight atomic.Int64
		done := make(chan error, 1)
		go func() {
			_, _, err := Relay(context.Background(), src, readFromConn{dstConn, &calls, &inFlight})
			done <- err
		}()
		_ = client.(*net.TCPConn).SetLinger(0)
		_ = client.Close()
		select {
		case err := <-done:
			if !errors.Is(err, syscall.ECONNRESET) {
				t.Fatalf("Relay() = %v, want a reset", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("a reset did not end the relay")
		}
	})
	t.Run("cancel", func(t *testing.T) {
		_, src := tcpPair(t)
		dstConn, _ := tcpPair(t)
		var calls, inFlight atomic.Int64
		ctx, cancel := context.WithCancelCause(context.Background())
		cause := errors.New("stop")
		done := make(chan error, 1)
		go func() {
			_, _, err := Relay(ctx, src, readFromConn{dstConn, &calls, &inFlight})
			done <- err
		}()
		time.Sleep(20 * time.Millisecond)
		cancel(cause)
		select {
		case err := <-done:
			if !errors.Is(err, cause) {
				t.Fatalf("Relay() = %v, want the cause", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("the context did not end the relay")
		}
	})
	t.Run("copy", func(t *testing.T) {
		// Copy closes nothing: the end of ctx interrupts the wait with a
		// deadline.
		_, src := tcpPair(t)
		dstConn, _ := tcpPair(t)
		var calls, inFlight atomic.Int64
		ctx, cancel := context.WithCancelCause(context.Background())
		cause := errors.New("stop")
		done := make(chan error, 1)
		go func() {
			_, err := Copy(ctx, readFromConn{dstConn, &calls, &inFlight}, src, nil)
			done <- err
		}()
		time.Sleep(20 * time.Millisecond)
		cancel(cause)
		select {
		case err := <-done:
			if !errors.Is(err, cause) {
				t.Fatalf("Copy() = %v, want the cause", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("the context did not end the copy")
		}
	})
}
