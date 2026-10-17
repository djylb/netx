package netx

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func openFDs(t *testing.T) int {
	t.Helper()
	es, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("no /proc/self/fd: %v", err)
	}
	return len(es)
}

// Idle relays that splice hold no pipe, only their sockets.
func TestRelaySpliceIdleHoldsNoPipe(t *testing.T) {
	const n = 50
	type relay struct{ a, b, c, d net.Conn }
	var wg sync.WaitGroup
	runtime.GC()
	runtime.GC()
	before := openFDs(t)
	var relays []relay
	for range n {
		a, b := tcpPair(t)
		c, d := tcpPair(t)
		relays = append(relays, relay{a, b, c, d})
		wg.Go(func() { _, _, _ = Relay(context.Background(), b, c) })
		// Move some data, then leave the relay idle.
		_, _ = a.Write([]byte("x"))
		_ = d.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(d, make([]byte, 1)); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(200 * time.Millisecond) // let every direction block
	// Pipes that idle directions put back stay in the pool until collected.
	runtime.GC()
	runtime.GC()
	time.Sleep(50 * time.Millisecond) // for the cleanups that close them
	held := openFDs(t) - before - 4*n
	for _, r := range relays {
		_ = r.a.Close()
		_ = r.d.Close()
	}
	wg.Wait()
	if held > n/2 {
		t.Fatalf("%d idle relays hold %d descriptors besides their sockets, want no pipes", n, held)
	}
}

// A splicing relay that cannot get a pipe, as when descriptors run out,
// copies that piece through its buffer instead of failing.
func TestRelaySpliceWithoutPipes(t *testing.T) {
	a, b := tcpPair(t)
	c, d := tcpPair(t)
	go func() { _, _, _ = Relay(context.Background(), b, c) }()
	exchange := func(msg string) {
		t.Helper()
		if _, err := a.Write([]byte(msg)); err != nil {
			t.Fatal(err)
		}
		_ = d.SetReadDeadline(time.Now().Add(5 * time.Second))
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(d, got); err != nil || string(got) != msg {
			t.Fatalf("relayed %q, %v; want %q", got, err, msg)
		}
	}
	exchange("first")
	// Drop the pooled pipes, which their cleanups close once collected,
	// then allow no new descriptor.
	for deadline := time.Now().Add(5 * time.Second); pipesOpen(t) > 0; {
		if time.Now().After(deadline) {
			t.Skip("the pooled pipes stay open")
		}
		runtime.GC()
		time.Sleep(10 * time.Millisecond)
	}
	var limit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil {
		t.Skip(err)
	}
	// A descriptor number below the limit is free again once closed, so
	// the limit goes down to the lowest free one.
	tight := limit
	tight.Cur = uint64(lowestFreeFD(t))
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &tight); err != nil {
		t.Skip(err)
	}
	defer func() { _ = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &limit) }()
	exchange("second")
	exchange("third")
}

// Moving a piece allocates nothing.
func TestRelaySpliceAllocatesNothingPerPiece(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector allocates")
	}
	a, b := tcpPair(t)
	c, d := tcpPair(t)
	go func() { _, _, _ = Relay(context.Background(), b, c) }()
	msg, buf := make([]byte, 64), make([]byte, 64)
	pingPong := func() {
		_, _ = a.Write(msg)
		_, _ = io.ReadFull(d, buf)
		_, _ = d.Write(msg)
		_, _ = io.ReadFull(a, buf)
	}
	for range 100 {
		pingPong()
	}
	const rounds = 1000
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for range rounds {
		pingPong()
	}
	runtime.ReadMemStats(&after)
	if per := float64(after.Mallocs-before.Mallocs) / rounds; per >= 1 {
		t.Fatalf("a round trip allocates %.1f times, want none", per)
	}
}

// lowestFreeFD returns the lowest descriptor number not in use.
func lowestFreeFD(t *testing.T) int {
	t.Helper()
	es, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("no /proc/self/fd: %v", err)
	}
	used := map[int]bool{}
	for _, e := range es {
		if n, err := strconv.Atoi(e.Name()); err == nil {
			used[n] = true
		}
	}
	// ReadDir's own descriptor, listed, is closed again.
	for fd := 0; ; fd++ {
		if !used[fd] {
			return fd
		}
	}
}

// pipesOpen counts the open pipes besides those of standard input, output
// and error, which a test runner may connect to pipes.
func pipesOpen(t *testing.T) int {
	t.Helper()
	es, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("no /proc/self/fd: %v", err)
	}
	std := map[string]bool{}
	for _, fd := range []string{"0", "1", "2"} {
		l, _ := os.Readlink("/proc/self/fd/" + fd)
		std[l] = true
	}
	n := 0
	for _, e := range es {
		if l, _ := os.Readlink("/proc/self/fd/" + e.Name()); strings.HasPrefix(l, "pipe:") && !std[l] {
			n++
		}
	}
	return n
}

// Splicing relays hold no pipe while their Waits block after a full piece.
func TestRelaySpliceBlockedWaitHoldsNoPipe(t *testing.T) {
	const n = 20
	release := make(chan struct{})
	var blocked atomic.Int64
	var wg sync.WaitGroup
	var peers []net.Conn
	for range n {
		a, b := tcpPair(t)
		c, d := tcpPair(t)
		peers = append(peers, a, d)
		calls := 0
		paced := RelayFlow{Wait: func(ctx context.Context, _ int64) (int64, error) {
			if calls++; calls > 1 {
				blocked.Add(1)
				select {
				case <-release:
				case <-ctx.Done():
				}
				return 0, errors.New("stopped")
			}
			return 1000, nil
		}}
		wg.Go(func() { _, _, _ = Relay(context.Background(), b, c, WithRelayFlows(paced, RelayFlow{})) })
		_, _ = a.Write(make([]byte, 64<<10))
	}
	waitUntil(t, func() bool { return blocked.Load() == n })
	// Pipes put back stay pooled until collected; held ones stay open.
	for deadline := time.Now().Add(3 * time.Second); pipesOpen(t) > 0 && time.Now().Before(deadline); {
		runtime.GC()
		time.Sleep(10 * time.Millisecond)
	}
	held := pipesOpen(t)
	close(release)
	for _, p := range peers {
		_ = p.Close()
	}
	wg.Wait()
	if held > 0 {
		t.Fatalf("%d relays blocked in Wait hold %d pipe descriptors, want none", n, held)
	}
}
