package socks5

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// An association whose first-datagram timer fires before it is added to the
// relay must not stay in the relay's pending map.
func TestServerUDPDoesNotKeepEndedAssociations(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{PacketConn: pc, UDPIdleTimeout: time.Nanosecond}
	defer func() { _ = s.Close() }()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() { _ = s.Serve(ln) }()
	for range 50 {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		_ = WriteMethods(c, MethodNoAuth)
		_, _ = ReadMethod(c)
		_ = WriteRequest(c, CmdUDPAssociate, Addr{})
		_, _ = ReadReply(c)
		_, _ = c.Read(make([]byte, 1)) // until the server ends it
		_ = c.Close()
	}
	s.mu.Lock()
	r := s.shared
	s.mu.Unlock()
	if r == nil {
		t.Fatal("no shared relay")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		r.mu.Lock()
		n := len(r.pending)
		r.mu.Unlock()
		if n == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d client addresses still have pending associations", n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Failed lookups are cached briefly, and Close ends a lookup in progress.
func TestPacketConnCachesFailedLookupsAndCancelsOnClose(t *testing.T) {
	var dials atomic.Int32
	fail := &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("no DNS server")
	}}
	u := newTestPacketConn(t, fail)
	if _, err := u.resolve("unresolvable.test"); err == nil {
		t.Fatal("resolve() error = nil, want the lookup failure")
	}
	first := dials.Load()
	if _, err := u.resolve("unresolvable.test"); err == nil {
		t.Fatal("cached resolve() error = nil, want the lookup failure")
	}
	if dials.Load() != first {
		t.Fatalf("a cached failure dialed DNS again (%d dials, want %d)", dials.Load(), first)
	}

	hang := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	u = newTestPacketConn(t, hang)
	done := make(chan error, 1)
	go func() {
		_, err := u.resolve("slow.test")
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	_ = u.Close()
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("resolve() after Close error = %v, want net.ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not end the lookup")
	}
}

func newTestPacketConn(t *testing.T, r *net.Resolver) *udpPacketConn {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	u := NewPacketConn(c).(*udpPacketConn)
	u.resolver = r
	t.Cleanup(func() { _ = u.Close() })
	return u
}
