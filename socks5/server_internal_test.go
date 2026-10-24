package socks5

import (
	"net"
	"testing"
	"time"

	"github.com/djylb/netx"
)

// An association whose first-datagram timer fires before it is added to the
// relay must not stay in the relay's pending map.
func TestServerUDPDoesNotKeepEndedAssociations(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{UDPSocket: pc, UDPIdleTimeout: time.Nanosecond}
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
		_ = WriteRequest(c, CmdUDPAssociate, netx.Addr{})
		_, _ = ReadReply(c)
		_, _ = c.Read(make([]byte, 1)) // until the server ends it
		_ = c.Close()
	}
	var r *udpRelay
	s.life.Locked(func(bool) { r = s.shared })
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
