package socks5_test

import (
	"bytes"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/djylb/netx"
	"github.com/djylb/netx/socks5"
)

// associationGoroutines counts the goroutines in the server's association
// code.
func associationGoroutines() int {
	buf := make([]byte, 1<<20)
	buf = buf[:runtime.Stack(buf, true)]
	n := 0
	for g := range bytes.SplitSeq(buf, []byte("\n\n")) {
		if bytes.Contains(g, []byte("socks5.(*Server).associate")) || bytes.Contains(g, []byte("socks5.(*association)")) {
			n++
		}
	}
	return n
}

// A bound association runs its control read and its two copy directions,
// and no goroutine that only waits to close the control connection.
func TestServerUDPAssociationGoroutines(t *testing.T) {
	echo := udpEcho(t)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := serve(t, &socks5.Server{UDPSocket: pc})
	ctl, relay := associate(t, addr, netx.Addr{})
	if got, _ := exchange(t, newUDPClient(t), relay, echo, "x"); got != "echo:x" {
		t.Fatalf("reply = %q", got)
	}
	// The handler of the exchange may still be on its way into its wait.
	n := associationGoroutines()
	for deadline := time.Now().Add(time.Second); n > 3 && time.Now().Before(deadline); n = associationGoroutines() {
		time.Sleep(time.Millisecond)
	}
	if n != 3 {
		t.Fatalf("association runs %d goroutines, want 3", n)
	}
	_ = ctl.Close()
}
