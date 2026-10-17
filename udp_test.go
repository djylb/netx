package netx

import (
	"context"
	"net"
	"runtime"
	"sync/atomic"
	"syscall"
	"testing"
)

// TestListenEphemeralUDPSkipsTakenPorts holds many ports on 127.0.0.1 and
// checks that no ephemeral socket gets one of them, as a dual-stack one can
// on macOS.
func TestListenEphemeralUDPSkipsTakenPorts(t *testing.T) {
	if runtime.GOOS == "js" || runtime.GOOS == "wasip1" || runtime.GOOS == "plan9" {
		t.Skip("no UDP sockets")
	}
	// Enough that a port picked at random hits one, but few enough that
	// tests running in parallel do not use up the ephemeral ports, which
	// makes ListenEphemeralUDP fall back.
	held := map[int]bool{}
	for range 500 {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			break
		}
		t.Cleanup(func() { _ = c.Close() })
		held[c.LocalAddr().(*net.UDPAddr).Port] = true
	}
	for range 2000 {
		c, err := ListenEphemeralUDP(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		port := c.LocalAddr().(*net.UDPAddr).Port
		_ = c.Close()
		if held[port] {
			t.Fatalf("ListenEphemeralUDP() took port %d, which 127.0.0.1 holds", port)
		}
	}
}

// The ListenConfig's Control runs for the socket.
func TestListenEphemeralUDPUsesListenConfig(t *testing.T) {
	if runtime.GOOS == "js" || runtime.GOOS == "wasip1" || runtime.GOOS == "plan9" {
		t.Skip("no UDP sockets")
	}
	var controlled atomic.Int64
	lc := &net.ListenConfig{Control: func(string, string, syscall.RawConn) error {
		controlled.Add(1)
		return nil
	}}
	c, err := ListenEphemeralUDP(context.Background(), lc)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if controlled.Load() == 0 {
		t.Fatal("the ListenConfig's Control did not run")
	}
}
