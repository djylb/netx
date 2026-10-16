package netx

import (
	"net"
	"runtime"
	"testing"
)

// TestListenEphemeralUDPSkipsTakenPorts holds many ports on 127.0.0.1 and
// checks that no ephemeral socket gets one of them, as a dual-stack one can
// on macOS.
func TestListenEphemeralUDPSkipsTakenPorts(t *testing.T) {
	if runtime.GOOS == "js" || runtime.GOOS == "wasip1" || runtime.GOOS == "plan9" {
		t.Skip("no UDP sockets")
	}
	held := map[int]bool{}
	for range 2000 {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			break
		}
		t.Cleanup(func() { _ = c.Close() })
		held[c.LocalAddr().(*net.UDPAddr).Port] = true
	}
	for range 2000 {
		c, err := ListenEphemeralUDP()
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
