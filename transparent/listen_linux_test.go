package transparent

import (
	"context"
	"net"
	"syscall"
	"testing"
)

// getsockoptInt reads an integer option of the socket beneath c.
func getsockoptInt(t *testing.T, c syscall.Conn, level, name int) int {
	t.Helper()
	raw, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var v int
	var optErr error
	if err := raw.Control(func(fd uintptr) {
		v, optErr = syscall.GetsockoptInt(int(fd), level, name)
	}); err != nil {
		t.Fatal(err)
	}
	if optErr != nil {
		t.Fatalf("getsockopt(%d, %d): %v", level, name, optErr)
	}
	return v
}

// Control composes with other options in a Control function of one's own.
func TestControlWithOtherOptions(t *testing.T) {
	const tos = 0x10
	lc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
		if err := Control(network, address, c); err != nil {
			return err
		}
		return controlFD(c, func(fd int) error {
			return syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TOS, tos)
		})
	}}
	ln, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	skipWithoutPrivilege(t, err)
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	tcp := ln.(*net.TCPListener)
	if v := getsockoptInt(t, tcp, solIP, ipTransparent); v != 1 {
		t.Fatalf("IP_TRANSPARENT = %d, want 1", v)
	}
	if v := getsockoptInt(t, tcp, syscall.IPPROTO_IP, syscall.IP_TOS); v != tos {
		t.Fatalf("IP_TOS = %#x, want %#x", v, tos)
	}
}

func TestControlPacketSetsOptions(t *testing.T) {
	for _, tt := range []struct {
		network, address string
		level            int
		opts             []int
	}{
		{"udp4", "127.0.0.1:0", solIP, []int{ipTransparent, ipRecvOrigDstAddr}},
		{"udp6", "[::1]:0", solIPv6, []int{ipv6Transparent, ipv6RecvOrigDstAddr}},
	} {
		t.Run(tt.network, func(t *testing.T) {
			lc := net.ListenConfig{Control: ControlPacket}
			pc, err := lc.ListenPacket(context.Background(), tt.network, tt.address)
			skipWithoutPrivilege(t, err)
			if err != nil {
				if tt.network == "udp6" {
					t.Skipf("no IPv6: %v", err)
				}
				t.Fatalf("ListenPacket() error = %v", err)
			}
			t.Cleanup(func() { _ = pc.Close() })
			for _, opt := range tt.opts {
				if v := getsockoptInt(t, pc.(*net.UDPConn), tt.level, opt); v != 1 {
					t.Errorf("option %#x = %d, want 1", opt, v)
				}
			}
		})
	}
}
