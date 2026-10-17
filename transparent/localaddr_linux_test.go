package transparent

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"syscall"
	"testing"
)

func TestIsLocalAddr(t *testing.T) {
	for _, tt := range []struct {
		addr  string
		local bool
	}{
		{"127.0.0.1", true},
		{"127.0.0.9", true}, // in the local route of 127.0.0.0/8
		{"::ffff:127.0.0.1", true},
		{"192.0.2.1", false},
		{"198.51.100.25", false},
		{"255.255.255.255", true}, // broadcast and multicast reach this host
		{"224.0.0.1", true},
		{"239.1.2.3", true},
	} {
		got, err := isLocalAddr(nil, netip.MustParseAddr(tt.addr))
		if err != nil || got != tt.local {
			t.Errorf("isLocalAddr(nil, %s) = %v, %v; want %v", tt.addr, got, err, tt.local)
		}
	}

	if b, ok := directedBroadcast(); ok {
		if got, err := isLocalAddr(nil, b); err != nil || !got {
			t.Errorf("isLocalAddr(%v) = %v, %v; want true for a directed broadcast", b, got, err)
		}
	}
	if got, err := isLocalAddr(nil, netip.MustParseAddr("ff02::1")); err != nil || !got {
		t.Errorf("isLocalAddr(ff02::1) = %v, %v; want true", got, err)
	}

	// IPv6 may be disabled; then nothing is local and nothing is an error.
	if got, err := isLocalAddr(nil, netip.MustParseAddr("2001:db8::1")); err != nil || got {
		t.Errorf("isLocalAddr(nil, 2001:db8::1) = %v, %v; want false", got, err)
	}
	if ln, err := net.Listen("tcp6", "[::1]:0"); err == nil {
		_ = ln.Close()
		if got, err := isLocalAddr(nil, netip.IPv6Loopback()); err != nil || !got {
			t.Errorf("isLocalAddr(nil, ::1) = %v, %v; want true", got, err)
		}
	}

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, _ := netip.AddrFromSlice(n.IP)
		if ip = ip.Unmap(); !ip.Is4() {
			continue // link-local IPv6 addresses need a zone
		}
		if got, err := isLocalAddr(nil, ip); err != nil || !got {
			t.Errorf("isLocalAddr(nil, %v) = %v, %v; want true for an interface address", ip, got, err)
		}
	}
}

func TestRouteLookupError(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.ENETUNREACH, syscall.EHOSTUNREACH, syscall.EACCES} {
		if err := routeLookupError(errno); err != nil {
			t.Errorf("routeLookupError(%v) = %v, want nil", errno, err)
		}
	}
	// EINVAL, of a blackhole route or a malformed request, is not hidden.
	for _, errno := range []syscall.Errno{syscall.EINVAL, syscall.ENOMEM} {
		if err := routeLookupError(errno); !errors.Is(err, errno) {
			t.Errorf("routeLookupError(%v) = %v, want %v", errno, err, errno)
		}
	}
}

// TestIsLocalAddrInVRF gives an address to a device in a VRF: it is local
// only to a socket bound to the VRF. It changes the host's network
// configuration, so it runs only as root with NETX_TEST_IPTABLES=1.
func TestIsLocalAddrInVRF(t *testing.T) {
	if os.Getenv("NETX_TEST_IPTABLES") != "1" || os.Geteuid() != 0 {
		t.Skip("needs root and NETX_TEST_IPTABLES=1")
	}
	const vrf, dev, addr = "netxvrf", "netxvrf0", "203.0.113.77"
	run := func(args ...string) error {
		out, err := exec.Command("ip", args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("ip %v: %w: %s", args, err, out)
		}
		return nil
	}
	if err := run("link", "add", vrf, "type", "vrf", "table", "4242"); err != nil {
		t.Skipf("no VRF support: %v", err)
	}
	t.Cleanup(func() { _ = run("link", "del", vrf) })
	t.Cleanup(func() { _ = run("link", "del", dev) })
	for _, args := range [][]string{
		{"link", "set", vrf, "up"},
		{"link", "add", dev, "type", "dummy"},
		{"link", "set", dev, "master", vrf},
		{"link", "set", dev, "up"},
		{"addr", "add", addr + "/32", "dev", dev},
	} {
		if err := run(args...); err != nil {
			t.Fatal(err)
		}
	}
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	raw, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr(addr)
	if got, err := isLocalAddr(raw, ip); err != nil || got {
		t.Fatalf("isLocalAddr(unbound, %v) = %v, %v; want false", ip, got, err)
	}
	var bindErr error
	if err := raw.Control(func(fd uintptr) {
		bindErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, vrf)
	}); err != nil || bindErr != nil {
		t.Fatalf("SO_BINDTODEVICE: %v, %v", err, bindErr)
	}
	if got, err := isLocalAddr(raw, ip); err != nil || !got {
		t.Fatalf("isLocalAddr(bound to %s, %v) = %v, %v; want true", vrf, ip, got, err)
	}
}
