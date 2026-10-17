//go:build linux

package transparent

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/djylb/netx"
)

func TestDestinationFromLocalAddr(t *testing.T) {
	for _, tt := range []struct {
		addr net.Addr
		want string
	}{
		{&net.TCPAddr{IP: net.ParseIP("203.0.113.10"), Port: 8443}, "203.0.113.10:8443"},
		{&net.TCPAddr{IP: net.ParseIP("::ffff:203.0.113.10"), Port: 8443}, "203.0.113.10:8443"},
		{&net.TCPAddr{IP: net.ParseIP("2001:db8::25"), Port: 9443}, "[2001:db8::25]:9443"},
		{&net.TCPAddr{IP: net.ParseIP("fe80::25"), Port: 9443, Zone: "eth0"}, "[fe80::25%eth0]:9443"},
	} {
		addr, err := destinationFromLocalAddr(tt.addr)
		if err != nil || addr.String() != tt.want {
			t.Errorf("destinationFromLocalAddr(%v) = %v, %v; want %s", tt.addr, addr, err, tt.want)
		}
	}
}

func TestDestinationFromLocalAddrRejectsInvalidAddr(t *testing.T) {
	for _, addr := range []net.Addr{
		&net.TCPAddr{},
		&net.TCPAddr{IP: net.IPv4zero, Port: 80},
		&net.TCPAddr{IP: net.IPv4(192, 0, 2, 1)},
		&net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 80},
		(*net.TCPAddr)(nil),
		nil,
	} {
		if dst, err := destinationFromLocalAddr(addr); err == nil {
			t.Errorf("destinationFromLocalAddr(%v) = %v, want an error", addr, dst)
		}
	}
}

// setSockaddrPort stores port the way the kernel does: in network byte order.
func setSockaddrPort(p *uint16, port int) {
	b := (*[2]byte)(unsafe.Pointer(p))
	b[0], b[1] = byte(port>>8), byte(port)
}

func TestSockaddrPortIsNetworkByteOrder(t *testing.T) {
	var port uint16
	*(*[2]byte)(unsafe.Pointer(&port)) = [2]byte{0x1f, 0x90}
	if got := sockaddrPort(&port); got != 8080 {
		t.Fatalf("sockaddrPort({0x1f, 0x90}) = %d, want 8080", got)
	}
	*(*[2]byte)(unsafe.Pointer(&port)) = [2]byte{0x01, 0xbb}
	if got := sockaddrPort(&port); got != 443 {
		t.Fatalf("sockaddrPort({0x01, 0xbb}) = %d, want 443", got)
	}
}

func TestAddrPortFromSockaddrInet4(t *testing.T) {
	sa := syscall.RawSockaddrInet4{Family: syscall.AF_INET, Addr: [4]byte{203, 0, 113, 10}}
	setSockaddrPort(&sa.Port, 8080)
	if got := addrPortFromSockaddrInet4(&sa).String(); got != "203.0.113.10:8080" {
		t.Fatalf("addrPortFromSockaddrInet4 = %q, want %q", got, "203.0.113.10:8080")
	}
}

func TestAddrPortFromSockaddrInet6(t *testing.T) {
	sa := syscall.RawSockaddrInet6{Family: syscall.AF_INET6}
	copy(sa.Addr[:], net.ParseIP("2001:db8::25"))
	setSockaddrPort(&sa.Port, 443)
	if got := addrPortFromSockaddrInet6(&sa).String(); got != "[2001:db8::25]:443" {
		t.Fatalf("addrPortFromSockaddrInet6 = %q, want %q", got, "[2001:db8::25]:443")
	}
	copy(sa.Addr[:], net.ParseIP("::ffff:192.0.2.1"))
	if got := addrPortFromSockaddrInet6(&sa).String(); got != "192.0.2.1:443" {
		t.Fatalf("addrPortFromSockaddrInet6(mapped) = %q, want %q", got, "192.0.2.1:443")
	}
}

// testInterface returns the name and index of an interface of this host.
func testInterface(t *testing.T) (string, uint32) {
	t.Helper()
	ifs, err := net.Interfaces()
	if err != nil || len(ifs) == 0 {
		t.Skipf("no network interfaces: %v", err)
	}
	return ifs[0].Name, uint32(ifs[0].Index)
}

func TestAddrPortFromSockaddrInet6Zone(t *testing.T) {
	name, index := testInterface(t)
	sa := syscall.RawSockaddrInet6{Family: syscall.AF_INET6, Scope_id: index}
	copy(sa.Addr[:], net.ParseIP("fe80::25"))
	setSockaddrPort(&sa.Port, 443)
	if got, want := addrPortFromSockaddrInet6(&sa).String(), "[fe80::25%"+name+"]:443"; got != want {
		t.Fatalf("addrPortFromSockaddrInet6 = %q, want %q", got, want)
	}
	sa.Scope_id = 0x7ffffff0 // no such interface
	if got, want := addrPortFromSockaddrInet6(&sa).String(), "[fe80::25%2147483632]:443"; got != want {
		t.Fatalf("addrPortFromSockaddrInet6 = %q, want %q", got, want)
	}
	copy(sa.Addr[:], net.ParseIP("2001:db8::25"))
	if got, want := addrPortFromSockaddrInet6(&sa).String(), "[2001:db8::25]:443"; got != want {
		t.Fatalf("addrPortFromSockaddrInet6 = %q, want %q", got, want)
	}
}

// SO_ORIGINAL_DST is read through typed getsockopt helpers whose buffers must
// start with room for the sockaddr the kernel writes back.
func TestOriginalDestinationGetsockoptBuffers(t *testing.T) {
	var mreq syscall.IPv6Mreq
	if off := unsafe.Offsetof(mreq.Multiaddr); off != 0 {
		t.Fatalf("IPv6Mreq.Multiaddr offset = %d, want 0", off)
	}
	if size := unsafe.Sizeof(mreq.Multiaddr); size != syscall.SizeofSockaddrInet4 {
		t.Fatalf("IPv6Mreq.Multiaddr size = %d, want sizeof(sockaddr_in) = %d", size, syscall.SizeofSockaddrInet4)
	}
	if size := unsafe.Sizeof(mreq); size != syscall.SizeofIPv6Mreq {
		t.Fatalf("sizeof(IPv6Mreq) = %d, want %d", size, syscall.SizeofIPv6Mreq)
	}

	var info syscall.IPv6MTUInfo
	if off := unsafe.Offsetof(info.Addr); off != 0 {
		t.Fatalf("IPv6MTUInfo.Addr offset = %d, want 0", off)
	}
	if size := unsafe.Sizeof(info.Addr); size != syscall.SizeofSockaddrInet6 {
		t.Fatalf("IPv6MTUInfo.Addr size = %d, want sizeof(sockaddr_in6) = %d", size, syscall.SizeofSockaddrInet6)
	}
	if size := unsafe.Sizeof(info); size != syscall.SizeofIPv6MTUInfo {
		t.Fatalf("sizeof(IPv6MTUInfo) = %d, want %d", size, syscall.SizeofIPv6MTUInfo)
	}
}

func TestOriginalDestinationOfDirectConn(t *testing.T) {
	for _, tt := range []struct {
		network string
		address string
		lookup  func(fd int) (netip.AddrPort, error)
	}{
		{network: "tcp4", address: "127.0.0.1:0", lookup: originalDestinationIPv4},
		{network: "tcp6", address: "[::1]:0", lookup: originalDestinationIPv6},
	} {
		t.Run(tt.network, func(t *testing.T) {
			ln, err := net.Listen(tt.network, tt.address)
			if err != nil {
				t.Skipf("listen %s %s: %v", tt.network, tt.address, err)
			}
			t.Cleanup(func() { _ = ln.Close() })
			_, server := dialAccepted(t, ln)

			// A connection that conntrack tracks without NAT reports its own
			// destination; without a conntrack entry the lookup fails and the
			// local address is used. Either way the result is the listener,
			// an address of this host, so not redirected.
			dst, redirected, err := OriginalDestination(server)
			if err != nil {
				t.Fatalf("OriginalDestination error = %v", err)
			}
			if dst.String() != ln.Addr().String() || redirected {
				t.Fatalf("OriginalDestination = %v, %v; want %v, false", dst, redirected, ln.Addr())
			}

			raw, err := server.(syscall.Conn).SyscallConn()
			if err != nil {
				t.Fatalf("SyscallConn error = %v", err)
			}
			var lookupDst netip.AddrPort
			var lookupErr error
			if err := raw.Control(func(fd uintptr) {
				lookupDst, lookupErr = tt.lookup(int(fd))
			}); err != nil {
				t.Fatalf("Control error = %v", err)
			}
			switch {
			case lookupErr == nil:
				if lookupDst.String() != ln.Addr().String() {
					t.Fatalf("original destination lookup = %v, want %v", lookupDst, ln.Addr())
				}
			case errors.Is(lookupErr, syscall.EINVAL), errors.Is(lookupErr, syscall.EFAULT):
				// The kernel rejects buffers smaller than the sockaddr it returns.
				t.Fatalf("original destination lookup rejected the getsockopt buffer: %v", lookupErr)
			}
		})
	}
}

// An IPv4 connection to a dual-stack socket reports an IPv4-mapped local
// address and is looked up with SO_ORIGINAL_DST.
func TestOriginalDestinationOfDualStackConn(t *testing.T) {
	ln, err := net.Listen("tcp", "[::]:0")
	if err != nil {
		t.Skipf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	port := ln.Addr().(*net.TCPAddr).Port
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	client, err := net.Dial("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Skipf("dial: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	server := <-accepted
	if server == nil {
		t.Fatal("Accept failed")
	}
	t.Cleanup(func() { _ = server.Close() })
	dst, redirected, err := OriginalDestination(server)
	if want := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port)); err != nil || dst != want || redirected {
		t.Fatalf("OriginalDestination = %v, %v, %v; want %v, false", dst, redirected, err, want)
	}
}

func TestOriginalDestinationUnwrapsConn(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	_, server := dialAccepted(t, ln)

	// The wrapper is not a syscall.Conn and reports another local address;
	// the lookup must still use the socket beneath it.
	fake := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1}
	wrapped := netx.NewTimeoutConn(netx.NewAddrOverrideConn(server, fake, nil), time.Minute)
	dst, redirected, err := OriginalDestination(wrapped)
	if err != nil {
		t.Fatalf("OriginalDestination error = %v", err)
	}
	if dst.String() != ln.Addr().String() || redirected {
		t.Fatalf("OriginalDestination = %v, %v; want %v, false", dst, redirected, ln.Addr())
	}
}

// A closed connection is an error, not the local address it still reports.
func TestOriginalDestinationOfClosedConn(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	_, server := dialAccepted(t, ln)
	_ = server.Close()
	if dst, _, err := OriginalDestination(server); err == nil {
		t.Fatalf("OriginalDestination(closed) = %v, want an error", dst)
	}
}

// TestOriginalDestinationOfRedirectedConn redirects a documentation address
// to a listener with iptables and reads it back. It changes the host's
// firewall, so it runs only as root with NETX_TEST_IPTABLES=1, as in CI.
func TestOriginalDestinationOfRedirectedConn(t *testing.T) {
	if os.Getenv("NETX_TEST_IPTABLES") != "1" || os.Geteuid() != 0 {
		t.Skip("needs root and NETX_TEST_IPTABLES=1")
	}
	for _, tt := range []struct {
		tool, network, listen, target string
	}{
		{"iptables", "tcp4", "127.0.0.1:0", "192.0.2.1:18080"},
		{"ip6tables", "tcp6", "[::1]:0", "[2001:db8::1]:18080"},
	} {
		t.Run(tt.network, func(t *testing.T) {
			ln, err := net.Listen(tt.network, tt.listen)
			if err != nil {
				t.Skipf("listen: %v", err)
			}
			t.Cleanup(func() { _ = ln.Close() })
			host, port, _ := net.SplitHostPort(tt.target)
			_, lnPort, _ := net.SplitHostPort(ln.Addr().String())
			rule := []string{"OUTPUT", "-t", "nat", "-p", "tcp", "-d", host, "--dport", port, "-j", "REDIRECT", "--to-ports", lnPort}
			if out, err := exec.Command(tt.tool, append([]string{"-A"}, rule...)...).CombinedOutput(); err != nil {
				t.Fatalf("%s: %v: %s", tt.tool, err, out)
			}
			t.Cleanup(func() { _ = exec.Command(tt.tool, append([]string{"-D"}, rule...)...).Run() })
			accepted := make(chan net.Conn, 1)
			go func() {
				c, _ := ln.Accept()
				accepted <- c
			}()
			client, err := net.DialTimeout(tt.network, tt.target, 5*time.Second)
			if err != nil {
				if tt.network == "tcp6" {
					t.Skipf("dial %s: %v", tt.target, err) // no IPv6 route
				}
				t.Fatalf("dial %s: %v", tt.target, err)
			}
			t.Cleanup(func() { _ = client.Close() })
			server := <-accepted
			if server == nil {
				t.Fatal("Accept failed")
			}
			t.Cleanup(func() { _ = server.Close() })
			dst, redirected, err := OriginalDestination(server)
			if err != nil {
				t.Fatalf("OriginalDestination error = %v", err)
			}
			if dst != netip.MustParseAddrPort(tt.target) || !redirected {
				t.Fatalf("OriginalDestination = %v, %v; want %v, true", dst, redirected, tt.target)
			}
		})
	}
}

// TestOriginalDestinationOfNATToOwnPort maps another address of this host to
// a listener on the same port, as a port mapping does: forwarding to the
// original destination would reach the listener again, so it is direct. Like
// TestOriginalDestinationOfRedirectedConn it changes the firewall.
func TestOriginalDestinationOfNATToOwnPort(t *testing.T) {
	if os.Getenv("NETX_TEST_IPTABLES") != "1" || os.Geteuid() != 0 {
		t.Skip("needs root and NETX_TEST_IPTABLES=1")
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	rule := []string{"OUTPUT", "-t", "nat", "-p", "tcp", "-d", "127.0.0.2", "--dport", port, "-j", "DNAT", "--to-destination", ln.Addr().String()}
	if out, err := exec.Command("iptables", append([]string{"-A"}, rule...)...).CombinedOutput(); err != nil {
		t.Fatalf("iptables: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("iptables", append([]string{"-D"}, rule...)...).Run() })
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	target := net.JoinHostPort("127.0.0.2", port)
	client, err := net.DialTimeout("tcp4", target, 5*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", target, err)
	}
	t.Cleanup(func() { _ = client.Close() })
	server := <-accepted
	if server == nil {
		t.Fatal("Accept failed")
	}
	t.Cleanup(func() { _ = server.Close() })
	dst, redirected, err := OriginalDestination(server)
	if err != nil || dst != netip.MustParseAddrPort(target) || redirected {
		t.Fatalf("OriginalDestination = %v, %v, %v; want %v, false", dst, redirected, err, target)
	}
}
