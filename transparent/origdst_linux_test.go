//go:build linux

package transparent

import (
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

type stubTransparentConn struct {
	local net.Addr
}

func (c stubTransparentConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c stubTransparentConn) Write([]byte) (int, error)        { return 0, io.EOF }
func (c stubTransparentConn) Close() error                     { return nil }
func (c stubTransparentConn) LocalAddr() net.Addr              { return c.local }
func (c stubTransparentConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c stubTransparentConn) SetDeadline(time.Time) error      { return nil }
func (c stubTransparentConn) SetReadDeadline(time.Time) error  { return nil }
func (c stubTransparentConn) SetWriteDeadline(time.Time) error { return nil }

func TestDestinationFromLocalAddr(t *testing.T) {
	addr, err := destinationFromLocalAddr(&net.TCPAddr{
		IP:   net.ParseIP("203.0.113.10"),
		Port: 8443,
	})
	if err != nil {
		t.Fatalf("destinationFromLocalAddr error = %v", err)
	}
	if addr.String() != "203.0.113.10:8443" {
		t.Fatalf("destinationFromLocalAddr = %q, want %q", addr.String(), "203.0.113.10:8443")
	}
}

func TestOriginalDestinationFallsBackToLocalAddrForTransparentConn(t *testing.T) {
	addr, err := OriginalDestination(stubTransparentConn{
		local: &net.TCPAddr{
			IP:   net.ParseIP("198.51.100.25"),
			Port: 443,
		},
	})
	if err != nil {
		t.Fatalf("OriginalDestination error = %v", err)
	}
	if addr.String() != "198.51.100.25:443" {
		t.Fatalf("OriginalDestination = %q, want %q", addr.String(), "198.51.100.25:443")
	}
}

func TestDestinationFromLocalAddrRejectsInvalidAddr(t *testing.T) {
	if _, err := destinationFromLocalAddr(&net.TCPAddr{}); err == nil {
		t.Fatal("expected error for empty local address")
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

func TestTCPAddrFromSockaddrInet4(t *testing.T) {
	sa := syscall.RawSockaddrInet4{Family: syscall.AF_INET, Addr: [4]byte{203, 0, 113, 10}}
	setSockaddrPort(&sa.Port, 8080)
	if got := tcpAddrFromSockaddrInet4(&sa).String(); got != "203.0.113.10:8080" {
		t.Fatalf("tcpAddrFromSockaddrInet4 = %q, want %q", got, "203.0.113.10:8080")
	}
}

func TestTCPAddrFromSockaddrInet6(t *testing.T) {
	sa := syscall.RawSockaddrInet6{Family: syscall.AF_INET6}
	copy(sa.Addr[:], net.ParseIP("2001:db8::25"))
	setSockaddrPort(&sa.Port, 443)
	addr := tcpAddrFromSockaddrInet6(&sa)
	if got := addr.String(); got != "[2001:db8::25]:443" {
		t.Fatalf("tcpAddrFromSockaddrInet6 = %q, want %q", got, "[2001:db8::25]:443")
	}
	sa.Addr[15] = 0x26
	if addr.IP[15] != 0x25 {
		t.Fatal("tcpAddrFromSockaddrInet6 aliases the sockaddr buffer")
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

func TestTCPAddrFromSockaddrInet6Zone(t *testing.T) {
	name, index := testInterface(t)
	sa := syscall.RawSockaddrInet6{Family: syscall.AF_INET6, Scope_id: index}
	copy(sa.Addr[:], net.ParseIP("fe80::25"))
	setSockaddrPort(&sa.Port, 443)
	if got, want := tcpAddrFromSockaddrInet6(&sa).String(), "[fe80::25%"+name+"]:443"; got != want {
		t.Fatalf("tcpAddrFromSockaddrInet6 = %q, want %q", got, want)
	}
	sa.Scope_id = 0x7ffffff0 // no such interface
	if got, want := tcpAddrFromSockaddrInet6(&sa).String(), "[fe80::25%2147483632]:443"; got != want {
		t.Fatalf("tcpAddrFromSockaddrInet6 = %q, want %q", got, want)
	}
	copy(sa.Addr[:], net.ParseIP("2001:db8::25"))
	if got, want := tcpAddrFromSockaddrInet6(&sa).String(), "[2001:db8::25]:443"; got != want {
		t.Fatalf("tcpAddrFromSockaddrInet6 = %q, want %q", got, want)
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
		lookup  func(fd int) (*net.TCPAddr, error)
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
			// local address is used. Either way the result is the listener.
			dst, err := OriginalDestination(server)
			if err != nil {
				t.Fatalf("OriginalDestination error = %v", err)
			}
			if dst.String() != ln.Addr().String() {
				t.Fatalf("OriginalDestination = %v, want %v", dst, ln.Addr())
			}

			raw, err := server.(syscall.Conn).SyscallConn()
			if err != nil {
				t.Fatalf("SyscallConn error = %v", err)
			}
			var lookupDst *net.TCPAddr
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
