package transparent

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

// soOriginalDst is SO_ORIGINAL_DST for SOL_IP and IP6T_SO_ORIGINAL_DST for SOL_IPV6.
const soOriginalDst = 80

// OriginalDestination returns the pre-redirect destination of an accepted
// TCP connection.
//
// On Linux it reads SO_ORIGINAL_DST or IP6T_SO_ORIGINAL_DST (REDIRECT/DNAT),
// and on FreeBSD it queries pf with DIOCNATLOOK. If that lookup fails, both
// fall back to conn's local address, which is the target for TPROXY or
// IP_BINDANY sockets. A direct, non-redirected connection therefore yields its
// own local address rather than an error. On macOS it queries pf with
// DIOCNATLOOK, which XNU only allows for root, and has no fallback. On other
// platforms it returns ErrOriginalDestinationUnsupported. A nil conn returns
// net.ErrClosed.
func OriginalDestination(conn net.Conn) (*net.TCPAddr, error) {
	if conn == nil {
		return nil, net.ErrClosed
	}
	dst, err := redirectedDestinationFromConn(conn)
	if err == nil {
		return dst, nil
	}
	localDst, localErr := destinationFromLocalAddr(conn.LocalAddr())
	if localErr == nil {
		return localDst, nil
	}
	return nil, fmt.Errorf("failed to get transparent address: redirect=%v local=%v", err, localErr)
}

func redirectedDestinationFromConn(conn net.Conn) (*net.TCPAddr, error) {
	sysconn, ok := conn.(syscall.Conn)
	if !ok {
		return nil, fmt.Errorf("connection does not support SyscallConn")
	}
	raw, err := sysconn.SyscallConn()
	if err != nil {
		return nil, err
	}

	var dst *net.TCPAddr
	var opErr error

	err = raw.Control(func(fd uintptr) {
		dst, opErr = originalDestinationFromFD(int(fd))
	})

	if err != nil {
		return nil, err
	}
	if opErr != nil {
		return nil, opErr
	}
	return dst, nil
}

// originalDestinationFromFD queries the pre-NAT destination recorded by
// conntrack, trying SO_ORIGINAL_DST first and IP6T_SO_ORIGINAL_DST second.
//
// syscall has no raw getsockopt, and SYS_GETSOCKOPT does not exist on
// linux/386 where socket calls go through socketcall(2). The lookups therefore
// use typed getsockopt helpers that work on every GOARCH and whose buffers
// start with room for the sockaddr the kernel writes back; the kernel only
// rejects buffers that are too small.
func originalDestinationFromFD(fd int) (*net.TCPAddr, error) {
	dst, err4 := originalDestinationIPv4(fd)
	if err4 == nil {
		return dst, nil
	}
	dst, err6 := originalDestinationIPv6(fd)
	if err6 == nil {
		return dst, nil
	}
	return nil, fmt.Errorf("not a redirected connection (errno4=%w, errno6=%w)", err4, err6)
}

// originalDestinationIPv4 reads SO_ORIGINAL_DST into an IPv6Mreq (20 bytes),
// whose first 16 bytes receive the sockaddr_in.
func originalDestinationIPv4(fd int) (*net.TCPAddr, error) {
	mreq, err := syscall.GetsockoptIPv6Mreq(fd, syscall.SOL_IP, soOriginalDst)
	if err != nil {
		return nil, err
	}
	return tcpAddrFromSockaddrInet4((*syscall.RawSockaddrInet4)(unsafe.Pointer(&mreq.Multiaddr))), nil
}

// originalDestinationIPv6 reads IP6T_SO_ORIGINAL_DST into an IPv6MTUInfo
// (32 bytes), which starts with the sockaddr_in6 (28 bytes).
func originalDestinationIPv6(fd int) (*net.TCPAddr, error) {
	info, err := syscall.GetsockoptIPv6MTUInfo(fd, syscall.SOL_IPV6, soOriginalDst)
	if err != nil {
		return nil, err
	}
	return tcpAddrFromSockaddrInet6(&info.Addr), nil
}

func tcpAddrFromSockaddrInet4(sa *syscall.RawSockaddrInet4) *net.TCPAddr {
	return &net.TCPAddr{
		IP:   net.IPv4(sa.Addr[0], sa.Addr[1], sa.Addr[2], sa.Addr[3]),
		Port: sockaddrPort(&sa.Port),
	}
}

func tcpAddrFromSockaddrInet6(sa *syscall.RawSockaddrInet6) *net.TCPAddr {
	return &net.TCPAddr{
		IP:   append(net.IP(nil), sa.Addr[:]...),
		Port: sockaddrPort(&sa.Port),
	}
}

// sockaddrPort decodes sin_port/sin6_port, which hold the port in network byte
// order regardless of host endianness.
func sockaddrPort(p *uint16) int {
	b := (*[2]byte)(unsafe.Pointer(p))
	return int(b[0])<<8 | int(b[1])
}
