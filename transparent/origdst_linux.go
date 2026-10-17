package transparent

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// soOriginalDst is SO_ORIGINAL_DST for SOL_IP and IP6T_SO_ORIGINAL_DST for SOL_IPV6.
const soOriginalDst = 80

// lookupRedirect returns the destination that conntrack translated the
// socket raw from, or an error wrapping errNotRedirected when it has none. It
// asks SO_ORIGINAL_DST for an IPv4 local address, including one an IPv6
// socket reports IPv4-mapped, and IP6T_SO_ORIGINAL_DST for an IPv6 one.
//
// syscall has no raw getsockopt, and SYS_GETSOCKOPT does not exist on
// linux/386 where socket calls go through socketcall(2). The lookups therefore
// use typed getsockopt helpers that work on every GOARCH and whose buffers
// start with room for the sockaddr the kernel writes back; the kernel only
// rejects buffers that are too small.
func lookupRedirect(_ net.Conn, raw syscall.RawConn, local netip.AddrPort) (netip.AddrPort, error) {
	lookup := originalDestinationIPv6
	if local.Addr().Is4() {
		lookup = originalDestinationIPv4
	}
	var dst netip.AddrPort
	var opErr error
	if err := raw.Control(func(fd uintptr) {
		dst, opErr = lookup(int(fd))
	}); err != nil {
		return netip.AddrPort{}, err
	}
	if opErr != nil && noTranslation(opErr) {
		return netip.AddrPort{}, fmt.Errorf("%w: %w", errNotRedirected, opErr)
	}
	return dst, opErr
}

// noTranslation reports whether a lookup error means that conntrack has no
// translation for the socket: ENOENT, or the option unknown, as without
// conntrack.
func noTranslation(err error) bool {
	return errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ENOPROTOOPT) || errors.Is(err, syscall.EOPNOTSUPP)
}

// originalDestinationIPv4 reads SO_ORIGINAL_DST into an IPv6Mreq (20 bytes),
// whose first 16 bytes receive the sockaddr_in.
func originalDestinationIPv4(fd int) (netip.AddrPort, error) {
	mreq, err := syscall.GetsockoptIPv6Mreq(fd, syscall.SOL_IP, soOriginalDst)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return addrPortFromSockaddrInet4((*syscall.RawSockaddrInet4)(unsafe.Pointer(&mreq.Multiaddr))), nil
}

// originalDestinationIPv6 reads IP6T_SO_ORIGINAL_DST into an IPv6MTUInfo
// (32 bytes), which starts with the sockaddr_in6 (28 bytes).
func originalDestinationIPv6(fd int) (netip.AddrPort, error) {
	info, err := syscall.GetsockoptIPv6MTUInfo(fd, syscall.SOL_IPV6, soOriginalDst)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return addrPortFromSockaddrInet6(&info.Addr), nil
}

func addrPortFromSockaddrInet4(sa *syscall.RawSockaddrInet4) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom4(sa.Addr), sockaddrPort(&sa.Port))
}

func addrPortFromSockaddrInet6(sa *syscall.RawSockaddrInet6) netip.AddrPort {
	ip := netip.AddrFrom16(sa.Addr)
	ip = ip.WithZone(scopeZone(ip, sa.Scope_id)).Unmap()
	return netip.AddrPortFrom(ip, sockaddrPort(&sa.Port))
}

// scopeZone returns the zone of a link-local IPv6 address with scope ID
// scope: the name of the interface with that index, or the index itself when
// no interface has it. It returns "" for other addresses.
func scopeZone(ip netip.Addr, scope uint32) string {
	if scope == 0 || !ip.Is6() || ip.Is4In6() || !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() {
		return ""
	}
	zones.Lock()
	if now := time.Now(); zones.names == nil || now.After(zones.expires) {
		zones.names, zones.expires = make(map[uint32]string), now.Add(time.Minute)
	}
	name, ok := zones.names[scope]
	zones.Unlock()
	if ok {
		return name
	}
	// Looked up without the lock, as it lists every interface: other
	// readers keep going meanwhile, and concurrent misses look up alike.
	name = strconv.FormatUint(uint64(scope), 10)
	if ifi, err := net.InterfaceByIndex(int(scope)); err == nil {
		name = ifi.Name
	}
	zones.Lock()
	if zones.names != nil {
		zones.names[scope] = name
	}
	zones.Unlock()
	return name
}

// zones caches interface names by index for a minute, since a lookup lists
// every interface and UDP needs one per datagram.
var zones struct {
	sync.Mutex
	names   map[uint32]string
	expires time.Time
}

// sockaddrPort decodes sin_port/sin6_port, which hold the port in network byte
// order regardless of host endianness.
func sockaddrPort(p *uint16) uint16 {
	b := (*[2]byte)(unsafe.Pointer(p))
	return uint16(b[0])<<8 | uint16(b[1])
}
