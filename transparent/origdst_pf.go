//go:build darwin || freebsd

package transparent

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"github.com/djylb/netx/internal/netutil"
)

// natlookAddr returns the redirect destination that a pf DIOCNATLOOK lookup
// left in addr, of address family af, with port.
func natlookAddr(af uint8, addr *[16]byte, port uint16) (netip.AddrPort, error) {
	var ip netip.Addr
	switch af {
	case syscall.AF_INET:
		ip = netip.AddrFrom4([4]byte(addr[:net.IPv4len]))
	case syscall.AF_INET6:
		ip = netip.AddrFrom16(*addr).Unmap()
	default:
		return netip.AddrPort{}, fmt.Errorf("unsupported address family: %d", af)
	}
	return netip.AddrPortFrom(ip, port), nil
}

// natlookKey holds the addresses of a TCP connection by which pf is asked
// for its translation: its remote address as the source, its local address
// as the destination.
type natlookKey struct {
	af           uint8
	saddr, daddr [16]byte
	sport, dport uint16
}

func natlookKeyOf(conn net.Conn, local netip.AddrPort) (natlookKey, error) {
	ra, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok || ra == nil {
		return natlookKey{}, fmt.Errorf("remote address is not tcp: %T", conn.RemoteAddr())
	}
	remote := netutil.UnmapAddrPort(ra.AddrPort())
	if remote.Addr().Is4() != local.Addr().Is4() {
		return natlookKey{}, fmt.Errorf("remote address %v and local address %v differ in family", remote, local)
	}
	key := natlookKey{sport: remote.Port(), dport: local.Port()}
	if remote.Addr().Is4() {
		key.af = syscall.AF_INET
		s, d := remote.Addr().As4(), local.Addr().As4()
		copy(key.saddr[:], s[:])
		copy(key.daddr[:], d[:])
	} else {
		key.af = syscall.AF_INET6
		key.saddr, key.daddr = remote.Addr().As16(), local.Addr().As16()
	}
	return key, nil
}
