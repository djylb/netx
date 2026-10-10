//go:build darwin || freebsd

package transparent

import (
	"fmt"
	"net"
	"syscall"
)

// natlookAddr returns the redirect destination that a pf DIOCNATLOOK lookup
// left in addr, of address family af, with port.
func natlookAddr(af uint8, addr *[16]byte, port int) (*net.TCPAddr, error) {
	var ip net.IP
	switch af {
	case syscall.AF_INET:
		ip = make(net.IP, net.IPv4len)
		copy(ip, addr[:net.IPv4len])
	case syscall.AF_INET6:
		ip = make(net.IP, net.IPv6len)
		copy(ip, addr[:])
	default:
		return nil, fmt.Errorf("unsupported address family: %d", af)
	}
	return &net.TCPAddr{IP: ip, Port: port}, nil
}
