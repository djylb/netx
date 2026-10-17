//go:build freebsd || darwin

package transparent

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"syscall"
)

// isLocalAddr reports whether ip is an address of this host: whether a socket
// without IP_BINDANY can bind it. The socket that ip arrived at is not needed.
func isLocalAddr(_ syscall.RawConn, ip netip.Addr) (bool, error) {
	ip = ip.Unmap()
	var family int
	var sa syscall.Sockaddr
	if ip.Is4() {
		family, sa = syscall.AF_INET, &syscall.SockaddrInet4{Addr: ip.As4()}
	} else {
		sa6 := &syscall.SockaddrInet6{Addr: ip.As16()}
		if zone := ip.Zone(); zone != "" {
			if ifi, err := net.InterfaceByName(zone); err == nil {
				sa6.ZoneId = uint32(ifi.Index)
			} else if n, err := strconv.ParseUint(zone, 10, 32); err == nil {
				sa6.ZoneId = uint32(n)
			} else {
				return false, fmt.Errorf("unknown zone %q", zone)
			}
		}
		family, sa = syscall.AF_INET6, sa6
	}
	// macOS has no SOCK_CLOEXEC; ForkLock keeps the descriptor from a
	// concurrent exec until it is marked close-on-exec.
	syscall.ForkLock.RLock()
	fd, err := syscall.Socket(family, syscall.SOCK_DGRAM, 0)
	if err == nil {
		syscall.CloseOnExec(fd)
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return false, err
	}
	defer func() { _ = syscall.Close(fd) }()
	switch err := syscall.Bind(fd, sa); {
	case err == nil:
		return true, nil
	case errors.Is(err, syscall.EADDRNOTAVAIL):
		return false, nil
	default:
		return false, err
	}
}
