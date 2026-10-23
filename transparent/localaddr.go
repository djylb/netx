//go:build linux || freebsd || darwin

package transparent

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/djylb/netx/internal/netutil"
)

// destinationFromLocalAddr returns the local address of an accepted TCP
// connection, unmapped.
func destinationFromLocalAddr(addr net.Addr) (netip.AddrPort, error) {
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok || tcpAddr == nil {
		return netip.AddrPort{}, fmt.Errorf("local address is not tcp: %T", addr)
	}
	ap := netutil.UnmapAddrPort(tcpAddr.AddrPort())
	if !ap.Addr().IsValid() || ap.Addr().IsUnspecified() || ap.Port() == 0 {
		return netip.AddrPort{}, fmt.Errorf("invalid local address %v", addr)
	}
	return ap, nil
}
