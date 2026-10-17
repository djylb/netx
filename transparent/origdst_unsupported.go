//go:build !linux && !freebsd && !darwin

package transparent

import (
	"net"
	"net/netip"
)

//goland:noinspection GoUnusedParameter
func originalDestination(net.Conn) (netip.AddrPort, bool, error) {
	return netip.AddrPort{}, false, ErrOriginalDestinationUnsupported
}
