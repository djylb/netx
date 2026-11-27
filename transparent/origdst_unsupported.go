//go:build !linux && !freebsd && !darwin

package transparent

import (
	"net"
	"net/netip"
)

func originalDestination(_ net.Conn) (netip.AddrPort, bool, error) {
	return netip.AddrPort{}, false, ErrOriginalDestinationUnsupported
}
