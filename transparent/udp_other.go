//go:build !linux

package transparent

import (
	"context"
	"net"
	"net/netip"
)

//goland:noinspection GoUnusedParameter
func listenPacket(context.Context, string) (*net.UDPConn, error) {
	return nil, ErrListenUnsupported
}

//goland:noinspection GoUnusedParameter
func readFromUDP(*net.UDPConn, []byte) (int, netip.AddrPort, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, netip.AddrPort{}, ErrOriginalDestinationUnsupported
}

//goland:noinspection GoUnusedParameter
func dialUDP(context.Context, netip.AddrPort, netip.AddrPort) (*net.UDPConn, error) {
	return nil, ErrListenUnsupported
}
