//go:build !linux

package transparent

import (
	"context"
	"net"
	"net/netip"
	"syscall"
)

// packetErr reports that ListenPacket is unsupported here, before a socket
// is made.
func packetErr() error { return ErrListenUnsupported }

//goland:noinspection GoUnusedParameter
func readFromUDP(*net.UDPConn, []byte) (int, PacketInfo, error) {
	return 0, PacketInfo{}, ErrOriginalDestinationUnsupported
}

//goland:noinspection GoUnusedParameter
func dialUDP(context.Context, netip.AddrPort, netip.AddrPort) (*net.UDPConn, error) {
	return nil, ErrListenUnsupported
}

//goland:noinspection GoUnusedParameter
func readDatagram(syscall.RawConn) (*[]byte, int, error) {
	return nil, 0, ErrListenUnsupported
}

// writeFrom sends b to to from c; the source address is the kernel's choice.
//
//goland:noinspection GoUnusedParameter
func writeFrom(c *net.UDPConn, b []byte, _, to netip.AddrPort) (int, error) {
	return c.WriteToUDPAddrPort(b, to)
}
