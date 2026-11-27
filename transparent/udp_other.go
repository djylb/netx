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

func readFromUDP(_ *net.UDPConn, _ []byte) (int, PacketInfo, error) {
	return 0, PacketInfo{}, ErrOriginalDestinationUnsupported
}

func dialUDP(_ context.Context, _, _ netip.AddrPort) (*net.UDPConn, error) {
	return nil, ErrListenUnsupported
}

func readDatagram(_ syscall.RawConn) (*[]byte, int, error) {
	return nil, 0, ErrListenUnsupported
}

// writeFrom sends b on c to the destination. The kernel chooses the source address.
func writeFrom(c *net.UDPConn, b []byte, _, to netip.AddrPort) (int, error) {
	return c.WriteToUDPAddrPort(b, to)
}

func retryReply(_ error) bool { return false }
