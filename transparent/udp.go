package transparent

import (
	"context"
	"net"
	"net/netip"
)

// ListenPacket listens on a UDP address for datagrams that a TPROXY rule
// redirects to it, and asks the kernel to report each datagram's original
// destination, which ReadFromUDP returns. It needs CAP_NET_ADMIN. It is
// available on Linux and Android; elsewhere it returns ErrListenUnsupported.
func ListenPacket(ctx context.Context, address string) (*net.UDPConn, error) {
	return listenPacket(ctx, address)
}

// ReadFromUDP reads one datagram from c, a socket from ListenPacket, into b
// and returns its source and the destination it was originally sent to. A
// datagram sent to the socket's own address reports that address.
func ReadFromUDP(c *net.UDPConn, b []byte) (n int, src, dst netip.AddrPort, err error) {
	return readFromUDP(c, b)
}

// DialUDP returns a UDP socket bound to local, the original destination of a
// redirected datagram, and connected to remote, the datagram's source, so
// that replies reach the client from the address it sent to. Several such
// sockets may share one local address. It needs CAP_NET_ADMIN and is
// available where ListenPacket is.
func DialUDP(ctx context.Context, local, remote netip.AddrPort) (*net.UDPConn, error) {
	return dialUDP(ctx, local, remote)
}
