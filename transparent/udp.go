package transparent

import (
	"context"
	"errors"
	"net"
	"net/netip"
)

// ErrControlTruncated is returned by ReadFromUDP, with the datagram, when the
// datagram's control messages were cut short before its original
// destination. It concerns that datagram only.
var ErrControlTruncated = errors.New("transparent: control messages truncated before the original destination")

// ListenPacket listens on a UDP address for datagrams that a TPROXY rule
// redirects to it, and asks the kernel to report each datagram's original
// destination, which ReadFromUDP returns. network must be "udp", "udp4" or
// "udp6". It is net.ListenConfig.ListenPacket with ControlPacket as the
// Control function, and needs CAP_NET_ADMIN. It is available on Linux and
// Android; elsewhere it returns ErrListenUnsupported.
func ListenPacket(ctx context.Context, network, address string) (*net.UDPConn, error) {
	if err := checkNetwork("listen", network, "udp"); err != nil {
		return nil, err
	}
	if err := packetErr(); err != nil {
		return nil, err
	}
	lc := net.ListenConfig{Control: ControlPacket}
	pc, err := lc.ListenPacket(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}

// PacketInfo describes a datagram that ReadFromUDP read.
type PacketInfo struct {
	// Src is the datagram's source.
	Src netip.AddrPort
	// Dst is the destination the datagram was originally sent to.
	Dst netip.AddrPort
	// Redirected reports whether a redirect brought the datagram to the
	// socket. A datagram sent to the socket directly reports false:
	// forwarding it would send it to the socket again.
	Redirected bool
}

// ReadFromUDP reads one datagram from c, a socket from ListenPacket, into b
// and returns its length and what is known of it.
//
// A datagram for a port other than c's, or, when c is bound to one address,
// for another address, was redirected. One for c's port on a wildcard socket
// was redirected unless its destination is an address of this host, which is
// looked up as for OriginalDestination; addresses found local are remembered
// for a minute, so a datagram to an address removed meanwhile may be reported
// as direct. Listening on a port that redirected traffic does not use, as
// DialUDP needs anyway, avoids the lookup.
//
// A datagram without the original destination, as on a socket not from
// ListenPacket, reports c's own address as Dst. If the datagram's control
// messages were cut short before the original destination, it returns the
// datagram and its source with ErrControlTruncated.
func ReadFromUDP(c *net.UDPConn, b []byte) (n int, info PacketInfo, err error) {
	return readFromUDP(c, b)
}

// DialUDP returns a UDP socket bound to local, the original destination of a
// redirected datagram, and connected to remote, the datagram's source, so
// that replies reach the client from the address it sent to. Several such
// sockets may share one local address. It needs CAP_NET_ADMIN and is
// available where ListenPacket is.
//
// The listening socket does not share its address, since that would let other
// sockets bind its port, so DialUDP fails with EADDRINUSE for an original
// destination the listener holds: with a listener on a wildcard address, any
// destination on the listener's port. Listen on a port that redirected
// traffic does not use.
func DialUDP(ctx context.Context, local, remote netip.AddrPort) (*net.UDPConn, error) {
	return dialUDP(ctx, local, remote)
}
