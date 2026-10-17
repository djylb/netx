// Package transparent accepts TCP connections and UDP datagrams that a
// transparent proxy setup redirects to a local socket, and recovers the
// destination they were addressed to.
//
//	Platform        Control                                OriginalDestination
//	Linux, Android  IP_TRANSPARENT/IPV6_TRANSPARENT        SO_ORIGINAL_DST, else the local address
//	FreeBSD         IP_BINDANY/IPV6_BINDANY                pf DIOCNATLOOK, else the local address
//	macOS, iOS      nothing (pf rdr needs no option)       pf DIOCNATLOOK (root only)
//	others          ErrListenUnsupported                   ErrOriginalDestinationUnsupported
//
// Listen is a net.ListenConfig with Control; to combine the transparent
// options with others, such as SO_REUSEPORT or SO_MARK, call Control from a
// Control function of one's own.
//
// For UDP, ListenPacket, ReadFromUDP and DialUDP implement Linux TPROXY:
// datagrams carry their original destination, and replies are sent from it.
// ControlPacket sets the options of ListenPacket. FlowListener, from
// ListenUDPFlows, builds on them a connection per flow. Elsewhere they return
// errors matching errors.ErrUnsupported.
package transparent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
)

// ErrListenUnsupported is returned by Listen, Control and their UDP
// counterparts on platforms without transparent sockets. It matches
// errors.ErrUnsupported.
var ErrListenUnsupported = fmt.Errorf("transparent: listening is not supported on this platform: %w", errors.ErrUnsupported)

// Listen listens on a TCP address for transparently redirected connections.
// network must be "tcp", "tcp4" or "tcp6". It is net.ListenConfig.Listen
// with Control as the Control function.
func Listen(ctx context.Context, network, address string) (net.Listener, error) {
	if err := checkNetwork("listen", network, "tcp"); err != nil {
		return nil, err
	}
	if err := listenErr(); err != nil {
		return nil, err
	}
	lc := net.ListenConfig{Control: Control}
	return lc.Listen(ctx, network, address)
}

// checkNetwork fails unless network is base, base+"4" or base+"6".
func checkNetwork(op, network, base string) error {
	switch network {
	case base, base + "4", base + "6":
		return nil
	}
	return &net.OpError{Op: op, Net: network, Err: net.UnknownNetworkError(network)}
}

// Control prepares a socket to take transparently redirected connections, or,
// on a dialer, to bind an address that is not local. It has the signature of
// net.ListenConfig.Control and net.Dialer.Control.
//
// On Linux it sets IP_TRANSPARENT and IPV6_TRANSPARENT, and on FreeBSD
// IP_BINDANY and IPV6_BINDANY, where the socket's family has them; it fails
// when neither could be set. Both usually require elevated privileges, such
// as CAP_NET_ADMIN on Linux. On macOS and iOS it does nothing: pf rdr rules
// need no socket option, and OriginalDestination asks pf for the target.
// Elsewhere, including Windows, it returns ErrListenUnsupported.
func Control(network, address string, c syscall.RawConn) error {
	return control(network, address, c)
}

// ControlPacket prepares a UDP socket for ListenPacket: it does what Control
// does and also sets IP_RECVORIGDSTADDR and IPV6_RECVORIGDSTADDR, so that
// ReadFromUDP can report each datagram's original destination. It has the
// signature of net.ListenConfig.Control. It is available on Linux and
// Android; elsewhere it returns ErrListenUnsupported.
func ControlPacket(network, address string, c syscall.RawConn) error {
	return controlPacket(network, address, c)
}
