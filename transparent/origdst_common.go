package transparent

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/djylb/netx"
)

// ErrOriginalDestinationUnsupported is returned by OriginalDestination on
// platforms without a lookup. It matches errors.ErrUnsupported.
var ErrOriginalDestinationUnsupported = fmt.Errorf("transparent: original destination lookup is not supported on this platform: %w", errors.ErrUnsupported)

// OriginalDestination returns the destination that an accepted TCP
// connection was addressed to, and whether a redirect brought it to this
// socket. A connection made to the socket directly reports its own local
// address and false: forwarding it would connect the proxy to itself.
//
// On Linux it reads SO_ORIGINAL_DST, or IP6T_SO_ORIGINAL_DST for a native
// IPv6 local address (REDIRECT/DNAT), and on FreeBSD and macOS it queries pf
// with DIOCNATLOOK, which XNU only allows for root. Without a translation the
// connection reached the address it was sent to, its local address, as
// TPROXY and IP_BINDANY sockets receive it. A destination on another port
// than the local one was redirected. One on the same port was redirected
// unless it is an address of this host: forwarding it would come back. Linux
// asks the routing table, through the device that the socket is bound to,
// such as a VRF, and counts local and IPv6 anycast routes; FreeBSD and macOS
// bind the address. So a NAT that maps another address of this host to the
// listener's port, or TPROXY delivering a connection for an address of this
// host, is reported as direct. Lookup failures, such as for a closed
// connection or without permission to read /dev/pf, are returned. On other
// platforms it returns ErrOriginalDestinationUnsupported.
//
// Wrappers such as netx.TimeoutConn are looked through with netx.InnermostConn,
// so the lookup and the local address are the accepted socket's rather than
// an address that a wrapper reports, such as the destination of a PROXY
// header, which conn.LocalAddr returns. A connection beneath which no socket
// can be reached is an error. IPv4-mapped addresses are unmapped. A nil conn
// returns net.ErrClosed.
func OriginalDestination(conn net.Conn) (dst netip.AddrPort, redirected bool, err error) {
	if conn == nil {
		return netip.AddrPort{}, false, net.ErrClosed
	}
	// A nil pointer, such as a nil *net.TCPConn, unwraps to nil. The
	// connection beneath is only looked at; conn's owner closes it.
	//noinspection GoResourceLeak
	if conn = netx.InnermostConn(conn); conn == nil {
		return netip.AddrPort{}, false, net.ErrClosed
	}
	return originalDestination(conn)
}
