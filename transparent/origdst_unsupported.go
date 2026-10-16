//go:build !linux && !freebsd && !darwin

package transparent

import (
	"net"

	"github.com/djylb/netx"
)

// OriginalDestination returns the pre-redirect destination of an accepted
// TCP connection.
//
// On Linux it reads SO_ORIGINAL_DST or IP6T_SO_ORIGINAL_DST (REDIRECT/DNAT),
// and on FreeBSD it queries pf with DIOCNATLOOK. When that lookup finds no
// redirect, as for a connection that conntrack or pf has no translation for
// or a host without them, both fall back to conn's local address, which is
// the target for TPROXY or IP_BINDANY sockets. A direct, non-redirected
// connection therefore yields its own local address rather than an error.
// Other lookup failures, such as for a closed connection or, on FreeBSD,
// without permission to read /dev/pf, are returned. On macOS it queries pf with
// DIOCNATLOOK, which XNU only allows for root, and has no fallback. On other
// platforms it returns ErrOriginalDestinationUnsupported. Wrappers such as
// netx.TimeoutConn are looked through with netx.RawConnOf, so the lookup, and
// the fallback to the local address, use the accepted socket rather than an
// address that a wrapper reports, such as the destination of a PROXY header,
// which conn.LocalAddr returns. A nil conn returns net.ErrClosed.
func OriginalDestination(conn net.Conn) (*net.TCPAddr, error) {
	if netx.RawConnOf(conn) == nil {
		return nil, net.ErrClosed
	}
	return nil, ErrOriginalDestinationUnsupported
}
