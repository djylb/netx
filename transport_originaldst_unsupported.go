//go:build !linux && !freebsd && !darwin

package netx

import "net"

// OriginalDestination returns the pre-redirect destination of an accepted
// TCP connection.
//
// On Linux it reads SO_ORIGINAL_DST or IP6T_SO_ORIGINAL_DST (REDIRECT/DNAT),
// and on FreeBSD it queries pf with DIOCNATLOOK. If that lookup fails, both
// fall back to conn's local address, which is the target for TPROXY or
// IP_BINDANY sockets. A direct, non-redirected connection therefore yields its
// own local address rather than an error. On macOS it queries pf with
// DIOCNATLOOK, which XNU only allows for root, and has no fallback. On other
// platforms it returns ErrOriginalDestinationUnsupported. A nil conn returns
// net.ErrClosed.
func OriginalDestination(conn net.Conn) (*net.TCPAddr, error) {
	if conn == nil {
		return nil, net.ErrClosed
	}
	return nil, ErrOriginalDestinationUnsupported
}
