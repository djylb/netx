// Package transparent accepts TCP connections that a transparent proxy setup
// redirects to a local listener, and recovers the destination they were
// addressed to.
//
//	Platform        Listen                                 OriginalDestination
//	Linux, Android  IP_TRANSPARENT/IPV6_TRANSPARENT        SO_ORIGINAL_DST, else the local address
//	FreeBSD         IP_BINDANY/IPV6_BINDANY                pf DIOCNATLOOK, else the local address
//	macOS, iOS      plain listener (pf rdr)                pf DIOCNATLOOK (root only)
//	others          ErrListenUnsupported                   ErrOriginalDestinationUnsupported
package transparent

import (
	"context"
	"errors"
	"fmt"
	"net"
)

// ErrListenUnsupported is returned by Listen on platforms without transparent
// listening. It matches errors.ErrUnsupported.
var ErrListenUnsupported = fmt.Errorf("transparent: listening is not supported on this platform: %w", errors.ErrUnsupported)

// Listen listens on a TCP address for transparently redirected connections.
//
// On Linux it sets IP_TRANSPARENT and IPV6_TRANSPARENT, and on FreeBSD
// IP_BINDANY and IPV6_BINDANY; both usually require elevated privileges, such
// as CAP_NET_ADMIN on Linux. On macOS and iOS it returns an ordinary listener:
// pf rdr rules need no socket option, and OriginalDestination asks pf for the
// target. Elsewhere, including Windows, it returns ErrListenUnsupported.
func Listen(ctx context.Context, address string) (net.Listener, error) {
	return listen(ctx, address)
}
