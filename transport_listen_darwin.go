//go:build darwin

package netx

import (
	"context"
	"net"
)

// listenTCPContext accepts WithTransparent as a no-op: pf rdr rules redirect
// traffic to an ordinary listener, and OriginalDestination looks up the
// original target with DIOCNATLOOK.
func listenTCPContext(ctx context.Context, address string, _ listenOptions) (net.Listener, error) {
	var lc net.ListenConfig
	return lc.Listen(ctx, "tcp", address)
}
