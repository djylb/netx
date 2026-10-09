//go:build darwin

package transparent

import (
	"context"
	"net"
)

// listen returns an ordinary listener: pf rdr rules redirect traffic to it,
// and OriginalDestination looks up the original target with DIOCNATLOOK.
func listen(ctx context.Context, address string) (net.Listener, error) {
	var lc net.ListenConfig
	return lc.Listen(ctx, "tcp", address)
}
