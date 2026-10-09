//go:build linux

package transparent

import (
	"context"
	"net"
)

const (
	solIP           = 0x0
	solIPv6         = 0x29
	ipTransparent   = 0x13
	ipv6Transparent = 0x4b
)

func listen(ctx context.Context, address string) (net.Listener, error) {
	lc := net.ListenConfig{Control: controlSocket(setTransparent)}
	return lc.Listen(ctx, "tcp", address)
}
