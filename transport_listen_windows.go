//go:build windows

package netx

import (
	"context"
	"net"
)

func listenTCPContext(ctx context.Context, address string, cfg listenOptions) (net.Listener, error) {
	if cfg.transparent {
		return nil, ErrTransparentListenUnsupported
	}
	var lc net.ListenConfig
	return lc.Listen(ctx, "tcp", address)
}
