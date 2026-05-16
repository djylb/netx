//go:build !linux && !freebsd && !windows

package netx

import (
	"context"
	"net"
)

func listenTCPContext(ctx context.Context, address string, opts ...ListenOption) (net.Listener, error) {
	cfg := newListenOptions(opts)
	if cfg.transparent {
		return nil, ErrTransparentListenUnsupported
	}
	var lc net.ListenConfig
	return lc.Listen(ctx, "tcp", address)
}
