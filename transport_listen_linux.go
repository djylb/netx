//go:build linux

package netx

import (
	"context"
	"errors"
	"net"
	"syscall"
)

const (
	solIP           = 0x0
	solIPv6         = 0x29
	ipTransparent   = 0x13
	ipv6Transparent = 0x4b
)

func listenTCPContext(ctx context.Context, address string, opts ...ListenOption) (net.Listener, error) {
	cfg := newListenOptions(opts)
	if !cfg.transparent {
		var lc net.ListenConfig
		return lc.Listen(ctx, "tcp", address)
	}

	lc := net.ListenConfig{
		Control: func(_, _ string, raw syscall.RawConn) error {
			var sockErr error
			if err := raw.Control(func(fd uintptr) {
				sockErr = enableTransparentSocket(int(fd))
			}); err != nil {
				return err
			}
			return sockErr
		},
	}
	return lc.Listen(ctx, "tcp", address)
}

func enableTransparentSocket(fd int) error {
	var firstErr error
	for _, opt := range []struct {
		level int
		name  int
	}{
		{level: solIP, name: ipTransparent},
		{level: solIPv6, name: ipv6Transparent},
	} {
		if err := syscall.SetsockoptInt(fd, opt.level, opt.name, 1); err != nil && !isIgnorableTransparentSockopt(err) {
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

func isIgnorableTransparentSockopt(err error) bool {
	return errors.Is(err, syscall.ENOPROTOOPT) ||
		errors.Is(err, syscall.EINVAL) ||
		errors.Is(err, syscall.EAFNOSUPPORT)
}
