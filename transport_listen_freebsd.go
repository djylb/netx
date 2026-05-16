//go:build freebsd

package netx

import (
	"context"
	"errors"
	"net"
	"syscall"
)

const (
	ipBindAny   = 0x18
	ipv6BindAny = 0x40
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
				sockErr = enableBindAnySocket(int(fd))
			}); err != nil {
				return err
			}
			return sockErr
		},
	}
	return lc.Listen(ctx, "tcp", address)
}

func enableBindAnySocket(fd int) error {
	var firstErr error
	for _, opt := range []struct {
		level int
		name  int
	}{
		{level: syscall.IPPROTO_IP, name: ipBindAny},
		{level: syscall.IPPROTO_IPV6, name: ipv6BindAny},
	} {
		if err := syscall.SetsockoptInt(fd, opt.level, opt.name, 1); err != nil && !isIgnorableBindAnySockopt(err) {
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

func isIgnorableBindAnySockopt(err error) bool {
	return errors.Is(err, syscall.ENOPROTOOPT) ||
		errors.Is(err, syscall.EINVAL) ||
		errors.Is(err, syscall.EAFNOSUPPORT)
}
