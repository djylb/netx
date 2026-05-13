//go:build linux

package netx

import (
	"context"
	"errors"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func ListenTCP(address string, transparent bool) (net.Listener, error) {
	if !transparent {
		return net.Listen("tcp", address)
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
	return lc.Listen(context.Background(), "tcp", address)
}

func enableTransparentSocket(fd int) error {
	var firstErr error
	for _, opt := range []struct {
		level int
		name  int
	}{
		{level: unix.SOL_IP, name: unix.IP_TRANSPARENT},
		{level: unix.SOL_IPV6, name: unix.IPV6_TRANSPARENT},
	} {
		if err := unix.SetsockoptInt(fd, opt.level, opt.name, 1); err != nil && !isIgnorableTransparentSockopt(err) {
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

func isIgnorableTransparentSockopt(err error) bool {
	return errors.Is(err, unix.ENOPROTOOPT) ||
		errors.Is(err, unix.EINVAL) ||
		errors.Is(err, unix.EAFNOSUPPORT)
}
