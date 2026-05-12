//go:build freebsd

package netx

import (
	"context"
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
				sockErr = enableBindAnySocket(int(fd))
			}); err != nil {
				return err
			}
			return sockErr
		},
	}
	return lc.Listen(context.Background(), "tcp", address)
}

func enableBindAnySocket(fd int) error {
	var firstErr error
	for _, opt := range []struct {
		level int
		name  int
	}{
		{level: unix.IPPROTO_IP, name: unix.IP_BINDANY},
		{level: unix.IPPROTO_IPV6, name: unix.IPV6_BINDANY},
	} {
		if err := unix.SetsockoptInt(fd, opt.level, opt.name, 1); err != nil && !isIgnorableBindAnySockopt(err) {
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

func isIgnorableBindAnySockopt(err error) bool {
	return err == unix.ENOPROTOOPT || err == unix.EINVAL || err == unix.EAFNOSUPPORT
}
