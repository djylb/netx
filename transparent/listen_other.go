//go:build !linux && !freebsd && !darwin

package transparent

import "syscall"

// listenErr reports that Listen is unsupported here, before a socket is
// made.
func listenErr() error { return ErrListenUnsupported }

func control(_, _ string, _ syscall.RawConn) error {
	return ErrListenUnsupported
}

func controlPacket(_, _ string, _ syscall.RawConn) error {
	return ErrListenUnsupported
}
