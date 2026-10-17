//go:build !linux && !freebsd && !darwin

package transparent

import "syscall"

// listenErr reports that Listen is unsupported here, before a socket is
// made.
func listenErr() error { return ErrListenUnsupported }

//goland:noinspection GoUnusedParameter
func control(string, string, syscall.RawConn) error {
	return ErrListenUnsupported
}

//goland:noinspection GoUnusedParameter
func controlPacket(string, string, syscall.RawConn) error {
	return ErrListenUnsupported
}
