//go:build linux || freebsd || darwin

package netx

import (
	"errors"
	"net"
	"syscall"
)

var errInvalidKeepAliveParams = errors.New("tcp keepalive parameters must be positive")

// SetTcpKeepAliveParams sets TCP keepalive parameters on tc.
func SetTcpKeepAliveParams(tc *net.TCPConn, idle, intvl, probes int) error {
	switch {
	case tc == nil:
		return net.ErrClosed
	case idle <= 0 || intvl <= 0 || probes <= 0:
		return errInvalidKeepAliveParams
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return err
	}
	var sockErr error
	err = raw.Control(func(fd uintptr) {
		if sockErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpKeepIdle, idle); sockErr != nil {
			return
		}
		if sockErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpKeepIntvl, intvl); sockErr != nil {
			return
		}
		sockErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpKeepCnt, probes)
	})
	if err != nil {
		return err
	}
	return sockErr
}
