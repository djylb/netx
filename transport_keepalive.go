//go:build linux || freebsd || darwin

package netx

import (
	"net"
	"syscall"
)

// SetTCPKeepAlive sets TCP keepalive parameters on tc.
func SetTCPKeepAlive(tc *net.TCPConn, cfg TCPKeepAliveConfig) error {
	if err := validateTCPKeepAliveConfig(tc, cfg); err != nil {
		return err
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return err
	}
	idle := durationSeconds(cfg.Idle)
	interval := durationSeconds(cfg.Interval)
	var sockErr error
	err = raw.Control(func(fd uintptr) {
		if sockErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpKeepIdle, idle); sockErr != nil {
			return
		}
		if sockErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpKeepIntvl, interval); sockErr != nil {
			return
		}
		sockErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpKeepCnt, cfg.Count)
	})
	if err != nil {
		return err
	}
	return sockErr
}
