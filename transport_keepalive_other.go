//go:build !linux && !freebsd && !darwin && !windows

package netx

import (
	"net"
)

// SetTCPKeepAlive returns an unsupported error on platforms without parameter support.
func SetTCPKeepAlive(tc *net.TCPConn, cfg TCPKeepAliveConfig) error {
	if err := validateTCPKeepAliveConfig(tc, cfg); err != nil {
		return err
	}
	return ErrTCPKeepAliveUnsupported
}
