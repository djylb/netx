//go:build !linux && !freebsd && !darwin && !windows

package netx

import (
	"errors"
	"net"
)

var errInvalidKeepAliveParams = errors.New("tcp keepalive parameters must be positive")
var errKeepAliveParamsUnsupported = errors.New("tcp keepalive parameters are not supported on this platform")

// SetTcpKeepAliveParams returns an unsupported error on platforms without parameter support.
func SetTcpKeepAliveParams(tc *net.TCPConn, idle, intvl, probes int) error {
	switch {
	case tc == nil:
		return net.ErrClosed
	case idle <= 0 || intvl <= 0 || probes <= 0:
		return errInvalidKeepAliveParams
	default:
		return errKeepAliveParamsUnsupported
	}
}
