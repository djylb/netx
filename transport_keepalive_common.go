package netx

import (
	"errors"
	"net"
	"time"
)

var errInvalidKeepAliveParams = errors.New("tcp keepalive parameters must be positive")
var errKeepAliveParamsUnsupported = errors.New("tcp keepalive parameters are not supported on this platform")

// TCPKeepAliveConfig configures TCP keepalive probes.
type TCPKeepAliveConfig struct {
	Idle     time.Duration
	Interval time.Duration
	Count    int
}

func validateTCPKeepAliveConfig(tc *net.TCPConn, cfg TCPKeepAliveConfig) error {
	switch {
	case tc == nil:
		return net.ErrClosed
	case cfg.Idle <= 0 || cfg.Interval <= 0 || cfg.Count <= 0:
		return errInvalidKeepAliveParams
	default:
		return nil
	}
}

func durationSeconds(d time.Duration) int {
	seconds := d / time.Second
	if d%time.Second != 0 {
		seconds++
	}
	maxInt := int(^uint(0) >> 1)
	if seconds > time.Duration(maxInt) {
		return maxInt
	}
	return int(seconds)
}
