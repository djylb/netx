//go:build !linux

package netx

import "syscall"

// Elsewhere SO_REUSEPORT does not spread unicast datagrams over the sockets.
const reusePortBalances = false

func setReusePort(syscall.RawConn) error { return ErrReusePortUnsupported }
