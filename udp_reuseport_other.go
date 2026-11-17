//go:build !linux

package netx

import "syscall"

// reusePortSupport reports ErrReusePortUnsupported: elsewhere SO_REUSEPORT
// does not spread unicast datagrams over the sockets.
func reusePortSupport() error { return ErrReusePortUnsupported }

func setReusePort(_ syscall.RawConn) error { return ErrReusePortUnsupported }
