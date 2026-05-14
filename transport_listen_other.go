//go:build !linux && !freebsd && !windows

package netx

import "net"

// ListenTCP listens on a TCP address; transparent TCP is ignored on this platform.
func ListenTCP(address string, _ ...ListenOption) (net.Listener, error) {
	return net.Listen("tcp", address)
}
