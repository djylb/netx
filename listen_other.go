//go:build !linux && !freebsd && !windows

package netx

import "net"

func ListenTCP(address string, _ bool) (net.Listener, error) {
	return net.Listen("tcp", address)
}
