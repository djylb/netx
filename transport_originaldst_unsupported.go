//go:build !linux && !freebsd && !darwin

package netx

import "net"

// OriginalDestination returns the original destination address for a transparent TCP connection.
func OriginalDestination(conn net.Conn) (*net.TCPAddr, error) {
	if conn == nil {
		return nil, net.ErrClosed
	}
	return nil, ErrOriginalDestinationUnsupported
}
