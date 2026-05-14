//go:build windows

package netx

import (
	"errors"
	"net"
)

// ListenTCP listens on address; transparent TCP is not supported on Windows.
func ListenTCP(address string, transparent bool) (net.Listener, error) {
	if transparent {
		return nil, errors.New("transparent tcp listener is not supported on Windows")
	}
	return net.Listen("tcp", address)
}
