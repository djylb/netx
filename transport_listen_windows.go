//go:build windows

package netx

import (
	"errors"
	"net"
)

// ListenTCP listens on a TCP address; transparent TCP is not supported on Windows.
func ListenTCP(address string, opts ...ListenOption) (net.Listener, error) {
	cfg := newListenOptions(opts)
	if cfg.transparent {
		return nil, errors.New("transparent tcp listener is not supported on Windows")
	}
	return net.Listen("tcp", address)
}
