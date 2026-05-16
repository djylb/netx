//go:build linux || freebsd

package netx

import (
	"fmt"
	"net"
)

func transparentDestinationFromLocalAddr(addr net.Addr) (*net.TCPAddr, error) {
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok || tcpAddr == nil {
		return nil, fmt.Errorf("local address is not tcp: %T", addr)
	}
	if tcpAddr.IP == nil || tcpAddr.IP.IsUnspecified() || tcpAddr.Port <= 0 {
		return nil, fmt.Errorf("invalid local address %v", addr)
	}
	return &net.TCPAddr{
		IP:   append(net.IP(nil), tcpAddr.IP...),
		Port: tcpAddr.Port,
		Zone: tcpAddr.Zone,
	}, nil
}
