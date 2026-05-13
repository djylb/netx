//go:build linux || freebsd

package netx

import (
	"fmt"
	"net"
	"strconv"
)

func transparentDestinationFromLocalAddr(addr net.Addr) (string, error) {
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok || tcpAddr == nil {
		return "", fmt.Errorf("local address is not tcp: %T", addr)
	}
	if tcpAddr.IP == nil || tcpAddr.IP.IsUnspecified() || tcpAddr.Port <= 0 {
		return "", fmt.Errorf("invalid local address %v", addr)
	}
	return net.JoinHostPort(tcpAddr.IP.String(), strconv.Itoa(tcpAddr.Port)), nil
}
