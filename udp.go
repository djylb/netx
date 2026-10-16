package netx

import (
	"net"
	"runtime"
)

// ListenEphemeralUDP opens a UDP socket on a free port of every local
// address, for IPv4 and IPv6 where the system has both, as
// net.ListenUDP("udp", nil) does. On macOS and iOS, that call can take a
// port that another socket holds on one IPv4 address, such as 127.0.0.1,
// which then receives the datagrams sent to that address and port; this
// function takes a port free for IPv4 instead.
func ListenEphemeralUDP() (*net.UDPConn, error) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "ios" {
		return net.ListenUDP("udp", nil)
	}
	for range 16 {
		// An IPv4 port that the system hands out is free on every IPv4
		// address, and an explicit bind fails on one that is taken.
		v4, err := net.ListenUDP("udp4", nil)
		if err != nil {
			break
		}
		port := v4.LocalAddr().(*net.UDPAddr).Port
		_ = v4.Close()
		if c, err := net.ListenUDP("udp", &net.UDPAddr{Port: port}); err == nil {
			return c, nil
		}
	}
	return net.ListenUDP("udp", nil)
}
