package netx

import (
	"context"
	"net"
	"runtime"
	"strconv"
)

// ListenEphemeralUDP opens a UDP socket on a free port of every local
// address, with lc, nil meaning a zero net.ListenConfig, so that its Control
// can set socket options, for IPv4 and IPv6 where the system has both, as
// net.ListenUDP("udp", nil) does. On macOS and iOS, that call can take a
// port that another socket holds on one IPv4 address, such as 127.0.0.1,
// which then receives the datagrams sent to that address and port; this
// function takes a port free for IPv4 instead, and falls back to that call
// when it finds none, as when the IPv4 ports run out.
func ListenEphemeralUDP(ctx context.Context, lc *net.ListenConfig) (*net.UDPConn, error) {
	if lc == nil {
		lc = &net.ListenConfig{}
	}
	listen := func(network, address string) (*net.UDPConn, error) {
		pc, err := lc.ListenPacket(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return pc.(*net.UDPConn), nil
	}
	if runtime.GOOS != "darwin" && runtime.GOOS != "ios" {
		return listen("udp", ":0")
	}
	for range 16 {
		// An IPv4 port that the system hands out is free on every IPv4
		// address, and an explicit bind fails on one that is taken.
		v4, err := listen("udp4", ":0")
		if err != nil {
			break
		}
		port := v4.LocalAddr().(*net.UDPAddr).Port
		_ = v4.Close()
		if c, err := listen("udp", net.JoinHostPort("", strconv.Itoa(port))); err == nil {
			return c, nil
		}
	}
	return listen("udp", ":0")
}
