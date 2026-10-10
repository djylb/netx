package transparent_test

import (
	"context"
	"errors"
	"log"
	"net"

	"github.com/djylb/netx"
	"github.com/djylb/netx/transparent"
)

// Accept redirected connections and forward each to its original destination.
func ExampleListen() {
	ln, err := transparent.Listen(context.Background(), "0.0.0.0:8080")
	if err != nil {
		log.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	// local reports whether ip is an address of this host.
	local := func(ip net.IP) bool {
		addrs, _ := net.InterfaceAddrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
				return true
			}
		}
		return ip.IsLoopback() || ip.IsUnspecified()
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			dst, err := transparent.OriginalDestination(c)
			// A connection made to the listener directly, not redirected,
			// reports the listener's own address: forwarding it would
			// connect the proxy to itself, again and again.
			if err != nil || dst.Port == port && local(dst.IP) {
				_ = c.Close()
				return
			}
			upstream, err := net.DialTCP("tcp", nil, dst)
			if err != nil {
				_ = c.Close()
				return
			}
			_, _, _ = netx.Relay(c, upstream)
		}()
	}
}

// Answer UDP datagrams redirected by a TPROXY rule from the address they were
// sent to.
func ExampleListenPacket() {
	ln, err := transparent.ListenPacket(context.Background(), "0.0.0.0:5353")
	if err != nil {
		log.Fatal(err)
	}
	buf := make([]byte, 65535)
	for {
		n, src, dst, err := transparent.ReadFromUDP(ln, buf)
		if errors.Is(err, transparent.ErrControlTruncated) {
			continue // this datagram's destination is unknown
		}
		if err != nil {
			log.Fatal(err)
		}
		reply, err := transparent.DialUDP(context.Background(), dst, src)
		if err != nil {
			continue
		}
		_, _ = reply.Write(buf[:n])
		_ = reply.Close()
	}
}
