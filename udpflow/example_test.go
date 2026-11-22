package udpflow_test

import (
	"log"
	"net"
	"time"

	"github.com/djylb/netx/udpflow"
)

// Serve one goroutine per UDP peer, like a TCP server.
func ExamplePacketListener() {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	l := udpflow.NewPacketListener(pc, udpflow.WithPacketIdleTimeout(time.Minute))
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			defer func() { _ = c.Close() }()
			buf := make([]byte, 1500)
			for {
				n, err := c.Read(buf) // one datagram from this peer
				if err != nil {
					return
				}
				_, _ = c.Write(buf[:n]) // echo it back
			}
		}()
	}
}
