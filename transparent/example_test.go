package transparent_test

import (
	"context"
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
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			dst, err := transparent.OriginalDestination(c)
			if err != nil {
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
