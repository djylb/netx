package transparent_test

import (
	"context"
	"errors"
	"log"
	"net"
	"syscall"
	"time"

	"github.com/djylb/netx"
	"github.com/djylb/netx/transparent"
)

// Accept redirected connections and forward each to its original destination.
func ExampleListen() {
	ctx := context.Background()
	ln, err := transparent.Listen(ctx, "tcp", "0.0.0.0:8080")
	if err != nil {
		log.Fatal(err)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			dst, redirected, err := transparent.OriginalDestination(c)
			// A connection made to the listener directly would connect the
			// proxy to itself, again and again.
			if err != nil || !redirected {
				_ = c.Close()
				return
			}
			var d net.Dialer
			upstream, err := d.DialContext(ctx, "tcp", dst.String())
			if err != nil {
				_ = c.Close()
				return
			}
			_, _, _ = netx.Relay(ctx, c, upstream)
		}()
	}
}

// Combine the transparent socket options with others of one's own.
func ExampleControl() {
	lc := net.ListenConfig{
		KeepAliveConfig: net.KeepAliveConfig{Enable: true, Idle: 30 * time.Second},
		Control: func(network, address string, c syscall.RawConn) error {
			if err := transparent.Control(network, address, c); err != nil {
				return err
			}
			// Set further options here, such as SO_REUSEPORT or SO_MARK.
			return nil
		},
	}
	ln, err := lc.Listen(context.Background(), "tcp", "0.0.0.0:8080")
	if err != nil {
		log.Fatal(err)
	}
	_ = ln.Close()
}

// Answer UDP datagrams redirected by a TPROXY rule from the address they were
// sent to.
func ExampleListenPacket() {
	ctx := context.Background()
	ln, err := transparent.ListenPacket(ctx, "udp", "0.0.0.0:5353")
	if err != nil {
		log.Fatal(err)
	}
	buf := make([]byte, 65535)
	for {
		n, info, err := transparent.ReadFromUDP(ln, buf)
		if errors.Is(err, transparent.ErrControlTruncated) {
			continue // this datagram's destination is unknown
		}
		if err != nil {
			log.Fatal(err)
		}
		if !info.Redirected {
			continue // sent to the listener itself
		}
		reply, err := transparent.DialUDP(ctx, info.Dst, info.Src)
		if err != nil {
			continue
		}
		_, _ = reply.Write(buf[:n])
		_ = reply.Close()
	}
}

// Forward each redirected UDP flow to its original destination.
func ExampleListenUDPFlows() {
	ctx := context.Background()
	l, err := transparent.ListenUDPFlows(ctx, "udp", "0.0.0.0:5353", transparent.WithFlowIdleTimeout(time.Minute))
	if err != nil {
		log.Fatal(err)
	}
	for {
		c, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			var d net.Dialer
			upstream, err := d.DialContext(ctx, "udp", c.LocalAddr().String())
			if err != nil {
				_ = c.Close()
				return
			}
			_, _, _ = netx.Relay(ctx, c, upstream)
		}()
	}
}
