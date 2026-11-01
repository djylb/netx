package socks5_test

import (
	"net"
	"testing"

	"github.com/djylb/netx/socks5"
)

// Negative settings fail Validate and ServeConn.
func TestNegativeSettings(t *testing.T) {
	for _, s := range []*socks5.Server{{UDPQueue: -1}, {HandshakeTimeout: -1}, {DialTimeout: -1}, {UDPIdleTimeout: -1}} {
		if s.Validate() == nil {
			t.Errorf("%+v valid", s)
		}
		a, b := net.Pipe()
		if s.ServeConn(t.Context(), a) == nil {
			t.Error("ServeConn served")
		}
		_ = b.Close()
	}
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	if err := (&socks5.DatagramRelay{IdleTimeout: -1}).Relay(t.Context(), a, nil); err == nil {
		t.Error("Relay with a negative IdleTimeout")
	}
}
