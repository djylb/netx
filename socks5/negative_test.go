package socks5_test

import (
	"net"
	"testing"

	"github.com/djylb/netx/socks5"
)

// A negative UDPQueue fails Validate and ServeConn; negative timeouts mean
// no timeout and are valid.
func TestNegativeSettings(t *testing.T) {
	s := &socks5.Server{UDPQueue: -1}
	if s.Validate() == nil {
		t.Error("negative UDPQueue valid")
	}
	a, b := net.Pipe()
	if s.ServeConn(t.Context(), a) == nil {
		t.Error("ServeConn served")
	}
	_ = b.Close()
	if err := (&socks5.Server{HandshakeTimeout: -1, DialTimeout: -1, UDPIdleTimeout: -1}).Validate(); err != nil {
		t.Error(err)
	}
}
