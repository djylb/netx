//go:build linux

package netx

import (
	"io"
	"net"
	"testing"
	"time"
)

type stubTransparentConn struct {
	local net.Addr
}

func (c stubTransparentConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c stubTransparentConn) Write([]byte) (int, error)        { return 0, io.EOF }
func (c stubTransparentConn) Close() error                     { return nil }
func (c stubTransparentConn) LocalAddr() net.Addr              { return c.local }
func (c stubTransparentConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c stubTransparentConn) SetDeadline(time.Time) error      { return nil }
func (c stubTransparentConn) SetReadDeadline(time.Time) error  { return nil }
func (c stubTransparentConn) SetWriteDeadline(time.Time) error { return nil }

func TestTransparentDestinationFromLocalAddr(t *testing.T) {
	addr, err := transparentDestinationFromLocalAddr(&net.TCPAddr{
		IP:   net.ParseIP("203.0.113.10"),
		Port: 8443,
	})
	if err != nil {
		t.Fatalf("transparentDestinationFromLocalAddr error = %v", err)
	}
	if addr != "203.0.113.10:8443" {
		t.Fatalf("transparentDestinationFromLocalAddr = %q, want %q", addr, "203.0.113.10:8443")
	}
}

func TestGetAddressFallsBackToLocalAddrForTransparentConn(t *testing.T) {
	addr, err := GetAddress(stubTransparentConn{
		local: &net.TCPAddr{
			IP:   net.ParseIP("198.51.100.25"),
			Port: 443,
		},
	})
	if err != nil {
		t.Fatalf("GetAddress error = %v", err)
	}
	if addr != "198.51.100.25:443" {
		t.Fatalf("GetAddress = %q, want %q", addr, "198.51.100.25:443")
	}
}

func TestTransparentDestinationFromLocalAddrRejectsInvalidAddr(t *testing.T) {
	if _, err := transparentDestinationFromLocalAddr(&net.TCPAddr{}); err == nil {
		t.Fatal("expected error for empty local address")
	}
}
