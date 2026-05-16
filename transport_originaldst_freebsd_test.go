//go:build freebsd

package netx

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

type stubFreeBSDTransparentConn struct {
	local net.Addr
}

func (c stubFreeBSDTransparentConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c stubFreeBSDTransparentConn) Write([]byte) (int, error)        { return 0, io.EOF }
func (c stubFreeBSDTransparentConn) Close() error                     { return nil }
func (c stubFreeBSDTransparentConn) LocalAddr() net.Addr              { return c.local }
func (c stubFreeBSDTransparentConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c stubFreeBSDTransparentConn) SetDeadline(time.Time) error      { return nil }
func (c stubFreeBSDTransparentConn) SetReadDeadline(time.Time) error  { return nil }
func (c stubFreeBSDTransparentConn) SetWriteDeadline(time.Time) error { return nil }

func TestTransparentDestinationFromLocalAddrIPv4(t *testing.T) {
	addr, err := transparentDestinationFromLocalAddr(&net.TCPAddr{
		IP:   net.ParseIP("203.0.113.10"),
		Port: 8443,
	})
	if err != nil {
		t.Fatalf("transparentDestinationFromLocalAddr error = %v", err)
	}
	if addr.String() != "203.0.113.10:8443" {
		t.Fatalf("transparentDestinationFromLocalAddr = %q, want %q", addr.String(), "203.0.113.10:8443")
	}
}

func TestTransparentDestinationFromLocalAddrIPv6(t *testing.T) {
	addr, err := transparentDestinationFromLocalAddr(&net.TCPAddr{
		IP:   net.ParseIP("2001:db8::25"),
		Port: 9443,
	})
	if err != nil {
		t.Fatalf("transparentDestinationFromLocalAddr error = %v", err)
	}
	if addr.String() != "[2001:db8::25]:9443" {
		t.Fatalf("transparentDestinationFromLocalAddr = %q, want %q", addr.String(), "[2001:db8::25]:9443")
	}
}

func TestOriginalDestinationFallsBackToLocalAddrForTransparentConn(t *testing.T) {
	addr, err := OriginalDestination(stubFreeBSDTransparentConn{
		local: &net.TCPAddr{
			IP:   net.ParseIP("198.51.100.25"),
			Port: 443,
		},
	})
	if err != nil {
		t.Fatalf("OriginalDestination error = %v", err)
	}
	if addr.String() != "198.51.100.25:443" {
		t.Fatalf("OriginalDestination = %q, want %q", addr.String(), "198.51.100.25:443")
	}
}

func TestOriginalDestinationRejectsNilConn(t *testing.T) {
	if _, err := OriginalDestination(nil); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("OriginalDestination(nil) error = %v, want %v", err, net.ErrClosed)
	}
}
