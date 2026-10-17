//go:build linux || freebsd || darwin

package transparent

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

// stubConn is a connection that is not a socket, with the addresses it is
// given, as a wrapper that netx.InnermostConn cannot look through.
type stubConn struct {
	local net.Addr
}

func (c stubConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c stubConn) Write([]byte) (int, error)        { return 0, io.EOF }
func (c stubConn) Close() error                     { return nil }
func (c stubConn) LocalAddr() net.Addr              { return c.local }
func (c stubConn) RemoteAddr() net.Addr             { return &net.TCPAddr{IP: net.IPv4(192, 0, 2, 9), Port: 50000} }
func (c stubConn) SetDeadline(time.Time) error      { return nil }
func (c stubConn) SetReadDeadline(time.Time) error  { return nil }
func (c stubConn) SetWriteDeadline(time.Time) error { return nil }

// The addresses of a connection that is not a socket, such as those of a
// PROXY header, are not taken for the socket's.
func TestOriginalDestinationRejectsNonSocket(t *testing.T) {
	c := stubConn{local: &net.TCPAddr{IP: net.ParseIP("198.51.100.25"), Port: 443}}
	if dst, redirected, err := OriginalDestination(c); err == nil {
		t.Fatalf("OriginalDestination(non-socket) = %v, %v; want an error", dst, redirected)
	}
}

func TestIsRedirected(t *testing.T) {
	local := netip.MustParseAddrPort("10.0.0.1:8080")
	hostAddrs := map[netip.Addr]bool{
		netip.MustParseAddr("10.0.0.1"):  true,
		netip.MustParseAddr("10.0.0.2"):  true,
		netip.MustParseAddr("127.0.0.1"): true,
	}
	lookupErr := errors.New("lookup failed")
	for _, tt := range []struct {
		name       string
		dst        string
		lookup     error
		redirected bool
		wantErr    bool
	}{
		{"direct", "10.0.0.1:8080", nil, false, false},
		{"TPROXY to another host", "198.51.100.1:8080", nil, true, false},
		{"NAT from another port", "198.51.100.1:443", nil, true, false},
		{"NAT from another port of this host", "10.0.0.2:443", nil, true, false},
		{"NAT from this host on the same port", "10.0.0.2:8080", nil, false, false},
		{"lookup failure", "198.51.100.1:8080", lookupErr, false, true},
	} {
		lookups := 0
		got, err := isRedirected(netip.MustParseAddrPort(tt.dst), local, func(ip netip.Addr) (bool, error) {
			lookups++
			return hostAddrs[ip], tt.lookup
		})
		if got != tt.redirected || (err != nil) != tt.wantErr {
			t.Errorf("%s: isRedirected() = %v, %v; want %v, error %v", tt.name, got, err, tt.redirected, tt.wantErr)
		}
		// Another port needs no lookup.
		if netip.MustParseAddrPort(tt.dst).Port() != local.Port() && lookups != 0 {
			t.Errorf("%s: %d lookups, want none", tt.name, lookups)
		}
	}
}
