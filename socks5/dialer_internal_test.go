package socks5

import (
	"context"
	"net"
	"net/netip"
	"testing"
)

// remoteConn is a connection with only a remote address.
type remoteConn struct {
	net.Conn
	remote net.Addr
}

func (c remoteConn) RemoteAddr() net.Addr { return c.remote }

// The relay address of a UDP ASSOCIATE reply: an unspecified address, and a
// loopback, private or link-local one from a proxy reached at another address
// that is not loopback, as behind a NAT or a port mapping, stand for the
// address the proxy was reached at.
func TestDialerRelayAddr(t *testing.T) {
	public := &net.TCPAddr{IP: net.ParseIP("203.0.113.5"), Port: 1080}
	private := &net.TCPAddr{IP: net.ParseIP("192.168.1.5"), Port: 1080}
	loopback := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1080}
	for _, tt := range []struct {
		bound  string
		remote net.Addr
		want   string
	}{
		{"0.0.0.0:7000", public, "203.0.113.5:7000"},
		{"[::]:7000", public, "203.0.113.5:7000"},
		{"172.17.0.2:7000", public, "203.0.113.5:7000"},
		{"127.0.0.1:7000", public, "203.0.113.5:7000"},
		{"[fe80::1]:7000", public, "203.0.113.5:7000"},
		{"198.51.100.9:7000", public, "198.51.100.9:7000"},
		// A LAN or container address that reaches the proxy beats the
		// address the proxy sees itself at.
		{"127.0.0.1:7000", private, "192.168.1.5:7000"},
		{"172.17.0.2:7000", private, "192.168.1.5:7000"},
		{"10.0.0.2:7000", private, "192.168.1.5:7000"},
		{"198.51.100.9:7000", private, "198.51.100.9:7000"},
		// A proxy reached over loopback knows its addresses best.
		{"172.17.0.2:7000", loopback, "172.17.0.2:7000"},
		{"127.0.0.2:7000", loopback, "127.0.0.2:7000"},
		{"203.0.113.5:7000", public, "203.0.113.5:7000"},
		{"172.17.0.2:7000", nil, "172.17.0.2:7000"},
		{"0.0.0.0:7000", nil, "192.0.2.80:7000"}, // the proxy's own address
	} {
		bound, err := ParseAddr(tt.bound)
		if err != nil {
			t.Fatal(err)
		}
		d := &Dialer{ProxyAddr: "192.0.2.80:1080"}
		got, err := d.relayAddr(context.Background(), remoteConn{remote: tt.remote}, bound)
		if err != nil || got != netip.MustParseAddrPort(tt.want) {
			t.Errorf("relayAddr(%s, remote %v) = %v, %v; want %s", tt.bound, tt.remote, got, err, tt.want)
		}
	}
	if _, err := (&Dialer{}).relayAddr(context.Background(), remoteConn{remote: public}, Addr{}); err == nil {
		t.Error("relayAddr() accepted port 0")
	}
}
