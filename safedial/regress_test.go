package safedial

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/djylb/netx"
)

// allowAll is a policy that allows every target, to show the checks that
// hold whatever the policy.
var allowAll = PolicyFunc(func(Target) error { return nil })

// A target with neither an address nor a name is refused by every policy
// of this package, and by the Dialer whatever its policy, as a socket sends
// to it on the local host.
func TestEmptyTargetRefused(t *testing.T) {
	for _, p := range []Policy{
		DefaultPolicy(), DenyScopes(), AllowScopes(netx.ScopeInvalid, netx.ScopeUnspecified, netx.ScopeGlobal),
		AllowPrefixes(netip.MustParsePrefix("::/0")), DenyPrefixes(netip.MustParsePrefix("10.0.0.0/8")),
	} {
		if err := p.Check(Target{Network: "udp", Port: 9}); err == nil {
			t.Errorf("%T allowed the empty target", p)
		}
	}
	for _, d := range []*Dialer{nil, {}, {Policy: allowAll}} {
		err := d.Check("udp", netip.AddrPort{})
		assertDenied(t, err, ErrScope, "")
		err = d.Check("udp", netip.AddrPortFrom(netip.Addr{}, 9))
		assertDenied(t, err, ErrScope, "")
	}
}

// hidden hides WriteToUDPAddrPort, as a net.PacketConn wrapper does.
type hidden struct{ net.PacketConn }

// A *net.UDPAddr without an IP, as net.ResolveUDPAddr returns for ":port",
// does not reach the local host through a wrapped connection.
func TestPacketConnNilIP(t *testing.T) {
	victim := listenUDP(t)
	port := netip.MustParseAddrPort(victim.LocalAddr().String()).Port()
	for _, policy := range []Policy{nil, allowAll} {
		d := &Dialer{Policy: policy}
		for _, c := range []net.PacketConn{listenUDP(t), hidden{listenUDP(t)}} {
			w := d.WrapPacketConn(c)
			_, err := w.WriteTo([]byte("secret"), &net.UDPAddr{Port: int(port)})
			assertDenied(t, err, ErrScope, "")
			_, err = w.WriteToUDPAddrPort([]byte("secret"), netip.AddrPortFrom(netip.Addr{}, port))
			assertDenied(t, err, ErrScope, "")
		}
	}
	_ = victim.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	buf := make([]byte, 64)
	if n, from, err := victim.ReadFromUDPAddrPort(buf); err == nil {
		t.Errorf("the local host received %q from %v", buf[:n], from)
	}
}

// Hosts that reach the local host or other refused addresses, in many
// forms, are refused by DefaultPolicy.
func TestRefusedForms(t *testing.T) {
	r := newFakeResolver(map[string][]string{
		"localhost":        {"127.0.0.1", "::1"},
		"127.0.0.1.nip.io": {"127.0.0.1"},
	})
	d := &Dialer{Resolver: r, Forward: &recordDialer{}}
	for _, h := range []string{
		"127.1", "0x7f.1", "0177.0.0.1", "2130706433", "127.0.0.1.", "[::1]", "[::127.0.0.1]",
		"[::ffff:7f00:1]", "[::ffff:0:7f00:1]", "[64:ff9b::7f00:1]", "[64:ff9b:1::7f00:1]", "[2002:7f00:1::1]",
		"[2001:0:4136:e378:8000:63bf:80ff:fffe]", "[fe80::1%25lo0]", "[fe80::1%lo0]", "0.0.0.0", "[::]", "0",
		"localhost", "LOCALHOST.", "127.0.0.1.nip.io", "[fec0::1]", "[100::1]", "[::ffff:127.0.0.1]",
		"%31%32%37.0.0.1", "127。0。0。1", "0x7F000001", "00000000177.0.0.1", "127.000.000.001",
		"[0:0:0:0:0:ffff:127.0.0.1]", "[2001:db8::1]", "[ff02::1]", "255.255.255.255", "169.254.169.254",
		"[fd00:ec2::254]", "[::ffff:169.254.169.254]", "[64:ff9b::a9fe:a9fe]", "[::169.254.169.254]",
		"127.0.0.1\x00.example.com", "1e100", "0x", "0x.0x.0x.0x", "08.0.0.1", "4294967296", "127.0.0.1:80",
	} {
		address := h + ":80"
		if addrs, err := d.Lookup(context.Background(), "tcp", address); err == nil {
			t.Errorf("Lookup(%q) = %v", address, addrs)
		}
	}
}

// Name patterns match in their ASCII form, and a pattern that is no host
// name fails closed.
func TestNamePatternsIDN(t *testing.T) {
	ace := nameT("www.xn--mnchen-3ya.example", 443)
	if err := DenyNames("MÜNCHEN.example").Check(ace); !errors.Is(err, ErrName) {
		t.Errorf("DenyNames(MÜNCHEN.example) allowed %v: %v", ace.Name, err)
	}
	if err := AllowNames("*.münchen.example").Check(ace); err != nil {
		t.Errorf("AllowNames(*.münchen.example) refused %v: %v", ace.Name, err)
	}
	for _, bad := range []string{"bad name", "\xff.example", "10.0.0.1"} {
		if err := DenyNames(bad).Check(nameT("example.com", 1)); !errors.Is(err, ErrName) {
			t.Errorf("DenyNames(%q) allowed a name: %v", bad, err)
		}
		if err := DenyNames(bad).Check(addrT("8.8.8.8", 1)); err != nil {
			t.Errorf("DenyNames(%q) refused an address: %v", bad, err)
		}
		if err := AllowNames(bad).Check(nameT("example.com", 1)); !errors.Is(err, ErrName) {
			t.Errorf("AllowNames(%q) allowed a name: %v", bad, err)
		}
	}
}

// The wrapped connection gets the address checked alone, without the name
// or zone of the destination given.
func TestAddrPacketConnSendsChecked(t *testing.T) {
	inner := newFakeAddrConn()
	w := (&Dialer{Policy: AllowScopes(netx.ScopeGlobal, netx.ScopeLinkLocal)}).WrapAddrPacketConn(inner)
	defer func() { _ = w.Close() }()
	for _, tt := range []struct{ dst, want netx.Addr }{
		{netx.Addr{IP: netip.MustParseAddr("::ffff:93.184.216.34"), Name: "other.example", Port: 53}, netx.Addr{IP: netip.MustParseAddr("93.184.216.34"), Port: 53}},
		{netx.Addr{IP: netip.MustParseAddr("fe80::1%eth0"), Port: 53}, netx.Addr{IP: netip.MustParseAddr("fe80::1"), Port: 53}},
	} {
		if _, err := w.WriteTo([]byte("x"), tt.dst); err != nil {
			t.Fatal(err)
		}
		if d := inner.next(t); d.dst != tt.want {
			t.Errorf("sent to %+v; want %+v", d.dst, tt.want)
		}
	}
}
