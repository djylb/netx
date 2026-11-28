package netx_test

import (
	"net/netip"
	"testing"

	"github.com/djylb/netx"
	"github.com/djylb/netx/addrclass"
)

// The root package re-exports the addrclass scopes; each one must name the
// same class and be reachable through ScopeOf.
func TestScopeReexports(t *testing.T) {
	for _, c := range []struct {
		addr string
		root netx.Scope
		want addrclass.Scope
	}{
		{"0.0.0.0", netx.ScopeUnspecified, addrclass.ScopeUnspecified},
		{"127.0.0.1", netx.ScopeLoopback, addrclass.ScopeLoopback},
		{"fe80::1", netx.ScopeLinkLocal, addrclass.ScopeLinkLocal},
		{"10.0.0.1", netx.ScopePrivate, addrclass.ScopePrivate},
		{"100.64.0.1", netx.ScopeShared, addrclass.ScopeShared},
		{"224.0.0.251", netx.ScopeMulticast, addrclass.ScopeMulticast},
		{"255.255.255.255", netx.ScopeBroadcast, addrclass.ScopeBroadcast},
		{"192.0.2.1", netx.ScopeDocumentation, addrclass.ScopeDocumentation},
		{"198.18.0.1", netx.ScopeBenchmarking, addrclass.ScopeBenchmarking},
		{"240.0.0.1", netx.ScopeReserved, addrclass.ScopeReserved},
		{"8.8.8.8", netx.ScopeGlobal, addrclass.ScopeGlobal},
	} {
		if c.root != c.want {
			t.Fatalf("%s: re-export %v differs from %v", c.addr, c.root, c.want)
		}
		if got := netx.ScopeOf(netip.MustParseAddr(c.addr)); got != c.root {
			t.Errorf("ScopeOf(%s) = %v, want %v", c.addr, got, c.root)
		}
	}
	if netx.ScopeOf(netip.Addr{}) != netx.ScopeInvalid {
		t.Error("zero address is not invalid")
	}
}

func TestEmbeddedIPv4(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"::ffff:192.168.1.10", "192.168.1.10"},
		{"2002:808:808::1", "8.8.8.8"},
	} {
		got, ok := netx.EmbeddedIPv4(netip.MustParseAddr(c.in))
		want, wok := addrclass.EmbeddedIPv4(netip.MustParseAddr(c.in))
		if !ok || got.String() != c.want || got != want || ok != wok {
			t.Errorf("EmbeddedIPv4(%s) = %v %v, want %s", c.in, got, ok, c.want)
		}
	}
	if _, ok := netx.EmbeddedIPv4(netip.MustParseAddr("2606:4700::1111")); ok {
		t.Error("native IPv6 reported an embedded IPv4 address")
	}
}
