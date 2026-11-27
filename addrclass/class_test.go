package addrclass

import (
	"net/netip"
	"slices"
	"testing"
)

func TestPrivateSets(t *testing.T) {
	lan := PrivateLAN.Prefixes()
	routing := PrivateRouting.Prefixes()
	loopback := Loopback.Prefixes()
	if len(lan) != 9 || len(routing) != 13 || len(loopback) != 2 {
		t.Fatalf("prefix counts: LAN %d, routing %d, loopback %d", len(lan), len(routing), len(loopback))
	}
	for _, p := range lan {
		if !slices.Contains(routing, p) || !PrivateLAN.Contains(p.Addr()) {
			t.Errorf("private prefix %s is missing from a class", p)
		}
	}
	for _, tc := range []struct {
		addr    string
		loop    bool
		lan     bool
		routing bool
	}{
		{"::ffff:127.0.0.1", true, true, true},
		{"::1%zone", true, true, true},
		{"::ffff:100.64.1.1", false, true, true},
		{"100.127.255.255", false, true, true},
		{"100.128.0.0", false, false, false},
		{"10.0.0.1", false, true, true},
		{"172.31.255.255", false, true, true},
		{"192.168.0.1", false, true, true},
		{"169.254.0.1", false, true, true},
		{"fe80::1%zone", false, true, true},
		{"fd00::1", false, true, true},
		{"0.1.2.3", false, false, true},
		{"224.0.0.1", false, false, true},
		{"255.255.255.255", false, false, true},
		{"ff02::1%zone", false, false, true},
		{"::", false, false, false},
		{"64:ff9b:1::1", false, false, false},
		{"192.0.2.1", false, false, false},
		{"198.18.0.0", false, false, false},
		{"2001:db8::1", false, false, false},
	} {
		a := netip.MustParseAddr(tc.addr)
		if got := Loopback.Contains(a); got != tc.loop {
			t.Errorf("Loopback(%s) = %t, want %t", a, got, tc.loop)
		}
		if got := PrivateLAN.Contains(a); got != tc.lan {
			t.Errorf("PrivateLAN(%s) = %t, want %t", a, got, tc.lan)
		}
		if got := PrivateRouting.Contains(a); got != tc.routing {
			t.Errorf("PrivateRouting(%s) = %t, want %t", a, got, tc.routing)
		}
	}
}

func TestPrefixesAreIndependent(t *testing.T) {
	prefixes := Loopback.Prefixes()
	clear(prefixes)
	if !Loopback.Contains(netip.IPv6Loopback()) || !PrivateLAN.Contains(netip.IPv6Loopback()) {
		t.Fatal("modifying a copy changed a class")
	}
	for _, c := range []Class{0, 255} {
		if len(c.Prefixes()) != 0 || c.Contains(netip.IPv6Loopback()) {
			t.Errorf("class %d is not empty", c)
		}
	}
	if Contains(Loopback.Prefixes(), netip.Addr{}) {
		t.Fatal("invalid address matched")
	}
}
