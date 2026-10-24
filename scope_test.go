package netx

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
)

// TestScopeTables checks every table entry's numbers against its prefix
// text, and the order: no entry may be shadowed by an earlier one that
// contains it.
func TestScopeTables(t *testing.T) {
	for i, e := range scopeTable4 {
		p := netip.MustParsePrefix(e.prefix)
		b := p.Addr().As4()
		if p.Masked() != p || binary.BigEndian.Uint32(b[:]) != e.addr || p.Bits() != int(e.bits) {
			t.Errorf("IPv4 entry %s holds %08x/%d", e.prefix, e.addr, e.bits)
		}
		for _, prev := range scopeTable4[:i] {
			if pp := netip.MustParsePrefix(prev.prefix); pp.Bits() <= p.Bits() && pp.Contains(p.Addr()) {
				t.Errorf("IPv4 entry %s is shadowed by %s", e.prefix, prev.prefix)
			}
		}
	}
	for i, e := range scopeTable6 {
		p := netip.MustParsePrefix(e.prefix)
		b := p.Addr().As16()
		if p.Masked() != p || binary.BigEndian.Uint64(b[:8]) != e.hi || binary.BigEndian.Uint64(b[8:]) != e.lo || p.Bits() != int(e.bits) {
			t.Errorf("IPv6 entry %s holds %016x%016x/%d", e.prefix, e.hi, e.lo, e.bits)
		}
		for _, prev := range scopeTable6[:i] {
			if pp := netip.MustParsePrefix(prev.prefix); pp.Bits() <= p.Bits() && pp.Contains(p.Addr()) {
				t.Errorf("IPv6 entry %s is shadowed by %s", e.prefix, prev.prefix)
			}
		}
	}
}

func TestScopeOf(t *testing.T) {
	for _, tt := range []struct {
		addr  string
		scope Scope
	}{
		{"0.0.0.0", ScopeUnspecified},
		{"0.1.2.3", ScopeReserved},
		{"1.1.1.1", ScopeGlobal},
		{"8.8.8.8", ScopeGlobal},
		{"9.255.255.255", ScopeGlobal},
		{"10.0.0.1", ScopePrivate},
		{"11.0.0.1", ScopeGlobal},
		{"100.63.255.255", ScopeGlobal},
		{"100.64.0.1", ScopeShared},
		{"100.127.255.255", ScopeShared},
		{"100.128.0.0", ScopeGlobal},
		{"127.0.0.1", ScopeLoopback},
		{"127.255.255.254", ScopeLoopback},
		{"169.254.1.1", ScopeLinkLocal},
		{"172.15.255.255", ScopeGlobal},
		{"172.16.0.1", ScopePrivate},
		{"172.31.255.255", ScopePrivate},
		{"172.32.0.0", ScopeGlobal},
		{"192.0.0.1", ScopeReserved},
		{"192.0.0.8", ScopeReserved},
		{"192.0.0.9", ScopeGlobal},
		{"192.0.0.10", ScopeGlobal},
		{"192.0.0.170", ScopeReserved},
		{"192.0.2.1", ScopeDocumentation},
		{"192.31.196.1", ScopeGlobal},
		{"192.52.193.1", ScopeGlobal},
		{"192.88.99.1", ScopeReserved},
		{"192.168.1.1", ScopePrivate},
		{"192.175.48.1", ScopeGlobal},
		{"198.17.255.255", ScopeGlobal},
		{"198.18.0.1", ScopeBenchmarking},
		{"198.19.255.255", ScopeBenchmarking},
		{"198.20.0.0", ScopeGlobal},
		{"198.51.100.7", ScopeDocumentation},
		{"203.0.113.9", ScopeDocumentation},
		{"223.255.255.255", ScopeGlobal},
		{"224.0.0.251", ScopeMulticast},
		{"239.255.255.250", ScopeMulticast},
		{"240.0.0.1", ScopeReserved},
		{"255.255.255.254", ScopeReserved},
		{"255.255.255.255", ScopeBroadcast},

		{"::", ScopeUnspecified},
		{"::1", ScopeLoopback},
		{"::2", ScopeReserved},
		{"::ffff:10.1.2.3", ScopePrivate},
		{"::ffff:8.8.8.8", ScopeGlobal},
		{"::ffff:0.0.0.0", ScopeUnspecified},
		{"::8.8.8.8", ScopeReserved},
		{"64:ff9b::8.8.8.8", ScopeGlobal},
		{"64:ff9b::10.0.0.1", ScopeReserved},
		{"64:ff9b::192.0.2.1", ScopeReserved},
		{"64:ff9b:1::8.8.8.8", ScopePrivate},
		{"100::1", ScopeReserved},
		{"100:0:0:1::1", ScopeReserved},
		{"100:0:0:2::1", ScopeReserved},
		{"2001::1", ScopeReserved},                              // Teredo, server 0.0.0.0
		{"2001:0:4136:e378:8000:63bf:3fff:fdd2", ScopeReserved}, // RFC 4380 example, client 192.0.2.45
		{"2001:0:4136:e378:8000:63bf:f7f7:f7f7", ScopeGlobal},   // client 8.8.8.8
		{"2001:0:4136:e378:8000:63bf:f5ff:fffe", ScopeReserved}, // client 10.0.0.1
		{"2001:0:c0a8:101::", ScopeReserved},                    // server 192.168.1.1
		{"2001:1::1", ScopeGlobal},
		{"2001:1::2", ScopeGlobal},
		{"2001:1::3", ScopeGlobal},
		{"2001:1::4", ScopeReserved},
		{"2001:2::1", ScopeBenchmarking},
		{"2001:2:1::1", ScopeReserved},
		{"2001:3::1", ScopeGlobal},
		{"2001:4:112::1", ScopeGlobal},
		{"2001:10::1", ScopeReserved},
		{"2001:20::1", ScopeGlobal},
		{"2001:30::1", ScopeGlobal},
		{"2001:1ff::1", ScopeReserved},
		{"2001:200::1", ScopeGlobal},
		{"2001:db8::1", ScopeDocumentation},
		{"2001:4860:4860::8888", ScopeGlobal},
		{"2002:808:808::1", ScopeGlobal},
		{"2002:c0a8:101::1", ScopeReserved},
		{"2002:7f00:1::1", ScopeReserved},
		{"2400:cb00::1", ScopeGlobal},
		{"2620:4f:8000::1", ScopeGlobal},
		{"3ffe::1", ScopeGlobal},
		{"3fff::1", ScopeDocumentation},
		{"3fff:fff::1", ScopeDocumentation},
		{"3fff:1000::1", ScopeGlobal},
		{"4000::1", ScopeReserved},
		{"5f00::1", ScopeReserved},
		{"fc00::1", ScopePrivate},
		{"fd12:3456::1", ScopePrivate},
		{"fe80::1", ScopeLinkLocal},
		{"fe80::1%eth0", ScopeLinkLocal},
		{"febf::1", ScopeLinkLocal},
		{"fec0::1", ScopeReserved},
		{"ff02::1", ScopeMulticast},
		{"ff0e::1", ScopeMulticast},
	} {
		a := netip.MustParseAddr(tt.addr)
		if got := ScopeOf(a); got != tt.scope {
			t.Errorf("ScopeOf(%s) = %v, want %v", tt.addr, got, tt.scope)
		}
		if got := IsGlobal(a); got != (tt.scope == ScopeGlobal) {
			t.Errorf("IsGlobal(%s) = %v", tt.addr, got)
		}
	}
	if got := ScopeOf(netip.Addr{}); got != ScopeInvalid {
		t.Errorf("ScopeOf(zero) = %v", got)
	}
	if IsGlobal(netip.Addr{}) {
		t.Error("IsGlobal(zero) = true")
	}
}

func TestScopeString(t *testing.T) {
	for s := ScopeInvalid; s <= ScopeGlobal; s++ {
		if str := s.String(); str == "" || strings.HasPrefix(str, "scope(") {
			t.Errorf("Scope(%d).String() = %q", s, s.String())
		}
	}
	if got := Scope(200).String(); got != "scope(200)" {
		t.Errorf("Scope(200).String() = %q", got)
	}
}

// refScope classifies a with netip prefixes from the table text, so that it
// shares no code with ScopeOf beyond the table.
func refScope(a netip.Addr) Scope {
	a = a.Unmap().WithZone("")
	if !a.IsValid() {
		return ScopeInvalid
	}
	if a.Is4() {
		for _, e := range scopeTable4 {
			if netip.MustParsePrefix(e.prefix).Contains(a) {
				return e.scope
			}
		}
		return ScopeGlobal
	}
	for _, e := range scopeTable6 {
		if !netip.MustParsePrefix(e.prefix).Contains(a) {
			continue
		}
		b := a.As16()
		v4 := func(i int) netip.Addr { return netip.AddrFrom4([4]byte(b[i : i+4])) }
		global := func(as ...netip.Addr) Scope {
			for _, x := range as {
				if refScope(x) != ScopeGlobal {
					return ScopeReserved
				}
			}
			return ScopeGlobal
		}
		switch e.scope {
		case scopeNAT64:
			return global(v4(12))
		case scope6to4:
			return global(v4(2))
		case scopeTeredo:
			c := v4(12).As4()
			for i := range c {
				c[i] ^= 0xff
			}
			return global(v4(4), netip.AddrFrom4(c))
		}
		return e.scope
	}
	return ScopeReserved
}

func FuzzScopeOf(f *testing.F) {
	for _, s := range []string{"10.0.0.1", "::ffff:100.64.0.1", "2001::1", "2002:808:808::", "64:ff9b::1.1.1.1", "fe80::1", "3fff::"} {
		b := netip.MustParseAddr(s).As16()
		f.Add(b[:])
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		var a netip.Addr
		switch {
		case len(b) >= 16:
			a = netip.AddrFrom16([16]byte(b[:16]))
		case len(b) >= 4:
			a = netip.AddrFrom4([4]byte(b[:4]))
		default:
			return
		}
		if got, want := ScopeOf(a), refScope(a); got != want {
			t.Fatalf("ScopeOf(%s) = %v, want %v", a, got, want)
		}
	})
}

func TestScopeOfAllocs(t *testing.T) {
	addrs := []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("fe80::1%eth0"), netip.MustParseAddr("2001:0:4136:e378:8000:63bf:3fff:fdd2")}
	if n := testing.AllocsPerRun(100, func() {
		for _, a := range addrs {
			_ = ScopeOf(a)
		}
	}); n != 0 {
		t.Errorf("ScopeOf allocates %v times", n)
	}
}

func BenchmarkScopeOf(b *testing.B) {
	for _, bc := range []struct{ name, addr string }{
		{"v4global", "8.8.8.8"},
		{"v4private", "192.168.1.1"},
		{"v4reserved", "240.0.0.1"},
		{"v6global", "2400:cb00::1"},
		{"v6teredo", "2001:0:4136:e378:8000:63bf:f7f7:f7f7"},
		{"v6ula", "fd00::1"},
	} {
		a := netip.MustParseAddr(bc.addr)
		b.Run(bc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				ScopeOf(a)
			}
		})
	}
}
