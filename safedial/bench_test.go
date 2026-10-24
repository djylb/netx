package safedial

import (
	"context"
	"net/netip"
	"testing"

	"github.com/djylb/netx"
)

func BenchmarkCheck(b *testing.B) {
	ap4 := netip.MustParseAddrPort("93.184.216.34:443")
	ap6 := netip.MustParseAddrPort("[2606:2800:220:1::1]:443")
	b.Run("default/v4", func(b *testing.B) {
		var d *Dialer
		b.ReportAllocs()
		for b.Loop() {
			_ = d.Check("udp", ap4)
		}
	})
	b.Run("default/v6", func(b *testing.B) {
		var d *Dialer
		b.ReportAllocs()
		for b.Loop() {
			_ = d.Check("udp", ap6)
		}
	})
	prefixes := make([]netip.Prefix, 0, 4096)
	for i := range 4096 {
		prefixes = append(prefixes, netip.PrefixFrom(netip.AddrFrom4([4]byte{1, byte(i >> 4), byte(i << 4), 0}), 20))
	}
	d := &Dialer{Policy: All(DenyPorts(25), DenyPrefixes(prefixes...), DefaultPolicy())}
	b.Run("composite/4096prefixes", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_ = d.Check("udp", ap4)
		}
	})
}

func BenchmarkParseTarget(b *testing.B) {
	for _, address := range []string{"93.184.216.34:443", "0x7f.1:80", "www.example.com:443"} {
		b.Run(address, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_, _ = ParseTarget("tcp", address)
			}
		})
	}
}

func BenchmarkWrapAddrPacketConn(b *testing.B) {
	r := newFakeResolver(map[string][]string{"dns.example": {"93.184.216.34"}})
	w := (&Dialer{Resolver: r}).WrapAddrPacketConn(discardAddrConn{})
	p := make([]byte, 512)
	b.Run("ip", func(b *testing.B) {
		dst := netx.Addr{IP: netip.MustParseAddr("93.184.216.34"), Port: 53}
		b.ReportAllocs()
		for b.Loop() {
			_, _ = w.WriteTo(p, dst)
		}
	})
	b.Run("name-cached", func(b *testing.B) {
		dst := netx.Addr{Name: "dns.example", Port: 53}
		_, _ = w.WriteTo(p, dst)
		waitLookups(b, w)
		b.ReportAllocs()
		for b.Loop() {
			_, _ = w.WriteTo(p, dst)
		}
	})
}

func BenchmarkLookup(b *testing.B) {
	r := newFakeResolver(map[string][]string{"www.example.com": {"93.184.216.34", "2606:2800:220:1::1", "10.0.0.1"}})
	d := &Dialer{Resolver: r}
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		_, _ = d.Lookup(ctx, "tcp", "www.example.com:443")
	}
}
