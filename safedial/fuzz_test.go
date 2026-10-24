package safedial

import (
	"net/netip"
	"strings"
	"testing"
)

// FuzzParseTarget checks that no host comes out as a name that a resolver
// could read as an address, and that addresses come out normalised.
func FuzzParseTarget(f *testing.F) {
	for _, s := range []string{
		"127.1:80", "0x7f.0.0.1:80", "2130706433:1", "[::ffff:1.2.3.4]:5", "[fe80::1%eth0]:1",
		"example.com.:443", "a.b:0", "1.2.3.4.:1", "0177.1:2", "1e100.net:80", "08:1", ":80",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, address string) {
		target, err := ParseTarget("udp", address)
		if err != nil {
			return
		}
		switch {
		case target.Addr.IsValid():
			if target.Name != "" || target.Addr.Is4In6() || target.Addr.Zone() != "" {
				t.Fatalf("%q: %+v", address, target)
			}
			if target.Zone != "" && !target.Addr.Is6() {
				t.Fatalf("%q: zone on IPv4", address)
			}
		case target.Name != "":
			host := strings.TrimSuffix(target.Name, ".")
			if _, ok := ParseLegacyIPv4(host); ok {
				t.Fatalf("%q: legacy IPv4 %q as a name", address, host)
			}
			if _, err := netip.ParseAddr(host); err == nil {
				t.Fatalf("%q: IP literal %q as a name", address, host)
			}
			if !validName(host) || strings.ToLower(target.Name) != target.Name {
				t.Fatalf("%q: name %q", address, target.Name)
			}
		default:
			t.Fatalf("%q: neither address nor name", address)
		}
		if ip, ok := ParseLegacyIPv4(address); ok {
			// Dotted decimal reads as netip reads it.
			if std, err := netip.ParseAddr(address); err == nil && std != ip {
				t.Fatalf("%q: %v; netip %v", address, ip, std)
			}
			if again, ok := ParseLegacyIPv4(ip.String()); !ok || again != ip {
				t.Fatalf("%q: %v does not round-trip", address, ip)
			}
		}
	})
}
