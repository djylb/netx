package safedial

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/djylb/netx"
)

func addrT(s string, port uint16) Target {
	return Target{Addr: netip.MustParseAddr(s), Network: "tcp", Port: port}
}

func nameT(name string, port uint16) Target {
	return Target{Name: name, Network: "tcp", Port: port}
}

func TestDefaultPolicy(t *testing.T) {
	p := DefaultPolicy()
	for _, s := range []string{
		"127.0.0.1", "::1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "fd00::1",
		"169.254.169.254", "fe80::1", "100.64.0.1", "0.0.0.0", "::", "0.1.2.3",
		"224.0.0.1", "ff02::1", "255.255.255.255", "192.0.2.1", "2001:db8::1",
		"198.18.0.1", "240.0.0.1", "64:ff9b::7f00:1", "2002:7f00:1::1",
		"::ffff:127.0.0.1", "64:ff9b:1::1", "fec0::1",
	} {
		tt := addrT(s, 80)
		tt.Addr = tt.Addr.Unmap()
		err := p.Check(tt)
		if !errors.Is(err, ErrScope) {
			t.Errorf("DefaultPolicy allowed %s: %v", s, err)
		}
	}
	for _, s := range []string{"93.184.216.34", "2606:2800:220:1::1", "64:ff9b::5db8:d822", "192.0.0.9"} {
		if err := p.Check(addrT(s, 80)); err != nil {
			t.Errorf("DefaultPolicy refused %s: %v", s, err)
		}
	}
	if err := p.Check(nameT("localhost", 80)); err != nil {
		t.Errorf("DefaultPolicy refused a name before resolving: %v", err)
	}
	if err := p.Check(addrT("127.0.0.1", 80)); err == nil || err.Error() != "safedial: loopback address not allowed" {
		t.Errorf("loopback reason = %v", err)
	}
}

func TestScopePolicies(t *testing.T) {
	allow := AllowScopes(netx.ScopeGlobal, netx.ScopePrivate)
	deny := DenyScopes(netx.ScopeLoopback)
	for _, tt := range []struct {
		addr        string
		allow, deny bool
	}{
		{"10.0.0.1", true, true},
		{"8.8.8.8", true, true},
		{"127.0.0.1", false, false},
		{"169.254.0.1", false, true},
	} {
		if got := allow.Check(addrT(tt.addr, 1)) == nil; got != tt.allow {
			t.Errorf("AllowScopes(%s) = %v", tt.addr, got)
		}
		if got := deny.Check(addrT(tt.addr, 1)) == nil; got != tt.deny {
			t.Errorf("DenyScopes(%s) = %v", tt.addr, got)
		}
	}
}

func TestPrefixPolicies(t *testing.T) {
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("10.1.0.0/16"), // inside the one before
		netip.MustParsePrefix("::ffff:192.168.0.0/112"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("203.0.113.7/32"),
	}
	allow, deny := AllowPrefixes(prefixes...), DenyPrefixes(prefixes...)
	for _, tt := range []struct {
		addr string
		in   bool
	}{
		{"10.0.0.0", true}, {"10.255.255.255", true}, {"10.1.2.3", true},
		{"11.0.0.0", false}, {"9.255.255.255", false},
		{"192.168.3.4", true}, {"192.169.0.0", false},
		{"2001:db8::1", true}, {"2001:db9::", false},
		{"203.0.113.7", true}, {"203.0.113.8", false}, {"203.0.113.6", false},
		{"::ffff:10.0.0.1", true}, {"fe80::1%eth0", false},
		{"0.0.0.0", false}, {"ffff::", false},
	} {
		target := addrT(tt.addr, 1)
		if got := allow.Check(target) == nil; got != tt.in {
			t.Errorf("AllowPrefixes(%s) = %v", tt.addr, got)
		}
		if got := deny.Check(target) == nil; got == tt.in {
			t.Errorf("DenyPrefixes(%s) = %v", tt.addr, got)
		}
	}
	if allow.Check(nameT("example.com", 1)) != nil || deny.Check(nameT("example.com", 1)) != nil {
		t.Error("a prefix policy refused a name")
	}
	// ::/0 holds the IPv4-mapped space, so it denies IPv4 too.
	if err := DenyPrefixes(netip.MustParsePrefix("::/0")).Check(addrT("1.2.3.4", 1)); !errors.Is(err, ErrPrefix) {
		t.Errorf("DenyPrefixes(::/0) allowed IPv4: %v", err)
	}
	// An invalid prefix fails closed.
	for _, p := range []Policy{AllowPrefixes(netip.Prefix{}), DenyPrefixes(netip.Prefix{})} {
		if err := p.Check(addrT("8.8.8.8", 1)); !errors.Is(err, ErrPrefix) {
			t.Errorf("invalid prefix allowed: %v", err)
		}
	}
}

func TestPortPolicies(t *testing.T) {
	for _, tt := range []struct {
		p    Policy
		port uint16
		ok   bool
	}{
		{AllowPorts(80, 443), 80, true},
		{AllowPorts(80, 443), 443, true},
		{AllowPorts(80, 443), 8080, false},
		{AllowPorts(80, 443), 0, false},
		{DenyPorts(25, 0), 25, false},
		{DenyPorts(25, 0), 0, false},
		{DenyPorts(25, 0), 26, true},
		{AllowPortRange(1024, 65535), 1023, false},
		{AllowPortRange(1024, 65535), 65535, true},
		{AllowPortRange(10, 1), 5, false},
		{DenyPortRange(0, 1023), 1023, false},
		{DenyPortRange(0, 1023), 1024, true},
	} {
		for _, target := range []Target{nameT("example.com", tt.port), addrT("8.8.8.8", tt.port)} {
			err := tt.p.Check(target)
			if (err == nil) != tt.ok || err != nil && !errors.Is(err, ErrPort) {
				t.Errorf("port %d of %v: %v; want ok=%v", tt.port, target, err, tt.ok)
			}
		}
	}
}

func TestNamePolicies(t *testing.T) {
	allow := AllowNames("Example.com.", "*.wild.example", ".dot.example", "  ", "")
	deny := DenyNames("example.com", "*.wild.example")
	for _, tt := range []struct {
		name string
		in   bool
	}{
		{"example.com", true}, {"example.com.", true}, {"www.example.com", true},
		{"a.b.example.com", true}, {"notexample.com", false}, {"com", false},
		{"wild.example", false}, {"a.wild.example", true},
		{"dot.example", false}, {"x.dot.example", true},
		{"", false}, {".", false},
	} {
		target := nameT(tt.name, 1)
		if got := allow.Check(target) == nil; got != tt.in {
			t.Errorf("AllowNames(%q) = %v", tt.name, got)
		}
		if tt.name == "dot.example" || tt.name == "x.dot.example" {
			continue
		}
		if got := deny.Check(target) == nil; got == tt.in {
			t.Errorf("DenyNames(%q) = %v", tt.name, got)
		}
	}
	// An address dialed as such has no name: AllowNames refuses it, and an
	// address that an allowed name resolved to passes.
	if err := allow.Check(addrT("8.8.8.8", 1)); !errors.Is(err, ErrName) {
		t.Errorf("AllowNames allowed an IP address: %v", err)
	}
	resolved := addrT("10.0.0.1", 1)
	resolved.Name = "www.example.com"
	if err := allow.Check(resolved); err != nil {
		t.Errorf("AllowNames refused an address of an allowed name: %v", err)
	}
}

func TestComposition(t *testing.T) {
	p := All(
		DenyPorts(25),
		nil,
		DenyNames("blocked.example"),
		Any(AllowNames("intranet.example"), AllowPrefixes(netip.MustParsePrefix("100.64.0.0/10")), DefaultPolicy()),
	)
	intranet := addrT("10.0.0.5", 443)
	intranet.Name = "intranet.example"
	other := addrT("10.0.0.5", 443)
	other.Name = "evil.example"
	for _, tt := range []struct {
		target Target
		want   error
	}{
		{nameT("intranet.example", 443), nil},
		{intranet, nil},
		{other, ErrScope},
		{addrT("10.0.0.5", 443), ErrScope},
		{addrT("100.64.1.1", 443), nil},
		{addrT("8.8.8.8", 443), nil},
		{addrT("8.8.8.8", 25), ErrPort},
		{nameT("blocked.example", 443), ErrName},
		{nameT("evil.example", 443), nil}, // decided by its addresses
	} {
		err := p.Check(tt.target)
		if tt.want == nil && err != nil || tt.want != nil && !errors.Is(err, tt.want) {
			t.Errorf("Check(%v) = %v; want %v", tt.target, err, tt.want)
		}
	}
	if err := All().Check(addrT("127.0.0.1", 1)); err != nil {
		t.Errorf("All() refused: %v", err)
	}
	if err := Any(nil).Check(addrT("8.8.8.8", 1)); err == nil {
		t.Error("Any() allowed")
	}
	called := false
	f := PolicyFunc(func(Target) error { called = true; return nil })
	if err := f.Check(Target{}); err != nil || !called {
		t.Errorf("PolicyFunc: %v, %v", err, called)
	}
}

// Allowing checks do not allocate, so that a relay can check every
// datagram.
func TestPolicyAllocs(t *testing.T) {
	prefixes := make([]netip.Prefix, 0, 256)
	for i := range 256 {
		prefixes = append(prefixes, netip.PrefixFrom(netip.AddrFrom4([4]byte{100, byte(i), 0, 0}), 16))
	}
	p := All(DenyPorts(25), DenyNames("blocked.example"), Any(AllowPrefixes(prefixes...), DefaultPolicy()))
	target := addrT("100.200.1.1", 443)
	target.Name = "www.example.com"
	if n := testing.AllocsPerRun(100, func() {
		if p.Check(target) != nil {
			t.Fatal("refused")
		}
		if p.Check(addrT("127.0.0.1", 443)) == nil {
			t.Fatal("allowed")
		}
	}); n != 0 {
		t.Errorf("%v allocations per check", n)
	}
}
