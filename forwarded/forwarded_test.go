package forwarded

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func mustSet(t testing.TB, entries ...string) *PrefixSet {
	t.Helper()
	s, err := ParsePrefixSet(entries...)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestParseNode(t *testing.T) {
	for _, tt := range []struct {
		in   string
		want string // "" for false
	}{
		{"192.0.2.1", "192.0.2.1:0"},
		{"192.0.2.1:8080", "192.0.2.1:8080"},
		{"192.0.2.1:_abc", "192.0.2.1:0"},
		{"192.0.2.1:", ""},
		{"192.0.2.1:65536", ""},
		{"192.0.2.1:123456", ""},
		{"192.0.2.1:8x", ""},
		{"192.0.2.1:_", ""},
		{"192.0.2.1:_a/b", ""},
		{"2001:db8::1", "[2001:db8::1]:0"},
		{"[2001:db8::1]", "[2001:db8::1]:0"},
		{"[2001:db8::1]:443", "[2001:db8::1]:443"},
		{"[2001:db8::1]:_p", "[2001:db8::1]:0"},
		{"[2001:db8::1]443", ""},
		{"[2001:db8::1", ""},
		{"[192.0.2.1]", ""},
		{"[192.0.2.1]:80", ""},
		{"::ffff:192.0.2.1", "192.0.2.1:0"},
		{"[::ffff:192.0.2.1]:80", "192.0.2.1:80"},
		{"fe80::1%eth0", "[fe80::1]:0"},
		{"[fe80::1%eth0]:80", "[fe80::1]:80"},
		{"192.0.2.1%eth0", ""},
		{"unknown", ""},
		{"_hidden", ""},
		{"example.com", ""},
		{"example.com:80", ""},
		{"", ""},
		{" 192.0.2.1", ""},
		{"1.2.3", ""},
	} {
		ap, ok := ParseNode(tt.in)
		got := ""
		if ok {
			got = ap.String()
		}
		if got != tt.want {
			t.Errorf("ParseNode(%q) = %q %v, want %q", tt.in, got, ok, tt.want)
		}
	}
}

func TestPrefixSet(t *testing.T) {
	s := mustSet(t, "10.0.0.0/8", " 192.0.2.1 ", "", "172.16.0.0/12", "172.20.0.0/16", "2001:db8::/32", "::1", "::ffff:198.51.100.0/120", "0.0.0.0/32", "255.255.255.255/32")
	for _, tt := range []struct {
		addr string
		want bool
	}{
		{"10.1.2.3", true},
		{"11.0.0.0", false},
		{"9.255.255.255", false},
		{"192.0.2.1", true},
		{"192.0.2.2", false},
		{"172.31.255.255", true},
		{"172.32.0.0", false},
		{"::ffff:10.0.0.1", true},
		{"198.51.100.200", true},
		{"198.51.101.0", false},
		{"2001:db8:ffff::1", true},
		{"2001:db9::", false},
		{"::1", true},
		{"::2", false},
		{"fe80::1%eth0", false},
		{"0.0.0.0", true},
		{"0.0.0.1", false},
		{"255.255.255.255", true},
	} {
		if got := s.Contains(netip.MustParseAddr(tt.addr)); got != tt.want {
			t.Errorf("Contains(%s) = %v", tt.addr, got)
		}
	}
	if s.Contains(netip.Addr{}) {
		t.Error("Contains(zero) = true")
	}
	var nilSet *PrefixSet
	if nilSet.Contains(netip.MustParseAddr("10.0.0.1")) || !nilSet.IsEmpty() || s.IsEmpty() {
		t.Error("nil set")
	}
	all := mustSet(t, "0.0.0.0/0", "::/0")
	for _, a := range []string{"0.0.0.0", "255.255.255.255", "::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "::ffff:1.2.3.4"} {
		if !all.Contains(netip.MustParseAddr(a)) {
			t.Errorf("all does not contain %s", a)
		}
	}
	if len(all.v4) != 1 || len(all.v6) != 1 {
		t.Errorf("all = %v %v", all.v4, all.v6)
	}
	merged := mustSet(t, "10.0.0.0/9", "10.128.0.0/9", "10.0.0.0/24", "2001:db8::/33", "2001:db8:8000::/33")
	if len(merged.v4) != 1 || len(merged.v6) != 1 {
		t.Errorf("adjacent prefixes not merged: %v %v", merged.v4, merged.v6)
	}
	for _, bad := range []string{"10.0.0.0/33", "example.com", "fe80::1%eth0", "10.0.0.0/8/8"} {
		if _, err := ParsePrefixSet(bad); !errors.Is(err, ErrInvalidPrefix) || !strings.Contains(err.Error(), bad) {
			t.Errorf("ParsePrefixSet(%q) error = %v", bad, err)
		}
	}
	if NewPrefixSet(netip.Prefix{}).IsEmpty() != true {
		t.Error("zero prefix not left out")
	}
}

func FuzzPrefixSet(f *testing.F) {
	f.Add([]byte{10, 0, 0, 0, 8, 192, 168, 0, 0, 16}, []byte{10, 1, 2, 3})
	f.Add([]byte{0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32}, []byte{0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	f.Fuzz(func(t *testing.T, spec, addr []byte) {
		// spec is a list of prefixes, each 4 or 16 address bytes chosen by
		// its first byte's low bit, then a length byte.
		var prefixes []netip.Prefix
		for len(spec) > 0 {
			n := 4
			if spec[0]&1 == 1 {
				n = 16
			}
			if len(spec) < n+1 {
				break
			}
			var a netip.Addr
			if n == 4 {
				a = netip.AddrFrom4([4]byte(spec[:4]))
			} else {
				a = netip.AddrFrom16([16]byte(spec[:16]))
			}
			prefixes = append(prefixes, netip.PrefixFrom(a, int(spec[n])%(a.BitLen()+1)))
			spec = spec[n+1:]
		}
		s := NewPrefixSet(prefixes...)
		var a netip.Addr
		switch {
		case len(addr) >= 16:
			a = netip.AddrFrom16([16]byte(addr[:16]))
		case len(addr) >= 4:
			a = netip.AddrFrom4([4]byte(addr[:4]))
		default:
			return
		}
		want := false
		u := a.Unmap()
		for _, p := range prefixes {
			if p.Addr().Is4In6() && p.Bits() >= 96 {
				p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
			}
			if p.Contains(u) {
				want = true
			}
		}
		if got := s.Contains(a); got != want {
			t.Fatalf("Contains(%s) = %v, want %v for %v", a, got, want, prefixes)
		}
	})
}

func TestResolve(t *testing.T) {
	trusted := mustSet(t, "10.0.0.0/8", "2001:db8:1::/48")
	xff := &Resolver{Trusted: trusted}
	fwd := &Resolver{Trusted: trusted, Header: HeaderForwarded}
	xri := &Resolver{Trusted: trusted, Header: HeaderXRealIP}
	type hdr = map[string][]string
	for _, tt := range []struct {
		name   string
		r      *Resolver
		peer   string
		header hdr
		want   Client
	}{
		{"untrusted peer", xff, "203.0.113.1:5000", hdr{"X-Forwarded-For": {"198.51.100.1"}},
			Client{Addr: ap("203.0.113.1:5000")}},
		{"nil resolver", nil, "10.0.0.1:5000", hdr{"X-Forwarded-For": {"198.51.100.1"}},
			Client{Addr: ap("10.0.0.1:5000")}},
		{"one proxy", xff, "10.0.0.1:5000", hdr{"X-Forwarded-For": {"198.51.100.1"}},
			Client{Addr: ap("198.51.100.1:0"), Hops: 1}},
		{"prepended spoof", xff, "10.0.0.1:5000", hdr{"X-Forwarded-For": {"1.1.1.1, 198.51.100.1"}},
			Client{Addr: ap("198.51.100.1:0"), Hops: 1}},
		{"two proxies", xff, "10.0.0.1:5000", hdr{"X-Forwarded-For": {"6.6.6.6, 198.51.100.1, 10.0.0.2"}},
			Client{Addr: ap("198.51.100.1:0"), Hops: 2}},
		{"field lines", xff, "10.0.0.1:5000", hdr{"X-Forwarded-For": {"6.6.6.6", "198.51.100.1 ,", " 10.0.0.2,10.0.0.3"}},
			Client{Addr: ap("198.51.100.1:0"), Hops: 3}},
		{"all trusted", xff, "10.0.0.1:5000", hdr{"X-Forwarded-For": {"10.0.0.3, 10.0.0.2"}},
			Client{Addr: ap("10.0.0.3:0"), Hops: 2}},
		{"no field", xff, "10.0.0.1:5000", hdr{},
			Client{Addr: ap("10.0.0.1:5000")}},
		{"empty field", xff, "10.0.0.1:5000", hdr{"X-Forwarded-For": {" , "}},
			Client{Addr: ap("10.0.0.1:5000")}},
		{"garbage", xff, "10.0.0.1:5000", hdr{"X-Forwarded-For": {"1.1.1.1, garbage, 10.0.0.2"}},
			Client{Addr: ap("10.0.0.2:0"), Hops: 1, Opaque: "garbage"}},
		{"ipv6 entries", xff, "[2001:db8:1::5]:443", hdr{"X-Forwarded-For": {"[2001:db8:2::1]:1234, 2001:db8:1::9"}},
			Client{Addr: ap("[2001:db8:2::1]:1234"), Hops: 2}},
		{"mapped peer", xff, "[::ffff:10.0.0.1]:80", hdr{"X-Forwarded-For": {"::ffff:198.51.100.1"}},
			Client{Addr: ap("198.51.100.1:0"), Hops: 1}},
		{"proto host", xff, "10.0.0.1:80", hdr{"X-Forwarded-For": {"198.51.100.1"}, "X-Forwarded-Proto": {"http, https"}, "X-Forwarded-Host": {"evil", "example.com:8443"}},
			Client{Addr: ap("198.51.100.1:0"), Hops: 1, Proto: "https", Host: "example.com:8443"}},
		{"bad proto host", xff, "10.0.0.1:80", hdr{"X-Forwarded-Proto": {"ht tp"}, "X-Forwarded-Host": {"a/b"}},
			Client{Addr: ap("10.0.0.1:80")}},
		{"proto from untrusted", xff, "203.0.113.1:80", hdr{"X-Forwarded-Proto": {"https"}},
			Client{Addr: ap("203.0.113.1:80")}},

		{"forwarded", fwd, "10.0.0.1:80", hdr{"Forwarded": {`for=198.51.100.1;proto=https;host=example.com`}},
			Client{Addr: ap("198.51.100.1:0"), Hops: 1, Proto: "https", Host: "example.com"}},
		{"forwarded ignores xff", fwd, "10.0.0.1:80", hdr{"X-Forwarded-For": {"1.1.1.1"}},
			Client{Addr: ap("10.0.0.1:80")}},
		{"forwarded quoted v6", fwd, "10.0.0.1:80", hdr{"Forwarded": {`For="[2001:db8:2::1]:4711" ; Proto=http, for=10.0.0.2;host="example.com:81"`}},
			Client{Addr: ap("[2001:db8:2::1]:4711"), Hops: 2, Proto: "http"}},
		{"forwarded lines", fwd, "10.0.0.1:80", hdr{"Forwarded": {`for=1.1.1.1`, `for=198.51.100.7, for="10.0.0.9:_p"`}},
			Client{Addr: ap("198.51.100.7:0"), Hops: 2}},
		{"forwarded obfuscated", fwd, "10.0.0.1:80", hdr{"Forwarded": {`for=198.51.100.7, for=_hidden;proto=https, for=10.0.0.2`}},
			Client{Addr: ap("10.0.0.2:0"), Hops: 1, Proto: "https", Opaque: "_hidden"}},
		{"forwarded unknown", fwd, "10.0.0.1:80", hdr{"Forwarded": {`for=unknown`}},
			Client{Addr: ap("10.0.0.1:80"), Opaque: "unknown"}},
		{"forwarded no for", fwd, "10.0.0.1:80", hdr{"Forwarded": {`proto=https;by=10.0.0.1`}},
			Client{Addr: ap("10.0.0.1:80"), Proto: "https", Opaque: "unknown"}},
		{"forwarded malformed spoof", fwd, "10.0.0.1:80", hdr{"Forwarded": {`for="1.1.1.1, for=198.51.100.2`}},
			Client{Addr: ap("198.51.100.2:0"), Hops: 1}},
		{"forwarded quoted comma spoof", fwd, "10.0.0.1:80", hdr{"Forwarded": {`for="x, for=10.0.0.5", for=198.51.100.3`}},
			Client{Addr: ap("198.51.100.3:0"), Hops: 1}},
		{"forwarded malformed nearest", fwd, "10.0.0.1:80", hdr{"Forwarded": {`for=198.51.100.3, for==`}},
			Client{Addr: ap("10.0.0.1:80"), Opaque: "for=="}},
		{"forwarded duplicate for", fwd, "10.0.0.1:80", hdr{"Forwarded": {`for=198.51.100.3;for=198.51.100.4`}},
			Client{Addr: ap("10.0.0.1:80"), Opaque: "for=198.51.100.3;for=198.51.100.4"}},
		{"forwarded escaped", fwd, "10.0.0.1:80", hdr{"Forwarded": {`for="\[2001:db8:3::1\]";host="a\"b"`}},
			Client{Addr: ap("[2001:db8:3::1]:0"), Hops: 1}},
		{"forwarded escaped close", fwd, "10.0.0.1:80", hdr{"Forwarded": {`for="198.51.100.3\"`}},
			Client{Addr: ap("10.0.0.1:80"), Opaque: `for="198.51.100.3\"`}},
		{"forwarded empty elements", fwd, "10.0.0.1:80", hdr{"Forwarded": {` , for=198.51.100.3 ,, `}},
			Client{Addr: ap("198.51.100.3:0"), Hops: 1}},
		{"forwarded unquoted v6", fwd, "10.0.0.1:80", hdr{"Forwarded": {`for=[2001:db8:3::1]:80`}},
			Client{Addr: ap("[2001:db8:3::1]:80"), Hops: 1}},
		{"forwarded extension", fwd, "10.0.0.1:80", hdr{"Forwarded": {`for=198.51.100.3;secret="a;b,c"`}},
			Client{Addr: ap("198.51.100.3:0"), Hops: 1}},

		{"x-xri-ip", xri, "10.0.0.1:80", hdr{"X-Real-Ip": {"1.1.1.1", "198.51.100.9"}, "X-Forwarded-For": {"2.2.2.2"}},
			Client{Addr: ap("198.51.100.9:0"), Hops: 1}},
		{"x-xri-ip trusted value", xri, "10.0.0.1:80", hdr{"X-Real-Ip": {"10.0.0.7"}},
			Client{Addr: ap("10.0.0.7:0"), Hops: 1}},
		{"x-xri-ip bad", xri, "10.0.0.1:80", hdr{"X-Real-Ip": {"nope"}},
			Client{Addr: ap("10.0.0.1:80"), Opaque: "nope"}},
		{"custom name", &Resolver{Trusted: trusted, Header: HeaderXRealIP, Name: "Cf-Connecting-Ip"}, "10.0.0.1:80", hdr{"Cf-Connecting-Ip": {"198.51.100.9"}, "X-Real-Ip": {"1.1.1.1"}},
			Client{Addr: ap("198.51.100.9:0"), Hops: 1}},
	} {
		got := tt.r.Resolve(ap(tt.peer), tt.header)
		if got != tt.want {
			t.Errorf("%s: Resolve = %+v, want %+v", tt.name, got, tt.want)
		}
	}
}

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

func TestHeaderString(t *testing.T) {
	if HeaderXRealIP.String() != "X-Real-IP" || HeaderForwarded.String() != "Forwarded" || Header(9).String() != "Header(9)" {
		t.Error("Header.String")
	}
}

func TestAppend(t *testing.T) {
	for _, tt := range []struct {
		e    Element
		want string
	}{
		{Element{For: ap("192.0.2.1:0")}, `for=192.0.2.1`},
		{Element{For: ap("192.0.2.1:80"), Proto: "https"}, `for="192.0.2.1:80";proto=https`},
		{Element{For: ap("[2001:db8::1]:0"), By: ap("[::ffff:10.0.0.1]:443"), Host: "example.com:8443"},
			`for="[2001:db8::1]";by="10.0.0.1:443";host="example.com:8443"`},
		{Element{Host: "a\"b\\c\r\n"}, `for=unknown;host="a\"b\\c"`},
		{Element{For: netip.AddrPortFrom(netip.MustParseAddr("fe80::1%eth0"), 9)}, `for="[fe80::1]:9"`},
	} {
		if got := string(AppendElement(nil, tt.e)); got != tt.want {
			t.Errorf("AppendElement(%+v) = %s, want %s", tt.e, got, tt.want)
		}
	}
	if got := string(AppendForwarded(nil, []string{"for=1.1.1.1", " ", "for=2.2.2.2 "}, Element{For: ap("192.0.2.1:0")})); got != "for=1.1.1.1, for=2.2.2.2, for=192.0.2.1" {
		t.Errorf("AppendForwarded = %s", got)
	}
	if got := string(AppendXForwardedFor(nil, []string{"1.1.1.1, 2.2.2.2", "3.3.3.3"}, netip.MustParseAddr("::ffff:192.0.2.1"))); got != "1.1.1.1, 2.2.2.2, 3.3.3.3, 192.0.2.1" {
		t.Errorf("AppendXForwardedFor = %s", got)
	}
	if got := string(AppendXForwardedFor(nil, nil, netip.Addr{})); got != "unknown" {
		t.Errorf("AppendXForwardedFor(invalid) = %s", got)
	}
}

// TestRoundTrip checks that what a proxy appends is read back by a Resolver
// that trusts it.
func TestRoundTrip(t *testing.T) {
	r := &Resolver{Trusted: mustSet(t, "10.0.0.0/8"), Header: HeaderForwarded}
	for _, client := range []string{"192.0.2.1:0", "192.0.2.1:4711", "[2001:db8::1]:0", "[2001:db8::1]:65535"} {
		e := Element{For: ap(client), Proto: "https", Host: "[2001:db8::2]:8443"}
		v := string(AppendForwarded(nil, []string{`for="1.1.1.1, x"`}, e))
		got := r.Resolve(ap("10.0.0.1:1"), map[string][]string{"Forwarded": {v}})
		if got.Addr != ap(client) || got.Proto != "https" || got.Host != e.Host || got.Hops != 1 {
			t.Errorf("%s: read back %+v from %s", client, got, v)
		}
	}
}

func TestResolveAllocs(t *testing.T) {
	trusted := mustSet(t, "10.0.0.0/8", "2001:db8:1::/48")
	h := map[string][]string{
		"X-Forwarded-For":   {"198.51.100.1, 10.0.0.2"},
		"Forwarded":         {`for="[2001:db8:2::1]:4711";proto=https, for=10.0.0.2`},
		"X-Forwarded-Proto": {"https"},
	}
	peer := ap("10.0.0.1:80")
	for _, hd := range []Header{HeaderXForwardedFor, HeaderForwarded, HeaderXRealIP} {
		r := &Resolver{Trusted: trusted, Header: hd}
		if n := testing.AllocsPerRun(100, func() { _ = r.Resolve(peer, h) }); n != 0 {
			t.Errorf("%v: Resolve allocates %v times", hd, n)
		}
	}
	if n := testing.AllocsPerRun(100, func() { _ = AppendElement(make([]byte, 0, 64), Element{For: ap("[2001:db8::1]:1"), Proto: "https"}) }); n > 1 {
		t.Errorf("AppendElement allocates %v times", n)
	}
}

// FuzzResolve checks that the client is the peer or an address of the
// header, that the hops behind it are trusted, and that a trusted proxy's
// element appended to any header is read back.
func FuzzResolve(f *testing.F) {
	for _, s := range []string{
		"198.51.100.1, 10.0.0.2",
		`for="[2001:db8::1]:80";proto=https, for=10.0.0.2`,
		`for="a\"b, for=1.1.1.1`,
		`for=_x;host=h, ,for=unknown`,
		"",
	} {
		f.Add(s, uint8(0))
		f.Add(s, uint8(1))
	}
	trusted := mustSet(f, "10.0.0.0/8", "2001:db8:1::/48")
	f.Fuzz(func(t *testing.T, v string, which uint8) {
		hd := Header(which % 3)
		r := &Resolver{Trusted: trusted, Header: hd}
		peer := ap("10.0.0.1:1")
		h := map[string][]string{hd.key(): {v}, "X-Forwarded-Proto": {v}, "X-Forwarded-Host": {v}}
		c := r.Resolve(peer, h)
		if c.Hops == 0 && c.Addr != peer {
			t.Fatalf("no hops but client %v", c.Addr)
		}
		if c.Hops > strings.Count(v, ",")+1 {
			t.Fatalf("%d hops from %q", c.Hops, v)
		}
		if c.Opaque != "" && c.Hops > 0 && !trusted.Contains(c.Addr.Addr()) {
			t.Fatalf("opaque hop recorded by untrusted %v", c.Addr)
		}
		if c.Proto != "" && !validProto(c.Proto) || c.Host != "" && !validHost(c.Host) {
			t.Fatalf("invalid proto %q or host %q", c.Proto, c.Host)
		}
		if hd != HeaderForwarded {
			return
		}
		e := Element{For: ap("[2001:db8:2::7]:9"), Proto: "https", Host: "example.com"}
		h["Forwarded"] = []string{v, string(AppendElement(nil, e))}
		if c := r.Resolve(peer, h); c.Addr != e.For || c.Hops != 1 || c.Proto != "https" || c.Host != "example.com" {
			t.Fatalf("appended element read as %+v after %q", c, v)
		}
		h["Forwarded"] = []string{string(AppendForwarded(nil, []string{v}, e))}
		if c := r.Resolve(peer, h); c.Addr != e.For || c.Hops != 1 {
			t.Fatalf("joined element read as %+v after %q", c, v)
		}
	})
}

func FuzzParseNode(f *testing.F) {
	for _, s := range []string{"192.0.2.1", "[2001:db8::1]:80", "1.2.3.4:_x", "fe80::1%x", "[::ffff:1.2.3.4]"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		a, ok := ParseNode(s)
		if !ok {
			return
		}
		if a.Addr().Is4In6() || a.Addr().Zone() != "" {
			t.Fatalf("ParseNode(%q) = %v", s, a)
		}
		// What AppendElement writes reads back.
		r := &Resolver{Trusted: mustSet(t, "10.0.0.1"), Header: HeaderForwarded}
		c := r.Resolve(ap("10.0.0.1:1"), map[string][]string{"Forwarded": {string(AppendElement(nil, Element{For: a}))}})
		if c.Addr != a {
			t.Fatalf("node %v read back as %v", a, c.Addr)
		}
	})
}

func BenchmarkResolve(b *testing.B) {
	trusted := mustSet(b, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "2001:db8:1::/48")
	peer := ap("10.0.0.1:80")
	for _, bc := range []struct {
		name string
		hd   Header
		h    map[string][]string
	}{
		{"untrusted", HeaderXForwardedFor, map[string][]string{"X-Forwarded-For": {"198.51.100.1"}}},
		{"xff/1", HeaderXForwardedFor, map[string][]string{"X-Forwarded-For": {"198.51.100.1"}}},
		{"xff/3", HeaderXForwardedFor, map[string][]string{"X-Forwarded-For": {"1.1.1.1, 198.51.100.1, 172.16.0.2, 192.168.1.1"}, "X-Forwarded-Proto": {"https"}}},
		{"forwarded/2", HeaderForwarded, map[string][]string{"Forwarded": {`for="[2001:db8:2::1]:4711";proto=https;host=example.com, for=10.0.0.2`}}},
		{"x-real-ip", HeaderXRealIP, map[string][]string{"X-Real-Ip": {"198.51.100.1"}}},
	} {
		r := &Resolver{Trusted: trusted, Header: bc.hd}
		p := peer
		if bc.name == "untrusted" {
			p = ap("203.0.113.1:80")
		}
		b.Run(bc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				r.Resolve(p, bc.h)
			}
		})
	}
}

func BenchmarkPrefixSetContains(b *testing.B) {
	var entries []string
	for i := range 1000 {
		entries = append(entries, netip.AddrFrom4([4]byte{byte(i >> 4), byte(i << 4), 0, 0}).String()+"/12")
	}
	s := mustSet(b, entries...)
	a := netip.MustParseAddr("200.1.2.3")
	b.ReportAllocs()
	for b.Loop() {
		s.Contains(a)
	}
}
