package tlsconn

import (
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestCanonicalName(t *testing.T) {
	long := strings.Repeat("a", 63)
	tests := []struct {
		in, want string // want "" for ErrInvalidName
	}{
		{"example.com", "example.com"},
		{"Example.COM.", "example.com"},
		{"localhost", "localhost"},
		{"under_score.test", "under_score.test"},
		{"a-b.c1.test", "a-b.c1.test"},
		{"123.example", "123.example"},
		{"a.1b", "a.1b"},
		{long + ".test", long + ".test"},
		{"bücher.test", "xn--bcher-kva.test"},
		{"BÜCHER.Test.", "xn--bcher-kva.test"},
		{"münchen.de", "xn--mnchen-3ya.de"},
		{"ü.test", "xn--tda.test"},
		{"例え.テスト", "xn--r8jz45g.xn--zckzah"},
		{"xn--bcher-kva.test", "xn--bcher-kva.test"},
		{"Kelvin.test", "kelvin.test"}, // KELVIN SIGN lowercases to k
		{"", ""},
		{".", ""},
		{"..", ""},
		{"a..b", ""},
		{".a.b", ""},
		{"a.b..", ""},
		{"*.example.com", ""},
		{"*", ""},
		{"-a.test", ""},
		{"a-.test", ""},
		{"a b.test", ""},
		{"a/b.test", ""},
		{long + "a.test", ""},
		{strings.Repeat(long+".", 4) + "ab", ""}, // 254 bytes
		{strings.Repeat("ü", 64) + ".test", ""},
		{"\xff.test", ""},
		{"1.2.3.4", ""},
		{"::1", ""},
		{"a.123", ""},
		{"1.2.3", ""},
	}
	for _, tt := range tests {
		got, err := CanonicalName(tt.in)
		if tt.want == "" {
			if !errors.Is(err, ErrInvalidName) {
				t.Errorf("CanonicalName(%q) = %q, %v, want ErrInvalidName", tt.in, got, err)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("CanonicalName(%q) = %q, %v, want %q", tt.in, got, err, tt.want)
			continue
		}
		if again, err := CanonicalName(got); err != nil || again != got {
			t.Errorf("CanonicalName(%q) = %q, %v, not idempotent", got, again, err)
		}
	}
	if got, err := CanonicalName(strings.Repeat(long+".", 3) + strings.Repeat("a", 61)); err != nil || len(got) != 253 {
		t.Errorf("CanonicalName(253 bytes) = %d bytes, %v", len(got), err)
	}
}

// namesCert has the names the coverage tests check, valid and not.
func namesCert(t testing.TB) *x509.Certificate {
	t.Helper()
	tmpl := leafTmpl("192.0.2.1", "2001:db8::1")
	tmpl.DNSNames = []string{
		"Example.COM.",
		"*.wild.test",
		"*.WILD2.test.",
		"*.com",
		"*",
		"f*.bad.test",
		"*f.bad.test",
		"a.*.bad.test",
		"*.*.deep.test",
		"1.2.3.4",
		"xn--bcher-kva.test",
		"under_score.test",
		"-bad.test",
		"a..b.test",
	}
	tmpl.Subject = pkix.Name{CommonName: "cn-only.test"}
	return newTestCert(t, tmpl, nil, testECKey(t, elliptic.P256()), nil)
}

func TestCovers(t *testing.T) {
	cert := namesCert(t)
	tests := []struct {
		name string
		want bool
	}{
		{"example.com", true},
		{"EXAMPLE.com.", true},
		{"www.example.com", false},
		{"com", false},
		{"a.wild.test", true},
		{"A.Wild.Test", true},
		{"ü.wild.test", true},
		{"xn--tda.wild.test", true},
		{"_srv.wild.test", true},
		{"wild.test", false},
		{"a.b.wild.test", false},
		{".wild.test", false},
		{"*.wild.test", false},
		{"x.wild2.test", true},
		{"x.com", false},
		{"fa.bad.test", false},
		{"af.bad.test", false},
		{"a.x.bad.test", false},
		{"a.b.deep.test", false},
		{"a.deep.test", false},
		{"bücher.test", true},
		{"BÜCHER.test", true},
		{"xn--bcher-kva.test", true},
		{"under_score.test", true},
		{"bad.test", false},
		{"cn-only.test", false},
		{"192.0.2.1", true},
		{"::ffff:192.0.2.1", true},
		{"2001:db8::1", true},
		{"2001:DB8:0::1", true},
		{"2001:db8::1%eth0", false},
		{"1.2.3.4", false},
		{"192.0.2.2", false},
		{"", false},
		{".", false},
		{"\xff", false},
	}
	names := CertNames(cert)
	for _, tt := range tests {
		if got := Covers(cert, tt.name); got != tt.want {
			t.Errorf("Covers(%q) = %t, want %t", tt.name, got, tt.want)
		}
		if got := names.Covers(tt.name); got != tt.want {
			t.Errorf("Names.Covers(%q) = %t, want %t", tt.name, got, tt.want)
		}
	}
	if Covers(nil, "example.com") || (Names{}).Covers("example.com") {
		t.Error("nothing covers a name")
	}
	wantDNS := []string{"example.com", "under_score.test", "xn--bcher-kva.test"}
	wantWild := []string{"*.wild.test", "*.wild2.test"}
	wantInvalid := []string{"*.com", "*", "f*.bad.test", "*f.bad.test", "a.*.bad.test", "*.*.deep.test", "1.2.3.4", "-bad.test", "a..b.test"}
	if !slices.Equal(names.DNS, wantDNS) || !slices.Equal(names.Wildcards, wantWild) || !slices.Equal(names.Invalid, wantInvalid) || len(names.IPs) != 2 {
		t.Errorf("CertNames() = %+v", names)
	}
	if !names.IPs[0].Is4() || names.IPs[0].String() != "192.0.2.1" || names.IPs[1].String() != "2001:db8::1" {
		t.Errorf("CertNames() IPs = %v", names.IPs)
	}
}

// The common name is never used, with or without other names.
func TestCoversIgnoresCommonName(t *testing.T) {
	tmpl := &x509.Certificate{Subject: pkix.Name{CommonName: "cn.test"}}
	cert := newTestCert(t, tmpl, nil, testECKey(t, elliptic.P256()), nil)
	if Covers(cert, "cn.test") || len(CertNames(cert).DNS) != 0 {
		t.Fatal("Covers() uses the common name of a certificate without alternative names")
	}
}

// A hand-built certificate with names x509 would not parse covers nothing
// by them.
func TestCoversNonASCIISAN(t *testing.T) {
	cert := &x509.Certificate{DNSNames: []string{"bücher.test", "*.ü.test"}, IPAddresses: []net.IP{{1, 2}}}
	if Covers(cert, "bücher.test") || Covers(cert, "a.ü.test") {
		t.Fatal("Covers() matches a non-ASCII alternative name")
	}
	if n := CertNames(cert); len(n.Invalid) != 2 || len(n.IPs) != 0 {
		t.Fatalf("CertNames() = %+v", n)
	}
}

func TestUnder(t *testing.T) {
	key := testECKey(t, elliptic.P256())
	mk := func(names ...string) Names { return CertNames(newTestCert(t, leafTmpl(names...), nil, key, nil)) }
	tests := []struct {
		name     string
		names    Names
		domain   string
		apex     bool
		byWild   bool
		subs     []string
		wild     []string
		covers   []string
		uncovers []string
	}{
		{
			name: "exact apex", names: mk("example.com"), domain: "example.com", apex: true,
			covers: []string{"example.com"}, uncovers: []string{"www.example.com", "a.b.example.com"},
		},
		{
			name: "wildcard is not the apex", names: mk("*.example.com"), domain: "Example.com.",
			wild:     []string{"*.example.com"},
			covers:   []string{"a.example.com", "www.example.com"},
			uncovers: []string{"example.com", "a.b.example.com", "other.test"},
		},
		{
			name: "wildcard for the parent", names: mk("*.example.com"), domain: "a.example.com", apex: true, byWild: true,
			covers: []string{"a.example.com"}, uncovers: []string{"b.a.example.com", "b.example.com", "example.com"},
		},
		{
			name: "mixed", names: mk("example.com", "www.example.com", "*.api.example.com", "other.test", "notexample.com", "*.example.org"),
			domain: "example.com", apex: true,
			subs: []string{"www.example.com"}, wild: []string{"*.api.example.com"},
			covers:   []string{"example.com", "www.example.com", "v1.api.example.com"},
			uncovers: []string{"api.example.com", "a.v1.api.example.com", "other.test", "notexample.com", "a.example.org", "mail.example.com"},
		},
		{
			name: "suffix is not a parent", names: mk("example.com", "*.example.com"), domain: "xample.com",
			uncovers: []string{"example.com", "a.example.com"},
		},
		{
			name: "subdomains only", names: mk("a.example.com", "b.example.com"), domain: "example.com",
			subs: []string{"a.example.com", "b.example.com"}, covers: []string{"a.example.com"}, uncovers: []string{"example.com", "c.example.com"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := tt.names.Under(tt.domain)
			if err != nil {
				t.Fatal(err)
			}
			if c.Apex != tt.apex || c.ApexByWildcard != tt.byWild || !slices.Equal(c.Subdomains, tt.subs) || !slices.Equal(c.Wildcards, tt.wild) {
				t.Fatalf("Under(%q) = %+v", tt.domain, c)
			}
			if c.Empty() != (!tt.apex && len(tt.subs) == 0 && len(tt.wild) == 0) {
				t.Fatalf("Under(%q).Empty() = %t", tt.domain, c.Empty())
			}
			for _, n := range tt.covers {
				if !c.Covers(n) {
					t.Errorf("Covers(%q) = false", n)
				}
				if !tt.names.Covers(n) {
					t.Errorf("Names.Covers(%q) = false for a name the coverage covers", n)
				}
			}
			for _, n := range tt.uncovers {
				if c.Covers(n) {
					t.Errorf("Covers(%q) = true", n)
				}
			}
		})
	}
	if _, err := mk("example.com").Under("*.example.com"); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("Under(wildcard) = %v", err)
	}
	if (DomainCoverage{}).Covers("example.com") {
		t.Fatal("zero DomainCoverage covers a name")
	}
}

func TestVerifyDomain(t *testing.T) {
	p := newTestPKI(t)
	key := testECKey(t, elliptic.P256())
	opts := VerifyOptions{Roots: p.roots}
	wild := p.leaf(t, key, "*.example.com", "example.com")
	c, err := VerifyDomain([]*x509.Certificate{wild, p.inter}, "example.com", opts)
	if err != nil || !c.Apex || !slices.Equal(c.Wildcards, []string{"*.example.com"}) {
		t.Fatalf("VerifyDomain() = %+v, %v", c, err)
	}
	if _, err := VerifyDomain([]*x509.Certificate{wild, p.inter}, "other.test", opts); !errors.Is(err, ErrNotCovered) {
		t.Fatalf("VerifyDomain(other domain) = %v", err)
	}
	// A certificate for names under a domain does not prove the domain, also
	// not a suffix that many users share.
	sub := p.leaf(t, key, "me.shared.test", "*.api.example.com")
	for _, d := range []string{"shared.test", "test", "example.com", "api.example.com"} {
		c, err := VerifyDomain([]*x509.Certificate{sub, p.inter}, d, opts)
		if !errors.Is(err, ErrOnlySubdomains) || c.Apex || c.Empty() {
			t.Errorf("VerifyDomain(%q) = %+v, %v, want ErrOnlySubdomains with the coverage", d, c, err)
		}
	}
	if c, err := VerifyDomain([]*x509.Certificate{sub, p.inter}, "me.shared.test", opts); err != nil || !c.Apex || c.ApexByWildcard {
		t.Errorf("VerifyDomain(exact) = %+v, %v", c, err)
	}
	if c, err := VerifyDomain([]*x509.Certificate{sub, p.inter}, "v1.api.example.com", opts); err != nil || !c.ApexByWildcard || c.Covers("a.v1.api.example.com") {
		t.Errorf("VerifyDomain(by wildcard) = %+v, %v", c, err)
	}
	self := newTestCert(t, leafTmpl("example.com"), nil, key, nil)
	if _, err := VerifyDomain([]*x509.Certificate{self}, "example.com", opts); !errors.Is(err, ErrSelfSigned) {
		t.Fatalf("VerifyDomain(self-signed) = %v", err)
	}
	expired := leafTmpl("example.com")
	expired.NotBefore, expired.NotAfter = time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour)
	old := newTestCert(t, expired, p.inter, key, p.interKey)
	if _, err := VerifyDomain([]*x509.Certificate{old, p.inter}, "example.com", opts); !errors.Is(err, ErrExpired) {
		t.Fatalf("VerifyDomain(expired) = %v", err)
	}
	if _, err := VerifyDomain([]*x509.Certificate{wild, p.inter}, "1.2.3.4", opts); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("VerifyDomain(IP) = %v", err)
	}
	if _, err := VerifyDomain(nil, "example.com", opts); !errors.Is(err, ErrNoCertificates) {
		t.Fatalf("VerifyDomain(nil) = %v", err)
	}
}

func BenchmarkCovers(b *testing.B) {
	names := make([]string, 0, 100)
	for i := range 98 {
		names = append(names, "host"+strings.Repeat("x", i%7)+string('a'+rune(i%26))+".example.com")
	}
	names = append(names, "*.wild.example.com", "exact.example.com")
	cert := newTestCert(b, leafTmpl(names...), nil, testECKey(b, elliptic.P256()), nil)
	n := CertNames(cert)
	for _, bc := range []struct{ name, host string }{
		{"exact", "exact.example.com"},
		{"wildcard", "a.wild.example.com"},
		{"miss", "nothere.example.org"},
		{"IP", "192.0.2.1"},
	} {
		b.Run("cert/"+bc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				Covers(cert, bc.host)
			}
		})
		b.Run("names/"+bc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				n.Covers(bc.host)
			}
		})
	}
}
