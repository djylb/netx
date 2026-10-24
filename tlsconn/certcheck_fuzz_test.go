package tlsconn

import (
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"unicode/utf8"
)

func FuzzParseCertificates(f *testing.F) {
	p := newTestPKI(f)
	leaf := p.leaf(f, testECKey(f, elliptic.P256()), "example.com", "*.example.com")
	f.Add(certPEM(leaf, p.inter))
	f.Add(append(append([]byte(nil), leaf.Raw...), p.inter.Raw...))
	f.Add([]byte("junk\n-----BEGIN CERTIFICATE-----\nMA==\n-----END CERTIFICATE-----\n"))
	f.Add([]byte{0x30, 0x80})
	f.Fuzz(func(t *testing.T, data []byte) {
		certs, err := ParseCertificates(data)
		if err != nil {
			return
		}
		if len(certs) == 0 {
			t.Fatal("ParseCertificates() returned no certificates and no error")
		}
		for _, c := range certs {
			n := CertNames(c)
			for _, d := range n.DNS {
				if !Covers(c, d) || !n.Covers(d) {
					t.Fatalf("certificate does not cover its name %q", d)
				}
			}
			_ = Summarize(c)
		}
	})
}

func FuzzParsePrivateKey(f *testing.F) {
	rsaKey := testRSAKey(f)
	ecKey := testECKey(f, elliptic.P256())
	sec1, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(x509.MarshalPKCS1PrivateKey(rsaKey))
	f.Add(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1}))
	f.Add(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8(f, testEd25519Key(f))}))
	f.Add([]byte("-----BEGIN PRIVATE KEY-----\nMAA=\n-----END PRIVATE KEY-----\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		key, err := ParsePrivateKey(data)
		if err != nil {
			return
		}
		if key == nil || key.Public() == nil {
			t.Fatal("ParsePrivateKey() returned no key and no error")
		}
	})
}

// Covers agrees with Names.Covers, and CanonicalName is idempotent and
// returns lowercase ASCII.
func FuzzCovers(f *testing.F) {
	for _, s := range [][2]string{
		{"*.example.com", "a.example.com"},
		{"Example.COM.", "example.com"},
		{"xn--bcher-kva.test", "bücher.test"},
		{"*.com", "a.com"},
		{"a..b", "a..b"},
		{"*.a.b", "*.a.b"},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, san, name string) {
		cert := &x509.Certificate{DNSNames: []string{san}}
		got := Covers(cert, name)
		if n := CertNames(cert); n.Covers(name) != got {
			t.Fatalf("Covers(%q, %q) = %t, Names.Covers = %t", san, name, got, !got)
		}
		c, err := CanonicalName(name)
		if err != nil {
			if got {
				t.Fatalf("Covers(%q, %q) = true for a name CanonicalName rejects", san, name)
			}
			return
		}
		for i := 0; i < len(c); i++ {
			if c[i] >= utf8.RuneSelf || c[i] >= 'A' && c[i] <= 'Z' {
				t.Fatalf("CanonicalName(%q) = %q, not lowercase ASCII", name, c)
			}
		}
		if again, err := CanonicalName(c); err != nil || again != c {
			t.Fatalf("CanonicalName(%q) = %q, %v, not idempotent", c, again, err)
		}
		if Covers(cert, c) != got {
			t.Fatalf("Covers(%q) differs from Covers(%q)", c, name)
		}
	})
}
