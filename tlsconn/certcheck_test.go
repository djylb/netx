package tlsconn

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

var (
	rsaKeyOnce sync.Once
	rsaKeyVal  *rsa.PrivateKey
	rsaKeyErr  error
)

// testRSAKey returns one RSA 2048 key for the whole test binary, since
// generating it is slow, above all on wasm.
func testRSAKey(t testing.TB) *rsa.PrivateKey {
	t.Helper()
	rsaKeyOnce.Do(func() { rsaKeyVal, rsaKeyErr = rsa.GenerateKey(rand.Reader, 2048) })
	if rsaKeyErr != nil {
		t.Fatal(rsaKeyErr)
	}
	return rsaKeyVal
}

func testECKey(t testing.TB, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func testEd25519Key(t testing.TB) ed25519.PrivateKey {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// newTestCert signs tmpl for key with parent and parentKey, or self-signs it
// when parent is nil, filling in a serial number and, when unset, a validity
// from an hour ago to a day ahead and server authentication.
func newTestCert(t testing.TB, tmpl, parent *x509.Certificate, key, parentKey crypto.Signer) *x509.Certificate {
	t.Helper()
	if tmpl.SerialNumber == nil {
		serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
		if err != nil {
			t.Fatal(err)
		}
		tmpl.SerialNumber = serial
	}
	if tmpl.NotBefore.IsZero() {
		tmpl.NotBefore = time.Now().Add(-time.Hour)
	}
	if tmpl.NotAfter.IsZero() {
		tmpl.NotAfter = time.Now().Add(24 * time.Hour)
	}
	if !tmpl.IsCA && tmpl.ExtKeyUsage == nil {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func caTemplate(name string) *x509.Certificate {
	return &x509.Certificate{
		Subject:               pkix.Name{CommonName: name},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
}

// testPKI is a root and an intermediate CA under it.
type testPKI struct {
	root, inter       *x509.Certificate
	rootKey, interKey crypto.Signer
	roots             *x509.CertPool
}

func newTestPKI(t testing.TB) *testPKI {
	t.Helper()
	p := &testPKI{rootKey: testECKey(t, elliptic.P256()), interKey: testECKey(t, elliptic.P256())}
	rootTmpl := caTemplate("Test Root")
	rootTmpl.NotBefore, rootTmpl.NotAfter = time.Now().Add(-30*24*time.Hour), time.Now().Add(365*24*time.Hour)
	p.root = newTestCert(t, rootTmpl, nil, p.rootKey, nil)
	interTmpl := caTemplate("Test Intermediate")
	interTmpl.NotBefore, interTmpl.NotAfter = time.Now().Add(-30*24*time.Hour), time.Now().Add(300*24*time.Hour)
	p.inter = newTestCert(t, interTmpl, p.root, p.interKey, p.rootKey)
	p.roots = x509.NewCertPool()
	p.roots.AddCert(p.root)
	return p
}

// leaf issues a leaf for names from the intermediate.
func (p *testPKI) leaf(t testing.TB, key crypto.Signer, names ...string) *x509.Certificate {
	t.Helper()
	return newTestCert(t, leafTmpl(names...), p.inter, key, p.interKey)
}

func leafTmpl(names ...string) *x509.Certificate {
	tmpl := &x509.Certificate{KeyUsage: x509.KeyUsageDigitalSignature}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	return tmpl
}

func certPEM(certs ...*x509.Certificate) []byte {
	var out []byte
	for _, c := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return out
}

func keyPEM(t testing.TB, typ string, der []byte) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func pkcs8(t testing.TB, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestParseKeyPairForms(t *testing.T) {
	p := newTestPKI(t)
	rsaKey := testRSAKey(t)
	ecKey := testECKey(t, elliptic.P384())
	edKey := testEd25519Key(t)
	ecSEC1, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		key    crypto.Signer
		keyPEM []byte
	}{
		{"RSA PKCS1", rsaKey, keyPEM(t, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaKey))},
		{"RSA PKCS8", rsaKey, keyPEM(t, "PRIVATE KEY", pkcs8(t, rsaKey))},
		{"ECDSA SEC1", ecKey, keyPEM(t, "EC PRIVATE KEY", ecSEC1)},
		{"ECDSA SEC1 with parameters", ecKey, append(keyPEM(t, "EC PARAMETERS", []byte{6, 5, 43, 129, 4, 0, 34}), keyPEM(t, "EC PRIVATE KEY", ecSEC1)...)},
		{"ECDSA PKCS8", ecKey, keyPEM(t, "PRIVATE KEY", pkcs8(t, ecKey))},
		{"Ed25519 PKCS8", edKey, keyPEM(t, "PRIVATE KEY", pkcs8(t, edKey))},
		{"mislabeled block", ecKey, keyPEM(t, "RSA PRIVATE KEY", pkcs8(t, ecKey))},
		{"DER PKCS1", rsaKey, x509.MarshalPKCS1PrivateKey(rsaKey)},
		{"DER SEC1", ecKey, ecSEC1},
		{"DER PKCS8", edKey, pkcs8(t, edKey)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			leaf := p.leaf(t, tt.key, "example.com")
			for _, chain := range [][]byte{
				certPEM(leaf, p.inter),
				append([]byte("Bag Attributes\n    localKeyID: 01\nsubject=CN = example.com\n"), certPEM(leaf, p.inter)...),
				append(append([]byte(nil), leaf.Raw...), p.inter.Raw...),
			} {
				cert, err := ParseKeyPair(chain, tt.keyPEM)
				if err != nil {
					t.Fatalf("ParseKeyPair() = %v", err)
				}
				if len(cert.Certificate) != 2 || cert.Leaf == nil || !bytes.Equal(cert.Leaf.Raw, leaf.Raw) || !bytes.Equal(cert.Certificate[1], p.inter.Raw) {
					t.Fatalf("ParseKeyPair() chain = %d certificates, leaf set %t", len(cert.Certificate), cert.Leaf != nil)
				}
				if signer, ok := cert.PrivateKey.(crypto.Signer); !ok || !tt.key.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(signer.Public()) {
					t.Fatalf("ParseKeyPair() key = %T, want the key", cert.PrivateKey)
				}
				if _, err := VerifyCertificate(&cert, VerifyOptions{Roots: p.roots}); err != nil {
					t.Fatalf("VerifyCertificate() = %v", err)
				}
			}
		})
	}
}

// One file holding the chain and the key serves as both arguments, and
// the result works in a TLS handshake.
func TestParseKeyPairCombinedFile(t *testing.T) {
	cert, err := NewSelfSigned(SelfSignedOptions{Hosts: []string{"combined.test"}})
	if err != nil {
		t.Fatal(err)
	}
	c, k, err := EncodePEM(cert)
	if err != nil {
		t.Fatal(err)
	}
	both := append(append([]byte(nil), k...), c...)
	got, err := ParseKeyPair(both, both)
	if err != nil {
		t.Fatalf("ParseKeyPair(combined) = %v", err)
	}
	if _, err := tls.X509KeyPair(c, k); err != nil {
		t.Fatal(err)
	}
	if got.Leaf == nil || !Covers(got.Leaf, "combined.test") {
		t.Fatal("ParseKeyPair(combined) leaf does not cover its name")
	}
}

func TestParseErrors(t *testing.T) {
	p := newTestPKI(t)
	key := testECKey(t, elliptic.P256())
	other := testECKey(t, elliptic.P256())
	leaf := p.leaf(t, key, "example.com")
	goodKey := keyPEM(t, "PRIVATE KEY", pkcs8(t, key))
	x25519, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encrypted := pem.EncodeToMemory(&pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-128-CBC,00"},
		Bytes:   []byte{1, 2, 3},
	})
	tests := []struct {
		name      string
		cert, key []byte
		want      error
	}{
		{"empty certificate", nil, goodKey, ErrNoCertificates},
		{"white space certificate", []byte(" \n"), goodKey, ErrNoCertificates},
		{"key only", goodKey, goodKey, ErrNoCertificates},
		{"bad DER certificate", []byte{0x30, 0x03, 1, 2, 3}, goodKey, ErrInvalidCertificate},
		{"bad PEM certificate", keyPEM(t, "CERTIFICATE", []byte("junk")), goodKey, ErrInvalidCertificate},
		{"bad second certificate", append(certPEM(leaf), keyPEM(t, "CERTIFICATE", []byte("junk"))...), goodKey, ErrInvalidCertificate},
		{"no key", certPEM(leaf), certPEM(leaf), ErrNoPrivateKey},
		{"empty key", certPEM(leaf), nil, ErrNoPrivateKey},
		{"two keys", certPEM(leaf), append(append([]byte(nil), goodKey...), goodKey...), ErrMultipleKeys},
		{"PKCS8 encrypted", certPEM(leaf), keyPEM(t, "ENCRYPTED PRIVATE KEY", []byte{1}), ErrEncryptedKey},
		{"legacy encrypted", certPEM(leaf), encrypted, ErrEncryptedKey},
		{"X25519 key", certPEM(leaf), keyPEM(t, "PRIVATE KEY", pkcs8(t, x25519)), ErrUnsupportedKey},
		{"bad PEM key", certPEM(leaf), keyPEM(t, "PRIVATE KEY", []byte("junk")), ErrInvalidKey},
		{"bad DER key", certPEM(leaf), []byte{0x30, 0x01, 0}, ErrInvalidKey},
		{"other key", certPEM(leaf), keyPEM(t, "PRIVATE KEY", pkcs8(t, other)), ErrKeyMismatch},
		{"leaf not first", certPEM(p.inter, leaf), goodKey, ErrKeyMismatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseKeyPair(tt.cert, tt.key); !errors.Is(err, tt.want) {
				t.Fatalf("ParseKeyPair() = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestMatchKey(t *testing.T) {
	key := testEd25519Key(t)
	leaf := newTestCert(t, leafTmpl("ed.test"), nil, key, nil)
	if err := MatchKey(leaf, key); err != nil {
		t.Fatalf("MatchKey(own key) = %v", err)
	}
	if err := MatchKey(leaf, &key); err != nil {
		t.Fatalf("MatchKey(pointer to own key) = %v", err)
	}
	if err := MatchKey(leaf, testEd25519Key(t)); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("MatchKey(other Ed25519 key) = %v", err)
	}
	if err := MatchKey(leaf, testECKey(t, elliptic.P256())); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("MatchKey(ECDSA key) = %v", err)
	}
	if err := MatchKey(leaf, "not a key"); !errors.Is(err, ErrUnsupportedKey) {
		t.Fatalf("MatchKey(string) = %v", err)
	}
	if err := MatchKey(leaf, nil); !errors.Is(err, ErrUnsupportedKey) {
		t.Fatalf("MatchKey(nil) = %v", err)
	}
	if err := MatchKey(nil, key); !errors.Is(err, ErrNoCertificates) {
		t.Fatalf("MatchKey(nil leaf) = %v", err)
	}
}

func TestVerifyChain(t *testing.T) {
	p := newTestPKI(t)
	key := testECKey(t, elliptic.P256())
	leaf := p.leaf(t, key, "example.com")
	unrelated := newTestCert(t, caTemplate("Unrelated"), nil, testECKey(t, elliptic.P256()), nil)

	chains, err := VerifyChain([]*x509.Certificate{leaf, unrelated, p.inter}, VerifyOptions{Roots: p.roots})
	if err != nil {
		t.Fatalf("VerifyChain() = %v", err)
	}
	if len(chains) != 1 || len(chains[0]) != 3 || chains[0][2] != p.root {
		t.Fatalf("VerifyChain() chains = %v", chains)
	}

	expired := leafTmpl("example.com")
	expired.NotBefore, expired.NotAfter = time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour)
	expiredLeaf := newTestCert(t, expired, p.inter, key, p.interKey)
	future := leafTmpl("example.com")
	future.NotBefore, future.NotAfter = time.Now().Add(24*time.Hour), time.Now().Add(48*time.Hour)
	futureLeaf := newTestCert(t, future, p.inter, key, p.interKey)
	clientTmpl := leafTmpl("example.com")
	clientTmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	clientLeaf := newTestCert(t, clientTmpl, p.inter, key, p.interKey)
	selfSigned := newTestCert(t, leafTmpl("example.com"), nil, key, nil)
	selfRoots := x509.NewCertPool()
	selfRoots.AddCert(selfSigned)
	oldInterTmpl := caTemplate("Expired Intermediate")
	oldInterTmpl.NotBefore, oldInterTmpl.NotAfter = time.Now().Add(-48*time.Hour), time.Now().Add(-time.Minute)
	oldInterKey := testECKey(t, elliptic.P256())
	oldInter := newTestCert(t, oldInterTmpl, p.root, oldInterKey, p.rootKey)
	underOld := newTestCert(t, leafTmpl("example.com"), oldInter, key, oldInterKey)
	constrainedTmpl := caTemplate("Constrained")
	constrainedTmpl.PermittedDNSDomains = []string{"allowed.test"}
	constrainedKey := testECKey(t, elliptic.P256())
	constrained := newTestCert(t, constrainedTmpl, p.root, constrainedKey, p.rootKey)
	outside := newTestCert(t, leafTmpl("other.test"), constrained, key, constrainedKey)

	tests := []struct {
		name  string
		chain []*x509.Certificate
		opts  VerifyOptions
		want  []error // nil: success
		not   []error
	}{
		{"no intermediate", []*x509.Certificate{leaf}, VerifyOptions{Roots: p.roots}, []error{ErrUnknownAuthority}, []error{ErrSelfSigned}},
		{"uploaded root is not trusted", []*x509.Certificate{leaf, p.inter, p.root}, VerifyOptions{Roots: x509.NewCertPool()}, []error{ErrUnknownAuthority}, nil},
		{"expired", []*x509.Certificate{expiredLeaf, p.inter}, VerifyOptions{Roots: p.roots}, []error{ErrExpired}, []error{ErrNotYetValid}},
		{"expired at a past time", []*x509.Certificate{expiredLeaf, p.inter}, VerifyOptions{Roots: p.roots, Time: time.Now().Add(-36 * time.Hour)}, nil, nil},
		{"not yet valid", []*x509.Certificate{futureLeaf, p.inter}, VerifyOptions{Roots: p.roots}, []error{ErrNotYetValid}, []error{ErrExpired}},
		{"expired intermediate", []*x509.Certificate{underOld, oldInter}, VerifyOptions{Roots: p.roots}, []error{ErrExpired}, nil},
		{"client certificate", []*x509.Certificate{clientLeaf, p.inter}, VerifyOptions{Roots: p.roots}, []error{ErrKeyUsage}, nil},
		{"client certificate for client auth", []*x509.Certificate{clientLeaf, p.inter}, VerifyOptions{Roots: p.roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, nil, nil},
		{"self-signed", []*x509.Certificate{selfSigned}, VerifyOptions{Roots: p.roots}, []error{ErrSelfSigned, ErrUnknownAuthority}, nil},
		{"self-signed trusted", []*x509.Certificate{selfSigned}, VerifyOptions{Roots: selfRoots}, nil, nil},
		{"name constraint", []*x509.Certificate{outside, constrained}, VerifyOptions{Roots: p.roots}, []error{ErrInvalidChain}, nil},
		{"empty", nil, VerifyOptions{Roots: p.roots}, []error{ErrNoCertificates}, nil},
		{"nil leaf", []*x509.Certificate{nil}, VerifyOptions{Roots: p.roots}, []error{ErrNoCertificates}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := VerifyChain(tt.chain, tt.opts)
			if tt.want == nil && err != nil {
				t.Fatalf("VerifyChain() = %v", err)
			}
			for _, w := range tt.want {
				if !errors.Is(err, w) {
					t.Errorf("VerifyChain() = %v, want %v", err, w)
				}
			}
			for _, n := range tt.not {
				if errors.Is(err, n) {
					t.Errorf("VerifyChain() = %v, also matches %v", err, n)
				}
			}
		})
	}
}

func TestVerifyCertificateErrors(t *testing.T) {
	if _, err := VerifyCertificate(nil, VerifyOptions{}); !errors.Is(err, ErrNoCertificates) {
		t.Fatalf("VerifyCertificate(nil) = %v", err)
	}
	if _, err := VerifyCertificate(&tls.Certificate{Certificate: [][]byte{{1}}}, VerifyOptions{}); !errors.Is(err, ErrInvalidCertificate) {
		t.Fatalf("VerifyCertificate(bad leaf) = %v", err)
	}
	cert, err := NewSelfSigned(SelfSignedOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cert.Certificate = append(cert.Certificate, []byte{1})
	if _, err := VerifyCertificate(&cert, VerifyOptions{}); !errors.Is(err, ErrInvalidCertificate) {
		t.Fatalf("VerifyCertificate(bad intermediate) = %v", err)
	}
}

func TestIsSelfSigned(t *testing.T) {
	p := newTestPKI(t)
	self, err := NewSelfSigned(SelfSignedOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !IsSelfSigned(self.Leaf) || !IsSelfSigned(p.root) {
		t.Fatal("IsSelfSigned() = false for a self-signed certificate")
	}
	if IsSelfSigned(p.inter) || IsSelfSigned(p.leaf(t, testECKey(t, elliptic.P256()), "a.test")) || IsSelfSigned(nil) {
		t.Fatal("IsSelfSigned() = true for an issued certificate")
	}
	// Same subject and issuer, signed by another key.
	tmpl := caTemplate("Twin")
	twinKey := testECKey(t, elliptic.P256())
	twin := newTestCert(t, tmpl, nil, twinKey, nil)
	impostor := newTestCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "Twin"}}, twin, testECKey(t, elliptic.P256()), twinKey)
	if IsSelfSigned(impostor) {
		t.Fatal("IsSelfSigned() = true for a certificate whose subject is its issuer's")
	}
}

func TestSummarize(t *testing.T) {
	p := newTestPKI(t)
	tests := []struct {
		key  crypto.Signer
		typ  string
		bits int
	}{
		{testRSAKey(t), "RSA", 2048},
		{testECKey(t, elliptic.P256()), "ECDSA P-256", 256},
		{testECKey(t, elliptic.P521()), "ECDSA P-521", 521},
		{testEd25519Key(t), "Ed25519", 256},
	}
	for _, tt := range tests {
		leaf := p.leaf(t, tt.key, "b.example.com", "*.example.com", "192.0.2.1")
		s := Summarize(leaf)
		if s.KeyType != tt.typ || s.KeyBits != tt.bits {
			t.Errorf("Summarize() key = %s %d, want %s %d", s.KeyType, s.KeyBits, tt.typ, tt.bits)
		}
		if s.Fingerprint != Fingerprint(leaf.Raw) || s.SelfSigned || s.IsCA || s.Issuer != "CN=Test Intermediate" {
			t.Errorf("Summarize() = %+v", s)
		}
		if len(s.Names.DNS) != 1 || len(s.Names.Wildcards) != 1 || len(s.Names.IPs) != 1 || s.SerialNumber == "" {
			t.Errorf("Summarize() names = %+v", s.Names)
		}
		if !s.NotBefore.Equal(leaf.NotBefore) || !s.NotAfter.Equal(leaf.NotAfter) {
			t.Errorf("Summarize() validity = %v..%v", s.NotBefore, s.NotAfter)
		}
	}
	if s := Summarize(p.root); !s.IsCA || !s.SelfSigned || s.Subject != "CN=Test Root" {
		t.Errorf("Summarize(root) = %+v", s)
	}
	if s := Summarize(nil); s.KeyType != "" {
		t.Errorf("Summarize(nil) = %+v", s)
	}
}
