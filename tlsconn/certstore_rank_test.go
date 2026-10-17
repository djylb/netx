package tlsconn

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"
)

// testCA is a certificate authority for tests.
type testCA struct {
	cert  *x509.Certificate
	key   crypto.Signer
	roots *x509.CertPool
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return &testCA{cert: cert, key: key, roots: roots}
}

var serial int64 = 100

// makeCert returns a certificate for hosts valid from notBefore to
// notAfter, issued by ca, or self-signed if ca is nil, with key, or a new
// ECDSA key if nil.
func makeCert(t *testing.T, ca *testCA, key crypto.Signer, notBefore, notAfter time.Time, hosts ...string) *tls.Certificate {
	t.Helper()
	if key == nil {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key = k
	}
	serial++
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: hosts[0]},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	parent, signer := tmpl, key
	if ca != nil {
		parent, signer = ca.cert, ca.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	cert := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	if ca != nil {
		cert.Certificate = append(cert.Certificate, ca.cert.Raw)
	}
	return cert
}

// pick returns the ID of the certificate s serves for hello.
func pick(t *testing.T, s *CertStore, hello *tls.ClientHelloInfo) string {
	t.Helper()
	c, err := s.certificate(context.Background(), hello)
	if err != nil {
		return "error: " + err.Error()
	}
	for _, info := range s.List() {
		if got, _ := s.Certificate(info.ID); sameLeaf(got, c) {
			return info.ID
		}
	}
	return "unknown"
}

func hello(name string) *tls.ClientHelloInfo { return &tls.ClientHelloInfo{ServerName: name} }

// The ranking: issued by an authority over self-signed, outranking exact
// over wildcard; then the later NotAfter, then the later added; never one
// that is not valid now.
func TestCertStoreRanking(t *testing.T) {
	ca := newTestCA(t)
	now := time.Now()
	clock := &fakeClock{t: now}
	from, to := now.Add(-time.Hour), now.Add(30*24*time.Hour)
	s := &CertStore{Roots: ca.roots, now: clock.now}
	// Valid longer, but self-signed.
	mustAdd(t, s, "self-exact", makeCert(t, nil, nil, from, to.Add(24*time.Hour), "www.example.com"))
	mustAdd(t, s, "ca-wild", makeCert(t, ca, nil, from, to, "*.example.com"))
	if got := pick(t, s, hello("www.example.com")); got != "ca-wild" {
		t.Fatalf("authority wildcard vs self-signed exact: got %s", got)
	}
	mustAdd(t, s, "ca-exact", makeCert(t, ca, nil, from, to, "www.example.com"))
	if got := pick(t, s, hello("www.example.com")); got != "ca-exact" {
		t.Fatalf("authority exact vs authority wildcard: got %s", got)
	}
	// The later NotAfter wins among equals, then the one added last.
	mustAdd(t, s, "ca-exact-longer", makeCert(t, ca, nil, from, to.Add(time.Hour), "www.example.com"))
	if got := pick(t, s, hello("www.example.com")); got != "ca-exact-longer" {
		t.Fatalf("later NotAfter: got %s", got)
	}
	mustAdd(t, s, "ca-exact-newer", makeCert(t, ca, nil, from, to.Add(time.Hour), "www.example.com"))
	if got := pick(t, s, hello("www.example.com")); got != "ca-exact-newer" {
		t.Fatalf("added last: got %s", got)
	}
	// One not valid yet, or no longer, does not serve.
	mustAdd(t, s, "ca-exact-future", makeCert(t, ca, nil, now.Add(time.Hour), to.Add(2*time.Hour), "www.example.com"))
	if got := pick(t, s, hello("www.example.com")); got != "ca-exact-newer" {
		t.Fatalf("not valid yet: got %s", got)
	}
	clock.advance(time.Hour)
	if got := pick(t, s, hello("www.example.com")); got != "ca-exact-future" {
		t.Fatalf("once valid: got %s", got)
	}
	for _, id := range []string{"ca-exact", "ca-exact-longer", "ca-exact-newer", "ca-exact-future"} {
		s.Remove(id)
	}
	if got := pick(t, s, hello("www.example.com")); got != "ca-wild" {
		t.Fatalf("after removing the exact ones: got %s", got)
	}

	// Among self-signed ones, exact wins over wildcard.
	mustAdd(t, s, "self-wild", makeCert(t, nil, nil, from, to.Add(48*time.Hour), "*.example.org"))
	mustAdd(t, s, "self-exact-org", makeCert(t, nil, nil, from, to, "api.example.org"))
	if got := pick(t, s, hello("api.example.org")); got != "self-exact-org" {
		t.Fatalf("self-signed exact vs wildcard: got %s", got)
	}
	if got := pick(t, s, hello("other.example.org")); got != "self-wild" {
		t.Fatalf("wildcard: got %s", got)
	}
	// An expired best one gives way.
	clock.advance(31 * 24 * time.Hour)
	if got := pick(t, s, hello("api.example.org")); got != "self-wild" {
		t.Fatalf("expired exact: got %s", got)
	}
	clock.advance(48 * time.Hour)
	if got := pick(t, s, hello("api.example.org")); got != "error: "+ErrNoCertificate.Error() {
		t.Fatalf("all expired: got %s", got)
	}
}

// A certificate the client can use wins over a better ranked one it cannot,
// and with none it can use, the best ranked serves.
func TestCertStoreClientSupport(t *testing.T) {
	ca := newTestCA(t)
	from, to := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s := &CertStore{Roots: ca.roots}
	mustAdd(t, s, "ecdsa", makeCert(t, ca, nil, from, to, "www.example.com"))
	mustAdd(t, s, "rsa", makeCert(t, nil, rsaKey, from, to, "*.example.com"))
	h := func(schemes ...tls.SignatureScheme) *tls.ClientHelloInfo {
		return &tls.ClientHelloInfo{
			ServerName:        "www.example.com",
			SupportedVersions: []uint16{tls.VersionTLS13},
			CipherSuites:      []uint16{tls.TLS_AES_128_GCM_SHA256},
			SupportedCurves:   []tls.CurveID{tls.X25519, tls.CurveP256},
			SignatureSchemes:  schemes,
		}
	}
	if got := pick(t, s, h(tls.PSSWithSHA256)); got != "rsa" {
		t.Fatalf("RSA-only client: got %s", got)
	}
	if got := pick(t, s, h(tls.ECDSAWithP256AndSHA256, tls.PSSWithSHA256)); got != "ecdsa" {
		t.Fatalf("client of both: got %s", got)
	}
	if got := pick(t, s, h(tls.Ed25519)); got != "ecdsa" {
		t.Fatalf("client of neither: got %s, want the best ranked", got)
	}
}

// Select names the certificate, also one not for the name; an ID that does
// not serve is reported and the ranking chooses; an error fails.
func TestCertStoreSelect(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	from := time.Now().Add(-time.Hour)
	errDenied := errors.New("denied")
	var reports []*CertError
	s := &CertStore{now: clock.now}
	s.OnError = func(err *CertError) {
		_, _ = s.Certificate(err.ID) // the hook may call back into the store
		reports = append(reports, err)
	}
	s.Select = func(hello *tls.ClientHelloInfo) (string, error) {
		switch hello.ServerName {
		case "denied.example":
			return "", errDenied
		case "auto.example":
			return "", nil
		}
		return hello.ServerName, nil // the host configuration names the ID
	}
	mustAdd(t, s, "site", makeCert(t, nil, nil, from, from.Add(48*time.Hour), "site.example"))
	mustAdd(t, s, "short", makeCert(t, nil, nil, from, from.Add(2*time.Hour), "other.example"))
	mustAdd(t, s, "auto", makeCert(t, nil, nil, from, from.Add(48*time.Hour), "auto.example"))
	mustAdd(t, s, "fallback", makeCert(t, nil, nil, from, from.Add(48*time.Hour), "*.example"))

	if got := pick(t, s, hello("site")); got != "site" {
		t.Fatalf("selected: got %s", got)
	}
	if got := pick(t, s, hello("short")); got != "short" {
		t.Fatalf("selected, not for the name: got %s", got)
	}
	if got := pick(t, s, hello("auto.example")); got != "auto" || len(reports) != 0 {
		t.Fatalf("no selection: got %s, reports %v", got, reports)
	}
	if got := pick(t, s, hello("denied.example")); got != "error: denied" {
		t.Fatalf("Select error: got %s", got)
	}
	if got := pick(t, s, hello("missing.example")); got != "fallback" {
		t.Fatalf("unknown ID: got %s, want the ranking's", got)
	}
	if len(reports) != 1 || reports[0].ID != "missing.example" || !errors.Is(reports[0].Err, ErrUnknownID) {
		t.Fatalf("reports = %+v, want ErrUnknownID", reports)
	}
	clock.advance(3 * time.Hour) // short has expired
	if got := pick(t, s, hello("short")); got != "error: "+ErrNoCertificate.Error() {
		t.Fatalf("expired selection: got %s, want the ranking's, which has none for the name", got)
	}
	if len(reports) != 2 || !errors.Is(reports[1].Err, ErrNotValidNow) {
		t.Fatalf("reports = %+v, want ErrNotValidNow", reports)
	}
}

// Add returns the fingerprint for an empty ID, replaces an ID, serves the
// names given in place of its leaf's, and does not change the certificate.
func TestCertStoreIDs(t *testing.T) {
	var s CertStore
	from, to := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	cert := makeCert(t, nil, nil, from, to, "a.example")
	id := mustAdd(t, &s, "", cert)
	if fp := Fingerprint(cert.Certificate[0]); id != hex.EncodeToString(fp[:]) || cert.Leaf != nil {
		t.Fatalf("ID = %s, leaf set %v; want the fingerprint and the certificate as it was", id, cert.Leaf != nil)
	}
	if got, ok := s.Certificate(id); !ok || !sameLeaf(got, cert) || got.Leaf == nil {
		t.Fatal("Certificate(id) does not return it with its leaf")
	}
	other := makeCert(t, nil, nil, from, to, "b.example")
	mustAdd(t, &s, id, other, "C.Example.", "192.0.2.1")
	if got := pick(t, &s, hello("a.example")); got != "error: "+ErrNoCertificate.Error() {
		t.Fatalf("replaced certificate still serves: %s", got)
	}
	if got := pick(t, &s, hello("b.example")); got != "error: "+ErrNoCertificate.Error() {
		t.Fatalf("leaf names serve in place of the given ones: %s", got)
	}
	if got := pick(t, &s, hello("c.example")); got != id {
		t.Fatalf("given name: got %s", got)
	}
	if infos := s.List(); len(infos) != 1 || !slices.Equal(infos[0].Names, []string{"192.0.2.1", "c.example"}) {
		t.Fatalf("List() = %+v", infos)
	}
	if !s.Remove(id) || s.Remove(id) {
		t.Fatal("Remove reports wrongly")
	}
	if _, ok := s.Certificate(id); ok {
		t.Fatal("removed certificate still held")
	}
	if _, err := s.Add("", &tls.Certificate{}); err == nil {
		t.Fatal("certificate without a chain added")
	}
}

// Match lists the candidates in rank order, each once, with why.
func TestCertStoreMatch(t *testing.T) {
	ca := newTestCA(t)
	from, to := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	s := &CertStore{Roots: ca.roots, Load: func(_ context.Context, name string) (*tls.Certificate, error) {
		return makeCert(t, nil, nil, from, to, name), nil
	}}
	mustAdd(t, s, "self-exact", makeCert(t, nil, nil, from, to, "www.example.com"))
	mustAdd(t, s, "ca-wild", makeCert(t, ca, nil, from, to, "*.example.com"))
	mustAdd(t, s, "expired", makeCert(t, ca, nil, from, from.Add(time.Minute), "www.example.com"))
	mustAdd(t, s, "default", makeCert(t, nil, nil, from, to, "default.example"))
	s.SetDefault("default")
	match := func(name string) []string {
		t.Helper()
		var got []string
		for _, info := range s.Match(name) {
			got = append(got, fmt.Sprintf("%s %v auth=%v wild=%v valid=%v default=%v %v",
				info.ID, info.Role, info.Authority, info.Wildcard, info.Valid, info.Default, info.Source))
		}
		return got
	}
	want := []string{
		"ca-wild candidate auth=true wild=true valid=true default=false add",
		"self-exact candidate auth=false wild=false valid=true default=false add",
		"expired candidate auth=true wild=false valid=false default=false add",
		"default default auth=false wild=false valid=true default=true add",
	}
	if got := match("WWW.example.com"); !slices.Equal(got, want) {
		t.Fatalf("Match() =\n%v\nwant\n%v", got, want)
	}
	// The default as a candidate is listed once, as a candidate.
	want = []string{"default candidate auth=false wild=false valid=true default=true add"}
	if got := match("default.example"); !slices.Equal(got, want) {
		t.Fatalf("Match(default.example) = %v, want %v", got, want)
	}
	if _, err := s.forName(context.Background(), "loaded.example"); err != nil {
		t.Fatal(err)
	}
	want = []string{
		" loaded auth=false wild=false valid=true default=false load",
		"default default auth=false wild=false valid=true default=true add",
	}
	if got := match("loaded.example"); !slices.Equal(got, want) {
		t.Fatalf("Match(loaded.example) = %v, want %v", got, want)
	}
	if infos := s.Match(""); len(infos) != 1 || infos[0].ID != "default" || infos[0].Role != RoleDefault {
		t.Fatalf("Match(\"\") = %+v, want the default", infos)
	}
	for _, info := range s.List() {
		if info.Role != RoleNone || info.Default != (info.ID == "default") {
			t.Fatalf("List() entry %+v", info)
		}
	}
}

// Clients that send no name get the certificate for the address they
// connected to, else the default.
func TestCertStoreNoServerName(t *testing.T) {
	from, to := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	s := &CertStore{}
	mustAdd(t, s, "ip", makeCert(t, nil, nil, from, to, "127.0.0.1"))
	s.SetDefault(mustAdd(t, s, "default", makeCert(t, nil, nil, from, to, "default.example")))
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{GetCertificate: s.GetCertificate})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.(*tls.Conn).Handshake()
			_ = c.Close()
		}
	}()
	served := func() []string {
		t.Helper()
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		leaf := c.ConnectionState().PeerCertificates[0]
		var names []string
		for _, ip := range leaf.IPAddresses {
			names = append(names, ip.String())
		}
		return append(names, leaf.DNSNames...)
	}
	if got := served(); !slices.Equal(got, []string{"127.0.0.1"}) {
		t.Fatalf("no server name: served %v, want the address's", got)
	}
	s.Remove("ip")
	if got := served(); !slices.Equal(got, []string{"default.example"}) {
		t.Fatalf("no server name: served %v, want the default", got)
	}
}

// AddFiles keeps the certificate in sync with its files under its ID: in
// the background as handshakes come, or at once with CheckFiles; a read that
// fails keeps the old one and is reported.
func TestCertStoreAddFiles(t *testing.T) {
	dir := t.TempDir()
	from := time.Now().Add(-time.Hour)
	first := makeCert(t, nil, nil, from, from.Add(48*time.Hour), "a.example")
	certFile, keyFile := writeCert(t, dir, *first)
	base := time.Now().Add(-time.Hour)
	setModTime(t, base, certFile, keyFile)
	clock := &fakeClock{t: time.Now()}
	reports := make(chan *CertError, 4)
	s := &CertStore{now: clock.now, OnError: func(err *CertError) { reports <- err }}
	// An empty ID means the cleaned path of the certificate file.
	given := dir + string(filepath.Separator) + "." + string(filepath.Separator) + "cert.pem"
	id, err := s.AddFiles("", given, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if id != certFile {
		t.Fatalf("ID = %s, want the path %s", id, certFile)
	}
	if infos := s.List(); len(infos) != 1 || infos[0].Source != SourceFiles || infos[0].CertFile != given {
		t.Fatalf("List() = %+v", infos)
	}

	// A renewal for another name: picked up in the background once due.
	second := makeCert(t, nil, nil, from, from.Add(72*time.Hour), "b.example")
	writeCert(t, dir, *second)
	setModTime(t, base.Add(time.Second), certFile, keyFile)
	if got, _ := s.forName(context.Background(), "a.example"); !sameLeaf(got, first) {
		t.Fatal("files checked before CheckInterval")
	}
	clock.advance(DefaultCheckInterval)
	_, _ = s.forName(context.Background(), "a.example") // starts the check
	eventually(t, func() bool {
		got, _ := s.forName(context.Background(), "b.example")
		return sameLeaf(got, second)
	})
	if got, ok := s.Certificate(certFile); !ok || !sameLeaf(got, second) || len(s.List()) != 1 {
		t.Fatal("the path ID changed with the files")
	}
	if got, _ := s.forName(context.Background(), "a.example"); got != nil {
		t.Fatal("the old name still serves")
	}

	// A broken file keeps the renewal serving and is reported.
	if err := os.WriteFile(certFile, []byte("broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	setModTime(t, base.Add(2*time.Second), certFile)
	s.CheckFiles()
	select {
	case r := <-reports:
		if r.ID != id || r.CertFile != given || r.Err == nil {
			t.Fatalf("report = %+v", r)
		}
	default:
		t.Fatal("failed read not reported")
	}
	if got, _ := s.forName(context.Background(), "b.example"); !sameLeaf(got, second) {
		t.Fatal("a failed read dropped the certificate")
	}

	// Removed or replaced while its files were read: the read does not
	// bring it back.
	s.addMu.RLock()
	old := s.byID[id]
	s.addMu.RUnlock()
	renewed, err := s.newCert(id, first, nil, SourceFiles, old.files)
	if err != nil {
		t.Fatal(err)
	}
	other := makeCert(t, nil, nil, from, from.Add(48*time.Hour), "c.example")
	mustAdd(t, s, id, other)
	s.put(renewed, old)
	if got, _ := s.Certificate(id); !sameLeaf(got, other) {
		t.Fatal("a read of replaced files overwrote the replacement")
	}
	s.Remove(id)
	s.put(renewed, old)
	if len(s.List()) != 0 {
		t.Fatal("a read of removed files brought the certificate back")
	}
	if missing, err := s.AddFiles("x", filepath.Join(dir, "missing.pem"), keyFile); err == nil {
		t.Fatalf("AddFiles of missing files = %s", missing)
	}
}

// Add and Remove race with handshakes, for the race detector.
func TestCertStoreConcurrentChanges(t *testing.T) {
	from, to := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	certs := make([]*tls.Certificate, 4)
	for i := range certs {
		certs[i] = makeCert(t, nil, nil, from, to, "a.example", "*.example")
	}
	s := &CertStore{}
	s.SetDefault("0")
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for range 4 {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				for _, name := range []string{"a.example", "b.example", ""} {
					_, _ = s.GetCertificate(hello(name))
				}
				_ = s.Match("a.example")
			}
		})
	}
	for i := range 200 {
		id := fmt.Sprint(i % len(certs))
		if i%3 == 0 {
			s.Remove(id)
		} else {
			mustAdd(t, s, id, certs[i%len(certs)])
		}
	}
	close(stop)
	wg.Wait()
}
