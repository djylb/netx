package tlsconn

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// serveAndDial runs a TLS handshake between a server with cert and a client
// with cfg over loopback TCP and returns the client's error.
func serveAndDial(t *testing.T, cert tls.Certificate, cfg *tls.Config) error {
	t.Helper()
	_, err := dialServer(t, &tls.Config{Certificates: []tls.Certificate{cert}}, cfg)
	return err
}

// dialServer runs a TLS handshake between a server with serverCfg and a
// client with cfg over loopback TCP, and reports whether the client resumed a
// session.
func dialServer(t *testing.T, serverCfg, cfg *tls.Config) (resumed bool, err error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		tc := tls.Server(c, serverCfg)
		if tc.Handshake() == nil {
			// The client reads this after any TLS 1.3 session ticket.
			_, _ = tc.Write([]byte("x"))
			_, _ = io.Copy(io.Discard, tc)
		}
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	tc, err := Client(context.Background(), raw, cfg, 2*time.Second)
	if err != nil {
		return false, err
	}
	defer func() { _ = tc.Close() }()
	_, err = io.ReadFull(tc, make([]byte, 1))
	return tc.ConnectionState().DidResume, err
}

func TestNewSelfSigned(t *testing.T) {
	cert, err := NewSelfSigned(SelfSignedOptions{Hosts: []string{"example.test", "192.0.2.1"}, Organization: "netx"})
	if err != nil {
		t.Fatal(err)
	}
	leaf := cert.Leaf
	if leaf == nil || leaf.Subject.CommonName != "example.test" || len(leaf.DNSNames) != 1 || len(leaf.IPAddresses) != 1 || leaf.Subject.Organization[0] != "netx" {
		t.Fatalf("leaf = %+v", leaf)
	}
	if d := time.Until(leaf.NotAfter); d < 364*24*time.Hour || d > 366*24*time.Hour {
		t.Fatalf("valid for %v, want a year", d)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	for _, name := range []string{"example.test", "192.0.2.1"} {
		if err := serveAndDial(t, cert, &tls.Config{RootCAs: roots, ServerName: name}); err != nil {
			t.Fatalf("handshake for %s: %v", name, err)
		}
	}
	if err := serveAndDial(t, cert, &tls.Config{RootCAs: roots, ServerName: "other.test"}); err == nil {
		t.Fatal("certificate accepted for another name")
	}

	// The zero options give localhost; an RSA key is used as given.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert, err = NewSelfSigned(SelfSignedOptions{Key: key, ValidFor: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if cert.Leaf.DNSNames[0] != "localhost" || cert.PrivateKey != key || cert.Leaf.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
		t.Fatalf("RSA certificate = %+v", cert.Leaf)
	}

	// EncodePEM round-trips through tls.X509KeyPair.
	certPEM, keyPEM, err := EncodePEM(cert)
	if err != nil {
		t.Fatal(err)
	}
	back, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil || Fingerprint(back.Certificate[0]) != Fingerprint(cert.Certificate[0]) {
		t.Fatalf("X509KeyPair(EncodePEM()) = %v", err)
	}
	if _, _, err := EncodePEM(tls.Certificate{}); err == nil {
		t.Fatal("EncodePEM accepted an empty certificate")
	}
}

func TestPinSet(t *testing.T) {
	pinned, err := NewSelfSigned(SelfSignedOptions{})
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewSelfSigned(SelfSignedOptions{})
	if err != nil {
		t.Fatal(err)
	}
	pins := NewPinSet(Fingerprint(pinned.Certificate[0]))
	cfg := pins.ClientConfig(&tls.Config{ClientSessionCache: tls.NewLRUClientSessionCache(4), ServerName: "localhost"})
	if err := serveAndDial(t, pinned, cfg); err != nil {
		t.Fatalf("pinned certificate: %v", err)
	}
	if err := serveAndDial(t, other, cfg); !errors.Is(err, ErrNotPinned) {
		t.Fatalf("other certificate error = %v, want %v", err, ErrNotPinned)
	}
	if pins.Len() != 1 || !pins.Contains(Fingerprint(pinned.Certificate[0])) {
		t.Fatal("pin set lost its pin")
	}

	// Removing the pin also fails a resumed session.
	serverCfg := &tls.Config{Certificates: []tls.Certificate{pinned}}
	if _, err := dialServer(t, serverCfg, cfg); err != nil {
		t.Fatal(err)
	}
	if resumed, err := dialServer(t, serverCfg, cfg); err != nil || !resumed {
		t.Fatalf("second connection resumed %v, %v; want a resumed session", resumed, err)
	}
	pins.Remove(Fingerprint(pinned.Certificate[0]))
	if _, err := dialServer(t, serverCfg, cfg); !errors.Is(err, ErrNotPinned) {
		t.Fatalf("resumption after Remove error = %v, want %v", err, ErrNotPinned)
	}

	var zero PinSet
	zero.Add(Fingerprint(other.Certificate[0]))
	if err := serveAndDial(t, other, zero.ClientConfig(nil)); err != nil {
		t.Fatalf("zero PinSet after Add: %v", err)
	}
}

func writeCert(t *testing.T, dir string, cert tls.Certificate) (certFile, keyFile string) {
	t.Helper()
	certPEM, keyPEM, err := EncodePEM(cert)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

func TestCertCacheFiles(t *testing.T) {
	first, _ := NewSelfSigned(SelfSignedOptions{})
	certFile, keyFile := writeCert(t, t.TempDir(), first)
	c := &CertCache{ReloadInterval: 50 * time.Millisecond}

	got, err := c.LoadFiles(certFile, keyFile)
	if err != nil || Fingerprint(got.Certificate[0]) != Fingerprint(first.Certificate[0]) {
		t.Fatalf("LoadFiles() = %v", err)
	}
	if again, _ := c.LoadFiles(certFile, keyFile); again != got {
		t.Fatal("second LoadFiles did not use the cache")
	}

	// A renewed certificate is picked up after ReloadInterval.
	second, _ := NewSelfSigned(SelfSignedOptions{})
	writeCert(t, filepath.Dir(certFile), second)
	time.Sleep(60 * time.Millisecond)
	if got, _ = c.LoadFiles(certFile, keyFile); Fingerprint(got.Certificate[0]) != Fingerprint(second.Certificate[0]) {
		t.Fatal("renewed certificate not reloaded")
	}

	// A failed reload keeps the previous certificate.
	if err := os.WriteFile(certFile, []byte("broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(60 * time.Millisecond)
	if kept, err := c.LoadFiles(certFile, keyFile); err != nil || kept != got {
		t.Fatalf("after a failed reload LoadFiles() = %v, %v; want the previous certificate", kept, err)
	}

	// A failed first load is not cached.
	if _, err := c.LoadFiles(filepath.Join(t.TempDir(), "missing.pem"), keyFile); err == nil {
		t.Fatal("missing file loaded")
	}
	if c.Len() != 1 {
		t.Fatalf("Len() = %d, want 1", c.Len())
	}
}

func TestCertCachePEM(t *testing.T) {
	var c CertCache
	certs := make([][2][]byte, 3)
	for i := range certs {
		cert, _ := NewSelfSigned(SelfSignedOptions{})
		certs[i][0], certs[i][1], _ = EncodePEM(cert)
	}

	// Concurrent first loads of one certificate share one result.
	var wg sync.WaitGroup
	results := make([]*tls.Certificate, 8)
	for i := range results {
		wg.Go(func() {
			results[i], _ = c.LoadPEM(certs[0][0], certs[0][1])
		})
	}
	wg.Wait()
	for _, r := range results {
		if r == nil || r != results[0] {
			t.Fatal("concurrent loads returned different certificates")
		}
	}
	if other, _ := c.LoadPEM(certs[1][0], certs[1][1]); other == results[0] {
		t.Fatal("different PEM data shared a cache entry")
	}
	if _, err := c.LoadPEM([]byte("x"), []byte("y")); err == nil {
		t.Fatal("invalid PEM loaded")
	}

	// MaxEntries drops the least recently used certificate.
	c.MaxEntries = 2
	_, _ = c.LoadPEM(certs[0][0], certs[0][1])
	_, _ = c.LoadPEM(certs[2][0], certs[2][1])
	if c.Len() != 2 {
		t.Fatalf("Len() = %d, want 2", c.Len())
	}
	if again, _ := c.LoadPEM(certs[0][0], certs[0][1]); again != results[0] {
		t.Fatal("recently used certificate was evicted")
	}

	// IdleTimeout drops certificates nobody loads.
	c.IdleTimeout = 20 * time.Millisecond
	time.Sleep(30 * time.Millisecond)
	_, _ = c.LoadPEM(certs[2][0], certs[2][1])
	if c.Len() != 1 {
		t.Fatalf("Len() after idle = %d, want 1", c.Len())
	}
	c.Clear()
	if c.Len() != 0 {
		t.Fatalf("Len() after Clear = %d", c.Len())
	}
}

func TestPinSetClientConfigKeepsBaseCheck(t *testing.T) {
	cert, _ := NewSelfSigned(SelfSignedOptions{})
	pins := NewPinSet(Fingerprint(cert.Certificate[0]))
	errPolicy := errors.New("policy")
	called := false
	cfg := pins.ClientConfig(&tls.Config{VerifyConnection: func(tls.ConnectionState) error {
		called = true
		return errPolicy
	}})
	if err := serveAndDial(t, cert, cfg); !errors.Is(err, errPolicy) || !called {
		t.Fatalf("handshake error = %v (base check called %v), want the base check's error", err, called)
	}
}

func TestEncodePEMEd25519Pointer(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := NewSelfSigned(SelfSignedOptions{Key: &key})
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := EncodePEM(cert)
	if err != nil {
		t.Fatalf("EncodePEM(*ed25519.PrivateKey) error = %v", err)
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
}

// TestCertCacheWaitersAndReloads has callers wait on a slow first load while
// another caller reloads right after it, for the race detector.
func TestCertCacheWaitersAndReloads(t *testing.T) {
	cert, _ := NewSelfSigned(SelfSignedOptions{})
	var loads atomic.Int32
	load := func() (*tls.Certificate, error) {
		if loads.Add(1) == 1 {
			time.Sleep(50 * time.Millisecond) // the first load: others wait
		}
		c := cert
		return &c, nil
	}
	c := &CertCache{ReloadInterval: time.Nanosecond}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if got, err := c.get("k", true, load); err != nil || got == nil {
				t.Errorf("get() = %v, %v", got, err)
			}
		})
	}
	wg.Go(func() {
		for range 200 {
			_, _ = c.get("k", true, load)
		}
	})
	wg.Wait()
}
