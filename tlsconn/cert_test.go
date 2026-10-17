package tlsconn

import (
	"bytes"
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
	"slices"
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
	tc, err := Client(timeoutContext(t, 2*time.Second), raw, cfg)
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

// fakeClock is a clock for CertFiles and CertStore that moves only when told to.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (f *fakeClock) now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.t
}

func (f *fakeClock) advance(d time.Duration) {
	f.mu.Lock()
	f.t = f.t.Add(d)
	f.mu.Unlock()
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

// ExtKeyUsage makes client certificates, or certificates for either side;
// the default is a server certificate, which a verifying server rejects as a
// client certificate.
func TestNewSelfSignedExtKeyUsage(t *testing.T) {
	both := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	for _, tc := range []struct {
		usage      []x509.ExtKeyUsage
		want       []x509.ExtKeyUsage
		clientAuth bool
	}{
		{nil, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, false},
		{[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, true},
		{both, both, true},
	} {
		cert, err := NewSelfSigned(SelfSignedOptions{ExtKeyUsage: tc.usage})
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(cert.Leaf.ExtKeyUsage, tc.want) {
			t.Fatalf("ExtKeyUsage(%v) = %v, want %v", tc.usage, cert.Leaf.ExtKeyUsage, tc.want)
		}
		pool := x509.NewCertPool()
		pool.AddCert(cert.Leaf)
		server, _ := NewSelfSigned(SelfSignedOptions{})
		err = handshakePair(t,
			&tls.Config{Certificates: []tls.Certificate{server}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool},
			&tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true})
		if (err == nil) != tc.clientAuth {
			t.Fatalf("ExtKeyUsage %v as a client certificate: server error = %v", tc.want, err)
		}
	}
	// The options' slice is not shared with the certificate.
	usage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	cert, _ := NewSelfSigned(SelfSignedOptions{ExtKeyUsage: usage})
	usage[0] = x509.ExtKeyUsageAny
	if cert.Leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatal("certificate shares the options' ExtKeyUsage")
	}
}

// handshakePair runs a handshake between Server with serverCfg and Client
// with clientCfg over a pipe and returns the server's error, which is where a
// rejected client certificate shows.
func handshakePair(t *testing.T, serverCfg, clientCfg *tls.Config) error {
	t.Helper()
	serverRaw, clientRaw := net.Pipe()
	defer func() { _ = clientRaw.Close() }()
	done := make(chan error, 1)
	go func() {
		_, err := Server(timeoutContext(t, 5*time.Second), serverRaw, serverCfg)
		if err == nil {
			_ = serverRaw.Close() // no close_notify to an unread pipe
		}
		done <- err
	}()
	if tc, err := Client(timeoutContext(t, 5*time.Second), clientRaw, clientCfg); err == nil {
		// Drain until the server ends, so that its last flight, or the
		// alert of a rejection, is read.
		_, _ = io.Copy(io.Discard, tc)
	}
	return <-done
}

// ServerConfig requires a client certificate and accepts only pinned ones,
// as between peers with self-signed certificates for either side.
func TestPinSetServerConfig(t *testing.T) {
	both := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	serverCert, _ := NewSelfSigned(SelfSignedOptions{ExtKeyUsage: both})
	clientCert, _ := NewSelfSigned(SelfSignedOptions{ExtKeyUsage: both})
	other, _ := NewSelfSigned(SelfSignedOptions{ExtKeyUsage: both})
	clientPins := NewPinSet(Fingerprint(serverCert.Certificate[0]))
	serverPins := NewPinSet(Fingerprint(clientCert.Certificate[0]))

	base := &tls.Config{Certificates: []tls.Certificate{serverCert}}
	serverCfg := serverPins.ServerConfig(base)
	if serverCfg.ClientAuth != tls.RequireAnyClientCert || base.ClientAuth != tls.NoClientCert || base.VerifyConnection != nil {
		t.Fatalf("ClientAuth = %v, base changed: %v", serverCfg.ClientAuth, base.ClientAuth)
	}
	client := func(cert tls.Certificate) *tls.Config {
		return clientPins.ClientConfig(&tls.Config{Certificates: []tls.Certificate{cert}})
	}
	if err := handshakePair(t, serverCfg, client(clientCert)); err != nil {
		t.Fatalf("pinned client certificate: %v", err)
	}
	if err := handshakePair(t, serverCfg, client(other)); !errors.Is(err, ErrNotPinned) {
		t.Fatalf("other client certificate error = %v, want %v", err, ErrNotPinned)
	}
	if err := handshakePair(t, serverCfg, clientPins.ClientConfig(nil)); err == nil {
		t.Fatal("handshake without a client certificate succeeded")
	}

	// A VerifyConnection of base runs after the pins, and a nil base works.
	errPolicy := errors.New("policy")
	withPolicy := serverPins.ServerConfig(&tls.Config{
		Certificates:     []tls.Certificate{serverCert},
		VerifyConnection: func(tls.ConnectionState) error { return errPolicy },
	})
	if err := handshakePair(t, withPolicy, client(clientCert)); !errors.Is(err, errPolicy) {
		t.Fatalf("base check error = %v, want %v", err, errPolicy)
	}
	if cfg := serverPins.ServerConfig(nil); cfg.ClientAuth != tls.RequireAnyClientCert || cfg.VerifyConnection == nil {
		t.Fatal("ServerConfig(nil) does not pin client certificates")
	}
}

// The Configs that a GetConfigForClient of the base returns are pinned too,
// as the handshake uses them in place of the outer one.
func TestPinSetServerConfigGetConfigForClient(t *testing.T) {
	both := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	serverCert, _ := NewSelfSigned(SelfSignedOptions{ExtKeyUsage: both})
	clientCert, _ := NewSelfSigned(SelfSignedOptions{ExtKeyUsage: both})
	other, _ := NewSelfSigned(SelfSignedOptions{ExtKeyUsage: both})
	clientPins := NewPinSet(Fingerprint(serverCert.Certificate[0]))
	serverPins := NewPinSet(Fingerprint(clientCert.Certificate[0]))

	errPolicy := errors.New("policy")
	var policy atomic.Bool
	inner := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		VerifyConnection: func(tls.ConnectionState) error {
			if policy.Load() {
				return errPolicy
			}
			return nil
		},
	}
	var returnNil atomic.Bool
	serverCfg := serverPins.ServerConfig(&tls.Config{
		Certificates: []tls.Certificate{serverCert},
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			if returnNil.Load() {
				return nil, nil
			}
			return inner, nil
		},
	})
	client := func(cert *tls.Certificate) *tls.Config {
		cfg := &tls.Config{}
		if cert != nil {
			cfg.Certificates = []tls.Certificate{*cert}
		}
		return clientPins.ClientConfig(cfg)
	}
	for _, nilConfig := range []bool{false, true} {
		returnNil.Store(nilConfig)
		if err := handshakePair(t, serverCfg, client(&clientCert)); err != nil {
			t.Fatalf("nil config %v: pinned client certificate: %v", nilConfig, err)
		}
		if err := handshakePair(t, serverCfg, client(&other)); !errors.Is(err, ErrNotPinned) {
			t.Fatalf("nil config %v: other client certificate error = %v, want %v", nilConfig, err, ErrNotPinned)
		}
		if err := handshakePair(t, serverCfg, client(nil)); err == nil {
			t.Fatalf("nil config %v: handshake without a client certificate succeeded", nilConfig)
		}
	}
	// The returned Config's own check runs after the pins, and it is not
	// changed itself.
	returnNil.Store(false)
	policy.Store(true)
	if err := handshakePair(t, serverCfg, client(&clientCert)); !errors.Is(err, errPolicy) {
		t.Fatalf("returned config's check error = %v, want %v", err, errPolicy)
	}
	if inner.ClientAuth != tls.NoClientCert {
		t.Fatal("GetConfigForClient's Config was changed")
	}
}

// NewCA makes a CA that signs leaves only; Issue's certificates verify
// against it, chain included, end with it, and serve in a CertStore as
// issued by an authority.
func TestNewCAAndIssue(t *testing.T) {
	ca, err := NewCA(SelfSignedOptions{Hosts: []string{"Test CA"}, ValidFor: 48 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if !ca.Leaf.IsCA || ca.Leaf.MaxPathLen != 0 || !ca.Leaf.MaxPathLenZero || ca.Leaf.KeyUsage&x509.KeyUsageCertSign == 0 || ca.Leaf.Subject.CommonName != "Test CA" {
		t.Fatalf("CA = %+v", ca.Leaf)
	}
	if def, _ := NewCA(SelfSignedOptions{}); def.Leaf.Subject.CommonName != "Private CA" {
		t.Fatalf("default CA name = %q", def.Leaf.Subject.CommonName)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Leaf)

	server, err := Issue(ca, SelfSignedOptions{Hosts: []string{"svc.internal", "10.0.0.1"}, ValidFor: 365 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if len(server.Certificate) != 2 || !bytes.Equal(server.Certificate[1], ca.Certificate[0]) || server.Leaf == nil {
		t.Fatal("issued chain is not leaf, then CA")
	}
	if server.Leaf.NotAfter.After(ca.Leaf.NotAfter) {
		t.Fatalf("issued NotAfter %v outlives the CA's %v", server.Leaf.NotAfter, ca.Leaf.NotAfter)
	}
	for _, name := range []string{"svc.internal", "10.0.0.1"} {
		if _, err := server.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: name}); err != nil {
			t.Fatalf("issued certificate for %s: %v", name, err)
		}
	}
	if err := serveAndDial(t, server, &tls.Config{RootCAs: roots, ServerName: "svc.internal"}); err != nil {
		t.Fatalf("handshake with an issued certificate: %v", err)
	}

	// Ranked as issued in a CertStore with the CA among its Roots, over a
	// self-signed certificate for the same name valid longer.
	self, _ := NewSelfSigned(SelfSignedOptions{Hosts: []string{"svc.internal"}, ValidFor: 10 * 365 * 24 * time.Hour})
	s := &CertStore{Roots: roots}
	mustAdd(t, s, "self", &self)
	issuedID := mustAdd(t, s, "", &server)
	if got, _ := s.forName(context.Background(), "svc.internal"); !sameLeaf(got, &server) {
		t.Fatal("issued certificate not preferred")
	}
	if infos := s.Match("svc.internal"); infos[0].ID != issuedID || !infos[0].Authority {
		t.Fatalf("Match() = %+v", infos)
	}

	// Issued client certificates for mutual TLS.
	client, err := Issue(ca, SelfSignedOptions{Hosts: []string{"client"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		t.Fatal(err)
	}
	serverCfg := &tls.Config{Certificates: []tls.Certificate{server}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	if err := handshakePair(t, serverCfg, &tls.Config{Certificates: []tls.Certificate{client}, RootCAs: roots, ServerName: "svc.internal"}); err != nil {
		t.Fatalf("mutual TLS with issued certificates: %v", err)
	}
	if err := handshakePair(t, serverCfg, &tls.Config{Certificates: []tls.Certificate{server}, RootCAs: roots, ServerName: "svc.internal"}); err == nil {
		t.Fatal("a server certificate passed as a client certificate")
	}

	if _, err := Issue(self, SelfSignedOptions{}); err == nil {
		t.Fatal("Issue signed with a certificate that is not a CA")
	}
	noKey := ca
	noKey.PrivateKey = nil
	if _, err := Issue(noKey, SelfSignedOptions{}); err == nil {
		t.Fatal("Issue signed without the CA's key")
	}
}

// CertID is the ID that a CertStore gives a certificate added without one.
func TestCertID(t *testing.T) {
	cert, _ := NewSelfSigned(SelfSignedOptions{})
	var s CertStore
	if id := mustAdd(t, &s, "", &cert); id != CertID(&cert) || len(id) != 64 {
		t.Fatalf("Add ID %s, CertID %s", id, CertID(&cert))
	}
	if CertID(nil) != "" || CertID(&tls.Certificate{}) != "" {
		t.Fatal("CertID of no certificate is not empty")
	}
}
