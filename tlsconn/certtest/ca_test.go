package certtest_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"math/big"
	"net"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/djylb/netx/tlsconn/certtest"
)

func keyPair(t *testing.T, chain, key []byte, err error) tls.Certificate {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(chain, key)
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

func TestValidityNamesAndKeys(t *testing.T) {
	start := time.Unix(1_000, 0)
	ca := certtest.NewCAWithValidity(t, start, start.Add(3*time.Hour))
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := start.Add(time.Hour)
	chain, key, err := ca.Issue(certtest.LeafOptions{Key: k, Names: []string{"one.example", "*.example.test", "127.0.0.1", "::1"}, NotBefore: now, Life: time.Hour})
	cert := keyPair(t, chain, key, err)
	if len(cert.Certificate) != 2 || !cert.PrivateKey.(*ecdsa.PrivateKey).Equal(k) {
		t.Fatal("wrong key or chain length")
	}
	leaf := cert.Leaf
	root, err := x509.ParseCertificate(cert.Certificate[1])
	if err != nil || !root.IsCA || !root.NotBefore.Equal(start) || !root.NotAfter.Equal(start.Add(3*time.Hour)) {
		t.Fatalf("invalid root: %v", err)
	}
	if !leaf.NotBefore.Equal(now) || !leaf.NotAfter.Equal(now.Add(time.Hour)) || !slices.Equal(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) {
		t.Fatal(leaf)
	}
	pool := ca.Pool()
	for _, host := range []string{"one.example", "one.example.test", "127.0.0.1", "::1"} {
		opts := x509.VerifyOptions{DNSName: host, CurrentTime: now, Roots: pool}
		chains, err := leaf.Verify(opts)
		if err != nil || len(chains) != 1 || !chains[0][1].Equal(root) {
			t.Fatalf("%s: %v", host, err)
		}
		opts.CurrentTime = leaf.NotAfter.Add(time.Second)
		if _, err = leaf.Verify(opts); err == nil {
			t.Error("accepted expired leaf")
		}
	}
	chain, key, err = ca.Issue(certtest.LeafOptions{NotBefore: now})
	noSAN := keyPair(t, chain, key, err).Leaf
	if len(noSAN.DNSNames)+len(noSAN.IPAddresses) != 0 || noSAN.Subject.CommonName != "" || !noSAN.NotBefore.Equal(noSAN.NotAfter) {
		t.Fatal(noSAN)
	}
}

func TestMutualTLS(t *testing.T) {
	ca := certtest.NewCA(t)
	now := time.Unix(4_000, 0)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca.PEM()) {
		t.Fatal("missing root")
	}
	server, err := ca.IssueTLS(certtest.LeafOptions{Names: []string{"server.example"}, NotBefore: now, Life: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	chain, key, err := ca.Issue(certtest.LeafOptions{Names: []string{"client.example"}, NotBefore: now, Life: time.Hour, Client: true})
	client := keyPair(t, chain, key, err)
	if !slices.Equal(client.Leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) {
		t.Fatal(client.Leaf.ExtKeyUsage)
	}
	clock := func() time.Time { return now }
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	s := tls.Server(a, &tls.Config{Certificates: []tls.Certificate{server}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, Time: clock})
	c := tls.Client(b, &tls.Config{Certificates: []tls.Certificate{client}, RootCAs: roots, ServerName: "server.example", Time: clock})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.HandshakeContext(ctx) }()
	clientErr := c.HandshakeContext(ctx)
	if clientErr != nil {
		cancel()
	}
	serverErr := <-done
	if clientErr != nil || serverErr != nil {
		t.Fatalf("client %v, server %v", clientErr, serverErr)
	}
	if !s.ConnectionState().VerifiedChains[0][0].Equal(client.Leaf) || !c.ConnectionState().VerifiedChains[0][0].Equal(server.Leaf) {
		t.Fatal("wrong peer")
	}
}

func TestConcurrentIssue(t *testing.T) {
	const count = 16
	ca := certtest.NewCA(t)
	serials := make(chan int64, count)
	var group sync.WaitGroup
	for range count {
		group.Go(func() {
			chain, key, err := ca.Issue(certtest.LeafOptions{NotBefore: time.Unix(0, 0), Life: time.Minute})
			if err != nil {
				t.Error(err)
				return
			}
			cert, err := tls.X509KeyPair(chain, key)
			if err != nil {
				t.Error(err)
				return
			}
			serials <- cert.Leaf.SerialNumber.Int64()
			clear(chain)
			clear(ca.PEM())
		})
	}
	group.Wait()
	close(serials)
	seen := map[int64]bool{1: true}
	for n := range serials {
		if n <= 0 || seen[n] {
			t.Fatal(n)
		}
		seen[n] = true
	}
	if len(seen) != count+1 {
		t.Fatal(len(seen))
	}
}

func TestExactTemplate(t *testing.T) {
	now := time.Unix(2000, 0)
	oid := asn1.ObjectIdentifier{1, 2, 3, 4}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(81), NotBefore: now, NotAfter: now.Add(time.Hour), Subject: pkix.Name{CommonName: "subject-only"}, ExtraExtensions: []pkix.Extension{{Id: oid, Critical: true, Value: []byte{5, 0}}}}
	cert, err := certtest.SignSelfSigned(tpl)
	if err != nil {
		t.Fatal(err)
	}
	leaf := cert.Leaf
	if len(cert.Certificate) != 1 || !bytes.Equal(cert.Certificate[0], leaf.Raw) || leaf.SerialNumber.Cmp(tpl.SerialNumber) != 0 || leaf.Subject.CommonName != tpl.Subject.CommonName || len(leaf.DNSNames) != 0 || !slices.ContainsFunc(leaf.Extensions, func(e pkix.Extension) bool {
		return e.Id.Equal(oid) && e.Critical && bytes.Equal(e.Value, []byte{5, 0})
	}) {
		t.Fatal(leaf)
	}
	if err := leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature); err != nil {
		t.Fatal(err)
	}
}

func TestErrors(t *testing.T) {
	now := time.Unix(0, 0)
	fake := &fatalTB{TB: t}
	done := make(chan *certtest.CA)
	go func() {
		defer close(done)
		done <- certtest.NewCAWithValidity(fake, now, now.Add(-time.Hour))
	}()
	if <-done != nil || !fake.failed {
		t.Fatal("reversed CA lifetime")
	}
	for _, tpl := range []*x509.Certificate{nil, {SerialNumber: big.NewInt(-1)}} {
		if cert, err := certtest.SignSelfSigned(tpl); err == nil || cert.Leaf != nil {
			t.Fatal(cert, err)
		}
	}
	ca := certtest.NewCA(t)
	valid, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []crypto.Signer{(*ecdsa.PrivateKey)(nil), &ecdsa.PrivateKey{}, &ecdsa.PrivateKey{PublicKey: valid.PublicKey}, opaqueSigner{valid}} {
		if chain, key, err := ca.Issue(certtest.LeafOptions{Key: k, NotBefore: now}); err == nil || chain != nil || key != nil {
			t.Fatal("invalid key accepted")
		}
	}
	if _, _, err := ca.Issue(certtest.LeafOptions{NotBefore: now, Life: -time.Second}); err == nil {
		t.Fatal("negative leaf lifetime")
	}
	if _, _, err := ca.Issue(certtest.LeafOptions{Names: []string{"é"}, NotBefore: now, Life: time.Minute}); err == nil {
		t.Fatal("non-ASCII DNS SAN")
	}
	if root, pool := new(certtest.CA).PEM(), new(certtest.CA).Pool(); root != nil || pool != nil {
		t.Fatal("uninitialized root")
	}
	if _, _, err := new(certtest.CA).Issue(certtest.LeafOptions{NotBefore: now}); err == nil {
		t.Fatal("uninitialized CA")
	}
}

type fatalTB struct {
	testing.TB
	failed bool
}

func (f *fatalTB) Helper() {}

func (f *fatalTB) Fatal(...any) {
	f.failed = true
	runtime.Goexit()
}

// opaqueSigner hides the concrete key type from PKCS #8 marshaling.
type opaqueSigner struct{ k *ecdsa.PrivateKey }

func (o opaqueSigner) Public() crypto.PublicKey { return o.k.Public() }

func (o opaqueSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return o.k.Sign(r, digest, opts)
}
