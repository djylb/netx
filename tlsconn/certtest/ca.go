// Package certtest creates ephemeral X.509 roots and TLS identities for tests.
// All validity intervals use caller-supplied times at X.509 second precision.
package certtest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// CA signs test leaves. An initialized CA may be used concurrently.
type CA struct {
	key    *ecdsa.PrivateKey
	cert   *x509.Certificate
	serial atomic.Int64
}

// NewCA creates a root valid from Unix second 0 through 1<<33. Use
// NewCAWithValidity for a different test clock. It calls tb.Fatal on failure.
func NewCA(tb testing.TB) *CA {
	tb.Helper()
	return NewCAWithValidity(tb, time.Unix(0, 0), time.Unix(1<<33, 0))
}

// NewCAWithValidity creates a root with inclusive validity bounds from start
// through end. It calls tb.Fatal when end precedes start or signing fails.
func NewCAWithValidity(tb testing.TB, start, end time.Time) *CA {
	tb.Helper()
	ca, err := newCA(start, end)
	if err != nil {
		tb.Fatal(err)
	}
	return ca
}

func newCA(start, end time.Time) (*CA, error) {
	if end.Before(start) {
		return nil, errors.New("certtest: CA validity ends before it starts")
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ca"},
		NotBefore: start, NotAfter: end, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	cert, err := SignSelfSigned(tpl)
	if err != nil {
		return nil, err
	}
	ca := &CA{key: cert.PrivateKey.(*ecdsa.PrivateKey), cert: cert.Leaf}
	ca.serial.Store(1)
	return ca, nil
}

// LeafOptions describes a leaf certificate for CA.Issue.
type LeafOptions struct {
	// Key signs the leaf's public key. Nil generates a fresh P-256 key. It
	// must be a key that x509.MarshalPKCS8PrivateKey accepts, such as
	// *ecdsa.PrivateKey, *rsa.PrivateKey or ed25519.PrivateKey.
	Key crypto.Signer
	// NotBefore starts the validity interval at X.509 second precision.
	NotBefore time.Time
	// Names become SANs: IP literals as IP SANs, all others as DNS SANs.
	// The first name is also the subject common name. An empty list
	// deliberately creates a leaf without subject or SANs.
	Names []string
	// Life is the validity length after NotBefore; it must not be negative.
	Life time.Duration
	// Client selects the client authentication EKU instead of server
	// authentication.
	Client bool
}

// Pool returns a fresh pool holding only the root, or nil for an
// uninitialized CA.
func (ca *CA) Pool() *x509.CertPool {
	if ca == nil || ca.cert == nil {
		return nil
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	return pool
}

// PEM returns a fresh PEM encoding of the root certificate, or nil for an
// uninitialized CA.
func (ca *CA) PEM() []byte {
	if ca == nil || ca.cert == nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})
}

// Issue signs a leaf. The results are a leaf-first PEM chain including the
// root and a PKCS #8 PEM private key.
func (ca *CA) Issue(o LeafOptions) (chain, key []byte, err error) {
	if o.Key == nil {
		if o.Key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			return nil, nil, err
		}
	}
	return ca.issueKey(o)
}

// IssueTLS is like Issue but returns a parsed certificate with its chain,
// key and Leaf set.
func (ca *CA) IssueTLS(o LeafOptions) (tls.Certificate, error) {
	chain, key, err := ca.Issue(o)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(chain, key)
}

func (ca *CA) issueKey(o LeafOptions) ([]byte, []byte, error) {
	if ca == nil || ca.cert == nil {
		return nil, nil, errors.New("certtest: uninitialized CA")
	}
	if o.Life < 0 {
		return nil, nil, errors.New("certtest: negative leaf lifetime")
	}
	if k, ok := o.Key.(*ecdsa.PrivateKey); ok {
		//lint:ignore SA1019 PKCS #8 marshaling dereferences these components on a partially initialized ECDSA key.
		if k == nil || k.D == nil || k.X == nil || k.Y == nil { //nolint:staticcheck // Guard the same incomplete keys for the bundled analyzer.
			return nil, nil, errors.New("certtest: incomplete ECDSA key")
		}
	}
	key, err := x509.MarshalPKCS8PrivateKey(o.Key)
	if err != nil {
		return nil, nil, fmt.Errorf("certtest: %w", err)
	}
	use := x509.ExtKeyUsageServerAuth
	if o.Client {
		use = x509.ExtKeyUsageClientAuth
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(ca.serial.Add(1)), NotBefore: o.NotBefore, NotAfter: o.NotBefore.Add(o.Life),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{use}}
	if len(o.Names) > 0 {
		tpl.Subject.CommonName = o.Names[0]
	}
	for _, name := range o.Names {
		if ip := net.ParseIP(name); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, name)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, o.Key.Public(), ca.key)
	if err != nil {
		return nil, nil, fmt.Errorf("certtest: %w", err)
	}
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return append(chain, ca.PEM()...), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), nil
}
