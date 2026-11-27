// Package certtest creates ephemeral X.509 roots and TLS identities for tests.
// All validity intervals use caller-supplied times at X.509 second precision.
package certtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
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

// NewCA creates a root valid from Unix second 0 through 1<<33.
// Use NewCAWithValidity for a different test clock.
func NewCA(t testing.TB) *CA {
	t.Helper()
	ca, err := NewCAWithValidity(time.Unix(0, 0), time.Unix(1<<33, 0))
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

// NewCAWithValidity creates a root with explicit inclusive validity bounds.
func NewCAWithValidity(start, end time.Time) (*CA, error) {
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

// PEM returns a fresh PEM encoding of the root certificate, or nil for an
// uninitialized CA.
func (ca *CA) PEM() []byte {
	if ca == nil || ca.cert == nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})
}

// Issue signs a server leaf with a fresh P-256 key. The results are a
// leaf-first PEM chain including the root and a PKCS #8 PEM private key.
// IP literals become IP SANs; all other names are copied as DNS SANs.
// An empty list deliberately creates a leaf without SANs.
func (ca *CA) Issue(names []string, now time.Time, life time.Duration) (chain, key []byte, err error) {
	return ca.issueFresh(names, now, life, x509.ExtKeyUsageServerAuth)
}

// IssueKey is like Issue but reuses the supplied ECDSA key.
func (ca *CA) IssueKey(k *ecdsa.PrivateKey, names []string, now time.Time, life time.Duration) (chain, key []byte, err error) {
	return ca.issueKey(k, names, now, life, x509.ExtKeyUsageServerAuth)
}

// IssueClient signs a leaf with the client authentication EKU and a fresh
// key. An empty name deliberately omits the subject and SAN.
func (ca *CA) IssueClient(name string, now time.Time, life time.Duration) (chain, key []byte, err error) {
	var names []string
	if name != "" {
		names = []string{name}
	}
	return ca.issueFresh(names, now, life, x509.ExtKeyUsageClientAuth)
}

func (ca *CA) issueFresh(names []string, now time.Time, life time.Duration, use x509.ExtKeyUsage) ([]byte, []byte, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return ca.issueKey(k, names, now, life, use)
}

func (ca *CA) issueKey(k *ecdsa.PrivateKey, names []string, now time.Time, life time.Duration, use x509.ExtKeyUsage) ([]byte, []byte, error) {
	if ca == nil || ca.cert == nil {
		return nil, nil, errors.New("certtest: uninitialized CA")
	}
	if life < 0 {
		return nil, nil, errors.New("certtest: negative leaf lifetime")
	}
	//lint:ignore SA1019 PKCS #8 marshaling dereferences these components on a partially initialized ECDSA key.
	if k == nil || k.D == nil || k.X == nil || k.Y == nil { //nolint:staticcheck // Guard the same incomplete keys for the bundled analyzer.
		return nil, nil, errors.New("certtest: missing ECDSA key")
	}
	key, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, nil, err
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(ca.serial.Add(1)), NotBefore: now, NotAfter: now.Add(life),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{use}}
	if len(names) > 0 {
		tpl.Subject.CommonName = names[0]
	}
	for _, name := range names {
		if ip := net.ParseIP(name); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, name)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, &k.PublicKey, ca.key)
	if err != nil {
		return nil, nil, err
	}
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return append(chain, ca.PEM()...), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), nil
}
