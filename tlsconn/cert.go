package tlsconn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"slices"
	"time"
)

// SelfSignedOptions configures NewSelfSigned, NewCA and Issue. The zero value
// gives a certificate for localhost, or a CA named Private CA.
type SelfSignedOptions struct {
	// Hosts are the DNS names and IP addresses the certificate is for. The
	// first is also its common name. Empty means localhost. For NewCA, only
	// the first is used, as the common name, which defaults to Private CA.
	Hosts []string
	// Organization is the subject's organization, if any.
	Organization string
	// ValidFor is how long the certificate is valid; one year if not
	// positive. Validity starts an hour in the past to allow for clock skew.
	ValidFor time.Duration
	// Key is the certificate's private key; nil generates an ECDSA P-256
	// key. Use an *rsa.PrivateKey for clients that need RSA.
	Key crypto.Signer
	// ExtKeyUsage is what the certificate may be used for; empty means
	// x509.ExtKeyUsageServerAuth. Use x509.ExtKeyUsageClientAuth for a
	// client certificate, or both for peers that take either side. For
	// NewCA, empty leaves the CA unrestricted, and a set one restricts what
	// the certificates it issues may be used for.
	ExtKeyUsage []x509.ExtKeyUsage
}

// NewSelfSigned returns a self-signed certificate with its Leaf set, a
// server certificate unless ExtKeyUsage says otherwise, for tests, internal
// services and peers that verify it by Fingerprint rather than by a
// certificate authority.
func NewSelfSigned(opts SelfSignedOptions) (tls.Certificate, error) {
	tmpl, key, err := leafTemplate(opts)
	if err != nil {
		return tls.Certificate{}, err
	}
	return create(tmpl, tmpl, key, key, nil)
}

// NewCA returns a self-signed certificate authority with its Leaf set, for
// Issue to sign certificates with, such as for a private network whose peers
// trust it in their root pools (tls.Config RootCAs or ClientCAs, or
// CertStore.Roots). It signs leaf certificates only: its MaxPathLen is 0.
// It is not a full CA: there is no revocation. Give it a ValidFor longer than
// the certificates it issues, whose validity ends with its own.
func NewCA(opts SelfSignedOptions) (tls.Certificate, error) {
	tmpl, key, err := baseTemplate(opts)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl.Subject.CommonName = "Private CA"
	if len(opts.Hosts) > 0 {
		tmpl.Subject.CommonName = opts.Hosts[0]
	}
	tmpl.IsCA = true
	tmpl.MaxPathLen, tmpl.MaxPathLenZero = 0, true
	tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature
	tmpl.ExtKeyUsage = slices.Clone(opts.ExtKeyUsage)
	return create(tmpl, tmpl, key, key, nil)
}

// Issue returns a certificate for opts, signed by ca as NewCA returns it,
// with its Leaf set and its chain holding the leaf, then ca's chain. It is a
// server certificate unless ExtKeyUsage says otherwise, as with
// NewSelfSigned, and its validity ends no later than ca's.
func Issue(ca tls.Certificate, opts SelfSignedOptions) (tls.Certificate, error) {
	caLeaf, err := leafOf(&ca)
	if err != nil {
		return tls.Certificate{}, err
	}
	if !caLeaf.IsCA || caLeaf.KeyUsage&x509.KeyUsageCertSign == 0 {
		return tls.Certificate{}, errors.New("tlsconn: Issue needs a CA certificate")
	}
	caKey, ok := ca.PrivateKey.(crypto.Signer)
	if !ok {
		return tls.Certificate{}, errors.New("tlsconn: Issue needs the CA's private key")
	}
	tmpl, key, err := leafTemplate(opts)
	if err != nil {
		return tls.Certificate{}, err
	}
	if tmpl.NotAfter.After(caLeaf.NotAfter) {
		tmpl.NotAfter = caLeaf.NotAfter
	}
	return create(tmpl, caLeaf, key, caKey, ca.Certificate)
}

// baseTemplate returns the key of opts, generated if not given, and a
// template with its serial number, validity and subject.
func baseTemplate(opts SelfSignedOptions) (*x509.Certificate, crypto.Signer, error) {
	key := opts.Key
	if key == nil {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		key = k
	}
	validFor := opts.ValidFor
	if validFor <= 0 {
		validFor = 365 * 24 * time.Hour
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	notBefore := time.Now().Add(-time.Hour)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(time.Hour).Add(validFor), // saturates rather than wraps
		BasicConstraintsValid: true,
	}
	if opts.Organization != "" {
		tmpl.Subject.Organization = []string{opts.Organization}
	}
	return tmpl, key, nil
}

// leafTemplate returns the key and template of a leaf certificate for opts.
func leafTemplate(opts SelfSignedOptions) (*x509.Certificate, crypto.Signer, error) {
	tmpl, key, err := baseTemplate(opts)
	if err != nil {
		return nil, nil, err
	}
	hosts := opts.Hosts
	if len(hosts) == 0 {
		hosts = []string{"localhost"}
	}
	tmpl.Subject.CommonName = hosts[0]
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	if _, ok := key.(*rsa.PrivateKey); ok {
		// RSA key exchange in TLS 1.2 encrypts to the certificate's key.
		tmpl.KeyUsage |= x509.KeyUsageKeyEncipherment
	}
	tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	if len(opts.ExtKeyUsage) > 0 {
		tmpl.ExtKeyUsage = slices.Clone(opts.ExtKeyUsage)
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	return tmpl, key, nil
}

// create signs tmpl for key with parent and parentKey and returns it with
// chain after it.
func create(tmpl, parent *x509.Certificate, key, parentKey crypto.Signer, chain [][]byte) (tls.Certificate, error) {
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), parentKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: append([][]byte{der}, chain...),
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}

// EncodePEM encodes cert's chain as CERTIFICATE blocks and its private key as
// a PKCS #8 PRIVATE KEY block, which tls.X509KeyPair and tls.LoadX509KeyPair
// read back. The key must be one that x509.MarshalPKCS8PrivateKey encodes:
// RSA, ECDSA, Ed25519 or ECDH, not a key kept in hardware.
func EncodePEM(cert tls.Certificate) (certPEM, keyPEM []byte, err error) {
	if len(cert.Certificate) == 0 {
		return nil, nil, errors.New("tlsconn: certificate has no chain")
	}
	key := cert.PrivateKey
	if k, ok := key.(*ed25519.PrivateKey); ok && k != nil {
		key = *k
	}
	for _, der := range cert.Certificate {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("tlsconn: encode private key: %w", err)
	}
	return certPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

// Fingerprint returns the SHA-256 digest of a DER-encoded certificate, such
// as tls.Certificate.Certificate[0] or a peer's raw certificate: the usual
// certificate pin.
func Fingerprint(der []byte) [sha256.Size]byte {
	return sha256.Sum256(der)
}
