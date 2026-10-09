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
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"
)

// SelfSignedOptions configures NewSelfSigned. The zero value gives a
// certificate for localhost.
type SelfSignedOptions struct {
	// Hosts are the DNS names and IP addresses the certificate is for. The
	// first is also its common name. Empty means localhost.
	Hosts []string
	// Organization is the subject's organization, if any.
	Organization string
	// ValidFor is how long the certificate is valid; one year if not
	// positive. Validity starts an hour in the past to allow for clock skew.
	ValidFor time.Duration
	// Key is the certificate's private key; nil generates an ECDSA P-256
	// key. Use an *rsa.PrivateKey for clients that need RSA.
	Key crypto.Signer
}

// NewSelfSigned returns a self-signed server certificate with its Leaf set,
// for tests, internal services and peers that verify it by Fingerprint
// rather than by a certificate authority.
func NewSelfSigned(opts SelfSignedOptions) (tls.Certificate, error) {
	key := opts.Key
	if key == nil {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return tls.Certificate{}, err
		}
		key = k
	}
	hosts := opts.Hosts
	if len(hosts) == 0 {
		hosts = []string{"localhost"}
	}
	validFor := opts.ValidFor
	if validFor <= 0 {
		validFor = 365 * 24 * time.Hour
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	notBefore := time.Now().Add(-time.Hour)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: hosts[0]},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(time.Hour + validFor),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if opts.Organization != "" {
		tmpl.Subject.Organization = []string{opts.Organization}
	}
	if _, ok := key.(*rsa.PrivateKey); ok {
		// RSA key exchange in TLS 1.2 encrypts to the certificate's key.
		tmpl.KeyUsage |= x509.KeyUsageKeyEncipherment
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
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
