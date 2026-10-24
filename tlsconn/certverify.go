package tlsconn

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// Errors of VerifyChain, VerifyCertificate and VerifyDomain. Each wraps the
// crypto/x509 error it comes from, if any.
var (
	// ErrExpired is the error of a chain whose leaf or an intermediate is
	// past its NotAfter at the time of verification.
	ErrExpired = errors.New("tlsconn: certificate has expired")
	// ErrNotYetValid is the error of a chain whose leaf or an intermediate
	// is before its NotBefore at the time of verification.
	ErrNotYetValid = errors.New("tlsconn: certificate is not yet valid")
	// ErrUnknownAuthority is the error of a chain that leads to none of the
	// roots.
	ErrUnknownAuthority = errors.New("tlsconn: certificate is signed by an unknown authority")
	// ErrSelfSigned is the error of a self-signed leaf that is not one of
	// the roots. The error matches ErrUnknownAuthority too.
	ErrSelfSigned = errors.New("tlsconn: certificate is self-signed")
	// ErrKeyUsage is the error of a chain that does not allow the key usages
	// asked for, such as server authentication.
	ErrKeyUsage = errors.New("tlsconn: certificate is not for the required key usage")
	// ErrInvalidChain is the error of a chain that fails verification for
	// another reason, such as a name constraint, a path length or an
	// insecure signature algorithm.
	ErrInvalidChain = errors.New("tlsconn: certificate chain is invalid")
)

// VerifyOptions configures VerifyChain, VerifyCertificate and VerifyDomain.
// The zero value verifies against the system roots, now, for server
// authentication.
type VerifyOptions struct {
	// Time is when the chain must be valid; zero means now.
	Time time.Time
	// Roots are the trusted roots; nil means the system's, which fails with
	// ErrInvalidChain where there are none, as on js/wasm.
	//
	// Set Roots for certificates that users upload. With nil, Windows, macOS
	// and iOS verify with the platform's verifier, which may fetch the
	// issuer URLs (Authority Information Access) that the certificate names,
	// so an uploaded certificate can make the server send requests to hosts
	// of the uploader's choosing, internal ones included. A set pool runs
	// the Go verifier, which fetches nothing. x509.SystemCertPool does not
	// help there: on those systems it delegates to the platform verifier
	// too and holds no certificates to copy. Load the roots from a file,
	// such as a CA bundle, with x509.CertPool.AppendCertsFromPEM.
	//
	// Certificates of
	// the chain being verified are never trusted as roots, even if
	// self-signed: add a self-signed certificate here to trust it.
	Roots *x509.CertPool
	// KeyUsages are the extended key usages the chain must allow; empty
	// means x509.ExtKeyUsageServerAuth, and x509.ExtKeyUsageAny allows any.
	KeyUsages []x509.ExtKeyUsage
}

// VerifyChain verifies chain, leaf first, against opts.Roots at opts.Time
// for opts.KeyUsages, as x509.Certificate.Verify does, with the certificates
// after the leaf, in any order, as intermediates. It returns the verified
// chains, each from the leaf to a root, or an error matching one of
// ErrExpired, ErrNotYetValid, ErrUnknownAuthority (and ErrSelfSigned for a
// self-signed leaf), ErrKeyUsage or ErrInvalidChain. Names are not checked:
// see CertNames and VerifyDomain.
func VerifyChain(chain []*x509.Certificate, opts VerifyOptions) ([][]*x509.Certificate, error) {
	if len(chain) == 0 || chain[0] == nil {
		return nil, ErrNoCertificates
	}
	leaf := chain[0]
	at := opts.Time
	if at.IsZero() {
		at = time.Now()
	}
	// x509 reports both as Expired; the leaf is checked first so that the
	// commonest case does not depend on how a platform verifier words it.
	if err := validityError(leaf, at); err != nil {
		return nil, err
	}
	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		if c != nil {
			intermediates.AddCert(c)
		}
	}
	usages := opts.KeyUsages
	if len(usages) == 0 {
		usages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots:         opts.Roots,
		Intermediates: intermediates,
		CurrentTime:   at,
		KeyUsages:     usages,
	})
	if err != nil {
		return nil, chainError(leaf, at, err)
	}
	return chains, nil
}

// VerifyCertificate is VerifyChain for cert's chain, with cert.Leaf, if set,
// as its leaf.
func VerifyCertificate(cert *tls.Certificate, opts VerifyOptions) ([][]*x509.Certificate, error) {
	chain, err := chainOf(cert)
	if err != nil {
		return nil, err
	}
	return VerifyChain(chain, opts)
}

// chainOf returns the parsed chain of cert.
func chainOf(cert *tls.Certificate) ([]*x509.Certificate, error) {
	leaf, err := leafOf(cert)
	if err != nil {
		if errors.Is(err, errNoChain) {
			return nil, ErrNoCertificates
		}
		return nil, fmt.Errorf("%w: certificate 0: %w", ErrInvalidCertificate, err)
	}
	chain := make([]*x509.Certificate, 1, len(cert.Certificate))
	chain[0] = leaf
	for i, der := range cert.Certificate[1:] {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("%w: certificate %d: %w", ErrInvalidCertificate, i+1, err)
		}
		chain = append(chain, c)
	}
	return chain, nil
}

// validityError returns ErrNotYetValid or ErrExpired if c is not valid at
// at, by RFC 5280, whose NotAfter is the last valid instant, as x509 checks.
func validityError(c *x509.Certificate, at time.Time) error {
	switch {
	case at.Before(c.NotBefore):
		return fmt.Errorf("%w: valid from %s", ErrNotYetValid, c.NotBefore.UTC().Format(time.RFC3339))
	case at.After(c.NotAfter):
		return fmt.Errorf("%w: valid until %s", ErrExpired, c.NotAfter.UTC().Format(time.RFC3339))
	}
	return nil
}

// chainError classifies an error of x509.Certificate.Verify for leaf at at.
func chainError(leaf *x509.Certificate, at time.Time, err error) error {
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) {
		switch invalid.Reason {
		case x509.Expired:
			if invalid.Cert != nil {
				if verr := validityError(invalid.Cert, at); verr != nil {
					return fmt.Errorf("%w: %w", verr, err)
				}
			}
			return fmt.Errorf("%w: %w", ErrExpired, err)
		case x509.IncompatibleUsage:
			return fmt.Errorf("%w: %w", ErrKeyUsage, err)
		case x509.NotAuthorizedToSign, x509.CANotAuthorizedForThisName, x509.TooManyIntermediates,
			x509.NameMismatch, x509.NameConstraintsWithoutSANs, x509.UnconstrainedName,
			x509.TooManyConstraints, x509.CANotAuthorizedForExtKeyUsage, x509.NoValidChains:
			// An invalid chain, reported below.
		}
	}
	var unknown x509.UnknownAuthorityError
	if errors.As(err, &unknown) {
		if IsSelfSigned(leaf) {
			return fmt.Errorf("%w: %w: %w", ErrSelfSigned, ErrUnknownAuthority, err)
		}
		return fmt.Errorf("%w: %w", ErrUnknownAuthority, err)
	}
	return fmt.Errorf("%w: %w", ErrInvalidChain, err)
}

// IsSelfSigned reports whether c is signed by its own key, with its issuer
// the same as its subject, whether or not it is a CA. A certificate signed
// with an algorithm crypto/x509 considers insecure, such as SHA-1, is not
// reported.
func IsSelfSigned(c *x509.Certificate) bool {
	if c == nil || !bytes.Equal(c.RawIssuer, c.RawSubject) {
		return false
	}
	// CheckSignatureFrom would also require c to be a CA.
	return c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}

// CertSummary describes a certificate for display, as Summarize returns it.
type CertSummary struct {
	// Subject and Issuer are the distinguished names, in RFC 2253 form.
	Subject, Issuer string
	// SerialNumber is the serial number in hex.
	SerialNumber string
	// KeyType is RSA, ECDSA with its curve (ECDSA P-256), Ed25519, or the
	// x509 algorithm name of another key.
	KeyType string
	// Names are the names it covers, as CertNames returns them.
	Names               Names
	NotBefore, NotAfter time.Time
	// Fingerprint is the SHA-256 of the DER certificate, as Fingerprint.
	Fingerprint [sha256.Size]byte
	// KeyBits is the size of the key: the RSA modulus, the curve, or 256
	// for Ed25519; 0 for another key.
	KeyBits int
	// SelfSigned reports IsSelfSigned.
	SelfSigned bool
	// IsCA reports whether it is a CA certificate, by basic constraints.
	IsCA bool
}

// Summarize describes c for display. It checks nothing: VerifyChain does.
func Summarize(c *x509.Certificate) CertSummary {
	if c == nil {
		return CertSummary{}
	}
	s := CertSummary{
		Subject:     c.Subject.String(),
		Issuer:      c.Issuer.String(),
		Names:       CertNames(c),
		NotBefore:   c.NotBefore,
		NotAfter:    c.NotAfter,
		Fingerprint: Fingerprint(c.Raw),
		SelfSigned:  IsSelfSigned(c),
		IsCA:        c.BasicConstraintsValid && c.IsCA,
		KeyType:     c.PublicKeyAlgorithm.String(),
	}
	if c.SerialNumber != nil {
		s.SerialNumber = c.SerialNumber.Text(16)
	}
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		if k != nil && k.N != nil {
			s.KeyType, s.KeyBits = "RSA", k.N.BitLen()
		}
	case *ecdsa.PublicKey:
		if k != nil && k.Curve != nil && k.Params() != nil {
			s.KeyType, s.KeyBits = "ECDSA "+k.Params().Name, k.Params().BitSize
		}
	case ed25519.PublicKey:
		s.KeyType, s.KeyBits = "Ed25519", 256
	}
	return s
}
