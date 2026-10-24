package tlsconn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// Errors of ParseCertificates, ParsePrivateKey, ParseKeyPair and MatchKey.
// Errors that come from crypto/x509 are wrapped too, so errors.Is and
// errors.As find both.
var (
	// ErrNoCertificates is the error of data that holds no certificate.
	ErrNoCertificates = errors.New("tlsconn: no certificate in the data")
	// ErrInvalidCertificate is the error of a certificate that does not
	// parse.
	ErrInvalidCertificate = errors.New("tlsconn: invalid certificate")
	// ErrNoPrivateKey is the error of data that holds no private key.
	ErrNoPrivateKey = errors.New("tlsconn: no private key in the data")
	// ErrMultipleKeys is the error of data that holds more than one private
	// key, of which none is taken, as it is not clear which is meant.
	ErrMultipleKeys = errors.New("tlsconn: more than one private key in the data")
	// ErrEncryptedKey is the error of a password-protected private key, which
	// has to be decrypted first.
	ErrEncryptedKey = errors.New("tlsconn: private key is encrypted")
	// ErrInvalidKey is the error of a private key that does not parse.
	ErrInvalidKey = errors.New("tlsconn: invalid private key")
	// ErrUnsupportedKey is the error of a key of a type that cannot sign
	// here, such as an X25519 key or a hardware key of an unknown type, or,
	// for a possession proof, an ECDSA key on a curve other than P-256,
	// P-384 and P-521.
	ErrUnsupportedKey = errors.New("tlsconn: unsupported key type")
	// ErrKeyMismatch is the error of a private key whose public key is not
	// the one of the certificate.
	ErrKeyMismatch = errors.New("tlsconn: private key does not match the certificate")
)

// ParseCertificates parses a certificate chain, leaf first, from PEM
// CERTIFICATE blocks or from DER, one certificate or several concatenated.
// PEM blocks of other types, such as a private key in the same file, and
// text around the blocks, such as the attributes that OpenSSL writes before
// them, are skipped, as tls.X509KeyPair does. Data that starts with an ASN.1
// SEQUENCE byte (0x30) is DER, and other data PEM.
//
// The data comes from users, so bound its size before reading it; parsing is
// linear in it.
func ParseCertificates(data []byte) ([]*x509.Certificate, error) {
	if !isPEM(data) {
		certs, err := x509.ParseCertificates(data)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidCertificate, err)
		}
		if len(certs) == 0 {
			return nil, ErrNoCertificates
		}
		return certs, nil
	}
	var certs []*x509.Certificate
	for rest := data; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: certificate %d: %w", ErrInvalidCertificate, len(certs), err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, ErrNoCertificates
	}
	return certs, nil
}

// ParsePrivateKey parses one private key from PEM or DER: PKCS #1 (RSA),
// PKCS #8 (RSA, ECDSA, Ed25519) or SEC 1 (ECDSA), whatever the PEM block's
// type says, as tls.X509KeyPair does. It returns an *rsa.PrivateKey, an
// *ecdsa.PrivateKey or an ed25519.PrivateKey. PEM blocks that hold no
// private key, such as certificates or EC PARAMETERS, are skipped; more than
// one key is ErrMultipleKeys, and a password-protected one ErrEncryptedKey.
func ParsePrivateKey(data []byte) (crypto.Signer, error) {
	if !isPEM(data) {
		return parseKeyDER(data)
	}
	var key crypto.Signer
	for rest := data; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "ENCRYPTED PRIVATE KEY":
			return nil, ErrEncryptedKey
		case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
		default:
			continue
		}
		if block.Headers["Proc-Type"] != "" {
			// Legacy OpenSSL encryption, as "Proc-Type: 4,ENCRYPTED".
			return nil, ErrEncryptedKey
		}
		if key != nil {
			return nil, ErrMultipleKeys
		}
		k, err := parseKeyDER(block.Bytes)
		if err != nil {
			return nil, err
		}
		key = k
	}
	if key == nil {
		return nil, ErrNoPrivateKey
	}
	return key, nil
}

// parseKeyDER parses a DER private key in any of the forms that
// ParsePrivateKey takes.
func parseKeyDER(der []byte) (crypto.Signer, error) {
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err == nil {
		switch k := k.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
			return k.(crypto.Signer), nil
		}
		return nil, fmt.Errorf("%w: %T", ErrUnsupportedKey, k)
	}
	if k, ecErr := x509.ParseECPrivateKey(der); ecErr == nil {
		return k, nil
	}
	return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
}

// MatchKey checks that key is the private key of leaf: that its public key
// equals leaf's, compared with the Equal method of the standard library's
// key types, the check tls.X509KeyPair makes. A key that is not a
// crypto.Signer is ErrUnsupportedKey, and another key ErrKeyMismatch.
func MatchKey(leaf *x509.Certificate, key crypto.PrivateKey) error {
	if leaf == nil {
		return ErrNoCertificates
	}
	signer, ok := key.(crypto.Signer)
	if !ok || signer == nil {
		return fmt.Errorf("%w: %T", ErrUnsupportedKey, key)
	}
	pub, ok := signer.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		return fmt.Errorf("%w: %T", ErrUnsupportedKey, key)
	}
	if !pub.Equal(leaf.PublicKey) {
		return ErrKeyMismatch
	}
	return nil
}

// ParseKeyPair parses a certificate chain, leaf first, as ParseCertificates
// does, and its private key, as ParsePrivateKey does, checks with MatchKey
// that the key is the leaf's, and returns them as a tls.Certificate with its
// Leaf set, ready for a tls.Config or CertStore.Add. Both may be in one
// file, passed as both arguments. It does not verify the chain or its
// validity dates; VerifyCertificate does.
func ParseKeyPair(certData, keyData []byte) (tls.Certificate, error) {
	certs, err := ParseCertificates(certData)
	if err != nil {
		return tls.Certificate{}, err
	}
	key, err := ParsePrivateKey(keyData)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := MatchKey(certs[0], key); err != nil {
		return tls.Certificate{}, err
	}
	chain := make([][]byte, len(certs))
	for i, c := range certs {
		chain[i] = c.Raw
	}
	return tls.Certificate{Certificate: chain, PrivateKey: key, Leaf: certs[0]}, nil
}

// isPEM reports whether data is PEM rather than DER, which starts with the
// tag of an ASN.1 SEQUENCE.
func isPEM(data []byte) bool {
	return len(data) == 0 || data[0] != 0x30
}
