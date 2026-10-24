package tlsconn_test

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"log"

	"github.com/djylb/netx/tlsconn"
)

// A server checks an uploaded certificate and key, then has the user prove
// that they hold the key before taking the certificate's names as theirs.
func ExampleChallenger() {
	// What the user uploads; here a certificate issued by a private CA that
	// the server trusts.
	ca, err := tlsconn.NewCA(tlsconn.SelfSignedOptions{})
	if err != nil {
		log.Fatal(err)
	}
	issued, err := tlsconn.Issue(ca, tlsconn.SelfSignedOptions{Hosts: []string{"*.example.com", "example.com"}})
	if err != nil {
		log.Fatal(err)
	}
	certPEM, keyPEM, err := tlsconn.EncodePEM(issued)
	if err != nil {
		log.Fatal(err)
	}

	// The server parses the upload and verifies what it covers.
	cert, err := tlsconn.ParseKeyPair(certPEM, keyPEM)
	if err != nil {
		log.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Leaf)
	chain := []*x509.Certificate{cert.Leaf}
	coverage, err := tlsconn.VerifyDomain(chain, "example.com", tlsconn.VerifyOptions{Roots: roots})
	if err != nil {
		log.Fatal(err)
	}

	// The certificate is public, so the user proves they hold its key.
	challenger, err := tlsconn.NewChallenger(tlsconn.ChallengerOptions{})
	if err != nil {
		log.Fatal(err)
	}
	const purpose = "claim example.com for user 42"
	challenge, err := challenger.Challenge(purpose)
	if err != nil {
		log.Fatal(err)
	}
	userKey := issued.PrivateKey.(crypto.Signer) // on the user's side
	sig, err := tlsconn.SignPossession(userKey, purpose, challenge)
	if err != nil {
		log.Fatal(err)
	}
	if err := challenger.Verify(cert.Leaf.PublicKey, purpose, challenge, sig); err != nil {
		log.Fatal(err)
	}

	fmt.Println("example.com:", coverage.Covers("example.com"))
	fmt.Println("www.example.com:", coverage.Covers("www.example.com"))
	fmt.Println("a.www.example.com:", coverage.Covers("a.www.example.com"))
	// Output:
	// example.com: true
	// www.example.com: true
	// a.www.example.com: false
}
