package certtest_test

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/djylb/netx/tlsconn/certtest"
)

func ExampleCA_Issue() {
	var t testing.T // use the test's *testing.T
	now := time.Unix(0, 0)
	ca := certtest.NewCAWithValidity(&t, now, now.Add(24*time.Hour))
	chain, key, err := ca.Issue(certtest.LeafOptions{Names: []string{"service.example"}, NotBefore: now, Life: time.Hour})
	if err != nil {
		panic(err)
	}
	pair, err := tls.X509KeyPair(chain, key)
	if err != nil {
		panic(err)
	}
	fmt.Println(len(pair.Certificate), pair.Leaf.DNSNames)
	// Output: 2 [service.example]
}

func ExampleSignSelfSigned() {
	template := &x509.Certificate{SerialNumber: big.NewInt(42), NotBefore: time.Unix(0, 0), NotAfter: time.Unix(3600, 0)}
	cert, err := certtest.SignSelfSigned(template)
	if err != nil {
		panic(err)
	}
	fmt.Println(cert.Leaf.SerialNumber, len(cert.Leaf.DNSNames))
	// Output: 42 0
}
