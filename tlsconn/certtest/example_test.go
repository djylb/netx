package certtest_test

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/big"
	"time"

	"github.com/djylb/netx/tlsconn/certtest"
)

func ExampleCA_Issue() {
	now := time.Unix(0, 0)
	ca, err := certtest.NewCAWithValidity(now, now.Add(24*time.Hour))
	if err != nil {
		panic(err)
	}
	chain, key, err := ca.Issue([]string{"service.example"}, now, time.Hour)
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
