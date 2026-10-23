package proxydial_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"net/textproto"
	"net/url"
	"time"

	"github.com/djylb/netx/proxydial"
	"github.com/djylb/netx/tlsconn"
)

// Dial through the proxy that ALL_PROXY names, unless NO_PROXY lists the
// target, and directly when ALL_PROXY is unset.
func ExampleFromEnvironment() {
	d, err := proxydial.FromEnvironment(nil, nil)
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", "example.com:443")
	if err != nil {
		log.Println(err)
		return
	}
	defer func() { _ = conn.Close() }()
}

// An https proxy whose certificate a private CA issued, with an extra
// CONNECT header field.
func ExampleHTTPDialer() {
	ca := x509.NewCertPool() // add the private CA here
	d := &proxydial.HTTPDialer{
		ProxyAddr: "proxy.corp.example:3128",
		Header:    textproto.MIMEHeader{"User-Agent": {"my-agent/1.0"}},
		Forward: &tlsconn.Dialer{
			Config:  &tls.Config{RootCAs: ca}, // verified against proxy.corp.example
			Forward: &net.Dialer{Timeout: 10 * time.Second},
		},
	}
	conn, err := d.Dial("tcp", "example.com:443")
	if err != nil {
		log.Println(err)
		return
	}
	defer func() { _ = conn.Close() }()
}

func ExampleFromURL() {
	u, err := url.Parse("socks5://user:secret@proxy.example:1080")
	if err != nil {
		log.Fatal(err)
	}
	d, err := proxydial.FromURL(u, &net.Dialer{Timeout: 10 * time.Second}, nil)
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", "example.com:443")
	if err != nil {
		log.Println(err)
		return
	}
	defer func() { _ = conn.Close() }()
}

func ExampleParseNoProxy() {
	np := proxydial.ParseNoProxy("localhost, .corp.example, 10.0.0.0/8, internal:8080")
	for _, target := range []string{"localhost:5432", "db.corp.example:5432", "corp.example:443", "10.1.2.3:22", "internal:80", "example.com:443"} {
		fmt.Println(target, np.Match(target))
	}
	// Output:
	// localhost:5432 true
	// db.corp.example:5432 true
	// corp.example:443 false
	// 10.1.2.3:22 true
	// internal:80 false
	// example.com:443 false
}
