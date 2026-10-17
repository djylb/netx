package tlsconn_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"path/filepath"
	"time"

	"github.com/djylb/netx/socks5"
	"github.com/djylb/netx/tlsconn"
)

// Upgrade a dialed connection, with the dial and the handshake bounded by ten
// seconds.
func ExampleClient() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", "example.com:443")
	if err != nil {
		log.Fatal(err)
	}
	// On failure raw is closed.
	conn, err := tlsconn.Client(ctx, raw, &tls.Config{ServerName: "example.com"})
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
}

// Serve TLS on connections accepted elsewhere, such as from a protocol
// multiplexer, so that a slow client cannot hold the accept loop.
func ExampleServer() {
	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		log.Fatal(err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	ln, err := net.Listen("tcp", ":8443")
	if err != nil {
		log.Fatal(err)
	}
	for {
		raw, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			conn, err := tlsconn.Server(ctx, raw, cfg)
			cancel()
			if err != nil {
				return
			}
			defer func() { _ = conn.Close() }()
			_, _ = conn.Write([]byte("hello\n"))
		}()
	}
}

// Reach a SOCKS5 proxy over TLS: the SOCKS dialer's Forward returns TLS
// connections to the proxy.
func ExampleDialer() {
	d := &socks5.Dialer{
		ProxyAddr: "proxy.example:1080",
		Forward: &tlsconn.Dialer{
			Config:  &tls.Config{MinVersion: tls.VersionTLS12}, // ServerName defaults to proxy.example
			Forward: &net.Dialer{Timeout: 10 * time.Second},
		},
	}
	conn, err := d.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		log.Println(err)
		return
	}
	defer func() { _ = conn.Close() }()
}

// Serve TLS with a generated certificate and give its fingerprint to clients
// out of band, for example in their configuration.
func ExampleNewSelfSigned() {
	cert, err := tlsconn.NewSelfSigned(tlsconn.SelfSignedOptions{Hosts: []string{"tunnel.internal", "10.0.0.1"}})
	if err != nil {
		log.Fatal(err)
	}
	pin := tlsconn.Fingerprint(cert.Certificate[0])
	fmt.Println(len(hex.EncodeToString(pin[:])), cert.Leaf.Subject.CommonName)
	// Output: 64 tunnel.internal
}

// Trust a self-signed server by its fingerprint instead of a certificate
// authority. Pins can be added and removed while the config is in use.
func ExamplePinSet() {
	var pin [32]byte // from the server's tlsconn.Fingerprint, shared out of band
	pins := tlsconn.NewPinSet(pin)
	d := &tlsconn.Dialer{Config: pins.ClientConfig(nil)}
	conn, err := d.Dial("tcp", "tunnel.internal:443")
	if err != nil {
		log.Println(err) // tlsconn.ErrNotPinned for another certificate
		return
	}
	defer func() { _ = conn.Close() }()
}

// Serve per-host certificates from files, picking up renewals as the files
// change.
func ExampleCertFiles() {
	certs := &tlsconn.CertFiles{MaxEntries: 1000, IdleTimeout: 24 * time.Hour}
	cfg := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			dir := filepath.Join("/etc/certs", filepath.Base(hello.ServerName))
			return certs.LoadFiles(filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "privkey.pem"))
		},
	}
	ln, err := tls.Listen("tcp", ":443", cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
}

// Pick certificates by server name: added ones first, an authority-issued
// one over a self-signed one and an exact name over a wildcard, then those
// loaded on demand.
func ExampleCertStore() {
	wildcard, _ := tlsconn.NewSelfSigned(tlsconn.SelfSignedOptions{Hosts: []string{"*.example.com"}})
	store := &tlsconn.CertStore{Load: func(_ context.Context, name string) (*tls.Certificate, error) {
		if name != "shop.example.net" {
			return nil, nil // none
		}
		c, err := tlsconn.NewSelfSigned(tlsconn.SelfSignedOptions{Hosts: []string{name}})
		if err != nil {
			return nil, err
		}
		return &c, nil
	}}
	if _, err := store.Add("wildcard", &wildcard); err != nil {
		log.Fatal(err)
	}
	_ = &tls.Config{GetCertificate: store.GetCertificate}

	for _, name := range []string{"www.example.com", "shop.example.net", "other.example.org"} {
		c, err := store.GetCertificate(&tls.ClientHelloInfo{ServerName: name})
		if err != nil {
			fmt.Println(name, err)
			continue
		}
		leaf, _ := x509.ParseCertificate(c.Certificate[0])
		fmt.Println(name, leaf.DNSNames)
	}
	// Output:
	// www.example.com [*.example.com]
	// shop.example.net [shop.example.net]
	// other.example.org tlsconn: no certificate for the server name
}

// Serve the certificate that each host's configuration names, kept in sync
// with its files, and let the ranking choose for hosts that name none.
func ExampleCertStore_Select() {
	type host struct{ certID string }
	hosts := map[string]host{"a.example.com": {certID: "a-internal"}, "b.example.com": {}}
	store := &tlsconn.CertStore{
		Select: func(hello *tls.ClientHelloInfo) (string, error) {
			return hosts[hello.ServerName].certID, nil
		},
		OnError: func(err *tlsconn.CertError) { log.Println(err) },
	}
	if _, err := store.AddFiles("a-internal", "/etc/certs/a/cert.pem", "/etc/certs/a/key.pem"); err != nil {
		log.Println(err)
	}
	if _, err := store.AddFiles("wildcard", "/etc/certs/wildcard/fullchain.pem", "/etc/certs/wildcard/privkey.pem"); err != nil {
		log.Println(err)
	}
	store.SetDefault("wildcard")
	ln, err := tls.Listen("tcp", ":443", &tls.Config{GetCertificate: store.GetCertificate})
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
}
