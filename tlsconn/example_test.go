package tlsconn_test

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"path/filepath"
	"time"

	"github.com/djylb/netx/socks5"
	"github.com/djylb/netx/tlsconn"
)

// Upgrade a dialed connection with a handshake bounded by five seconds.
func ExampleClient() {
	raw, err := net.Dial("tcp", "example.com:443")
	if err != nil {
		log.Fatal(err)
	}
	// On failure raw is closed.
	conn, err := tlsconn.Client(context.Background(), raw, &tls.Config{ServerName: "example.com"}, 5*time.Second)
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
			conn, err := tlsconn.Server(context.Background(), raw, cfg, 10*time.Second)
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

// Serve per-host certificates from files, picking up renewals within an hour.
func ExampleCertCache() {
	certs := &tlsconn.CertCache{MaxEntries: 1000, ReloadInterval: time.Hour, IdleTimeout: 24 * time.Hour}
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
