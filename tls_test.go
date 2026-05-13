package netx

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"
)

func TestNewTlsConnClearsHandshakeDeadline(t *testing.T) {
	cert := testSelfSignedCert(t)
	serverConn, clientConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()
	defer func() { _ = clientConn.Close() }()

	errCh := make(chan error, 1)
	go func() {
		tlsServer := tls.Server(serverConn, &tls.Config{Certificates: []tls.Certificate{cert}})
		if err := tlsServer.Handshake(); err != nil {
			errCh <- err
			return
		}
		time.Sleep(450 * time.Millisecond)
		_, err := tlsServer.Write([]byte("x"))
		errCh <- err
	}()

	tlsClient, err := NewTlsConn(clientConn, 300*time.Millisecond, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "example.com",
	})
	if err != nil {
		t.Fatalf("NewTlsConn() error = %v", err)
	}
	defer func() { _ = tlsClient.Close() }()

	buf := make([]byte, 1)
	if _, err := tlsClient.Read(buf); err != nil {
		t.Fatalf("Read() error = %v, want successful read after handshake deadline expires", err)
	}
	if got := string(buf); got != "x" {
		t.Fatalf("Read() byte = %q, want %q", got, "x")
	}

	if err := <-errCh; err != nil {
		t.Fatalf("server TLS flow error = %v", err)
	}
}

func TestNewTlsConnContextNormalizesNonPositiveTimeout(t *testing.T) {
	cert := testSelfSignedCert(t)
	serverConn, clientConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()
	defer func() { _ = clientConn.Close() }()

	errCh := make(chan error, 1)
	go func() {
		tlsServer := tls.Server(serverConn, &tls.Config{Certificates: []tls.Certificate{cert}})
		if err := tlsServer.Handshake(); err != nil {
			errCh <- err
			return
		}
		_, err := tlsServer.Write([]byte("y"))
		errCh <- err
	}()

	tlsClient, err := NewTlsConnContext(context.Background(), clientConn, 0, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "example.com",
	})
	if err != nil {
		t.Fatalf("NewTlsConnContext() error = %v", err)
	}
	defer func() { _ = tlsClient.Close() }()

	buf := make([]byte, 1)
	if _, err := tlsClient.Read(buf); err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if got := string(buf); got != "y" {
		t.Fatalf("Read() byte = %q, want %q", got, "y")
	}

	if err := <-errCh; err != nil {
		t.Fatalf("server TLS flow error = %v", err)
	}
}

func TestGetTlsConn(t *testing.T) {
	cert := testSelfSignedCert(t)
	serverConn, clientConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()
	defer func() { _ = clientConn.Close() }()

	errCh := make(chan error, 1)
	go func() {
		tlsServer := tls.Server(serverConn, &tls.Config{Certificates: []tls.Certificate{cert}})
		errCh <- tlsServer.Handshake()
	}()

	tlsClient, err := GetTlsConn(clientConn, "localhost:443", false)
	if err != nil {
		t.Fatalf("GetTlsConn() error = %v", err)
	}
	defer func() { _ = tlsClient.Close() }()

	if err := <-errCh; err != nil {
		t.Fatalf("server TLS handshake error = %v", err)
	}
}

func TestTlsConnHelpersHandleNilState(t *testing.T) {
	var nilConn *TlsConn
	assertClosedRawConnState(t, "nil", nilConn)

	malformed := &TlsConn{}
	assertClosedRawConnState(t, "malformed", malformed)
}
