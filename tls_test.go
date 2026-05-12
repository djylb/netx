package netx

import (
	"context"
	"crypto/tls"
	"errors"
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

func TestTlsConnHelpersHandleNilState(t *testing.T) {
	var nilConn *TlsConn
	if got := nilConn.GetRawConn(); got != nil {
		t.Fatalf("nil GetRawConn() = %v, want nil", got)
	}
	if got := nilConn.LocalAddr(); got != nil {
		t.Fatalf("nil LocalAddr() = %v, want nil", got)
	}
	if got := nilConn.RemoteAddr(); got != nil {
		t.Fatalf("nil RemoteAddr() = %v, want nil", got)
	}
	if _, err := nilConn.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("nil Read() error = %v, want %v", err, net.ErrClosed)
	}
	if _, err := nilConn.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("nil Write() error = %v, want %v", err, net.ErrClosed)
	}
	if err := nilConn.SetDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("nil SetDeadline() error = %v, want %v", err, net.ErrClosed)
	}
	if err := nilConn.SetReadDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("nil SetReadDeadline() error = %v, want %v", err, net.ErrClosed)
	}
	if err := nilConn.SetWriteDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("nil SetWriteDeadline() error = %v, want %v", err, net.ErrClosed)
	}

	malformed := &TlsConn{}
	if got := malformed.GetRawConn(); got != nil {
		t.Fatalf("malformed GetRawConn() = %v, want nil", got)
	}
	if got := malformed.LocalAddr(); got != nil {
		t.Fatalf("malformed LocalAddr() = %v, want nil", got)
	}
	if got := malformed.RemoteAddr(); got != nil {
		t.Fatalf("malformed RemoteAddr() = %v, want nil", got)
	}
	if _, err := malformed.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("malformed Read() error = %v, want %v", err, net.ErrClosed)
	}
	if _, err := malformed.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("malformed Write() error = %v, want %v", err, net.ErrClosed)
	}
	if err := malformed.SetDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("malformed SetDeadline() error = %v, want %v", err, net.ErrClosed)
	}
	if err := malformed.SetReadDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("malformed SetReadDeadline() error = %v, want %v", err, net.ErrClosed)
	}
	if err := malformed.SetWriteDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("malformed SetWriteDeadline() error = %v, want %v", err, net.ErrClosed)
	}
}
