package netx

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestNewTLSConnClearsHandshakeDeadline(t *testing.T) {
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

	tlsClient, err := NewTLSConn(clientConn, 300*time.Millisecond, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "example.com",
	})
	if err != nil {
		t.Fatalf("NewTLSConn() error = %v", err)
	}
	defer func() { _ = tlsClient.Close() }()
	// Close the peer first so close_notify fails at once instead of
	// blocking on the unread pipe until tls.Conn's 5s close deadline.
	defer func() { _ = serverConn.Close() }()

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

func TestNewTLSConnContextNormalizesNonPositiveTimeout(t *testing.T) {
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

	tlsClient, err := NewTLSConnContext(context.Background(), clientConn, 0, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "example.com",
	})
	if err != nil {
		t.Fatalf("NewTLSConnContext() error = %v", err)
	}
	defer func() { _ = tlsClient.Close() }()
	// Close the peer first so close_notify fails at once instead of
	// blocking on the unread pipe until tls.Conn's 5s close deadline.
	defer func() { _ = serverConn.Close() }()

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

func TestTLSConnHelpersHandleNilState(t *testing.T) {
	var nilConn *TLSConn
	assertClosedRawConnState(t, "nil", nilConn)

	malformed := &TLSConn{}
	assertClosedRawConnState(t, "malformed", malformed)
}

// deadlineIgnoringConn accepts deadlines but never enforces them, like a
// tunnelled stream without deadline support.
type deadlineIgnoringConn struct {
	net.Conn
}

func (c *deadlineIgnoringConn) SetDeadline(time.Time) error      { return nil }
func (c *deadlineIgnoringConn) SetReadDeadline(time.Time) error  { return nil }
func (c *deadlineIgnoringConn) SetWriteDeadline(time.Time) error { return nil }

func TestNewTLSConnContextBoundsHandshakeWhenDeadlinesIgnored(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()
	defer func() { _ = clientConn.Close() }()
	// The peer swallows the ClientHello and never answers.
	go func() { _, _ = io.Copy(io.Discard, serverConn) }()

	started := time.Now()
	tlsClient, err := NewTLSConnContext(context.Background(), &deadlineIgnoringConn{Conn: clientConn}, 200*time.Millisecond, &tls.Config{
		InsecureSkipVerify: true,
	})
	elapsed := time.Since(started)
	if err == nil {
		_ = tlsClient.Close()
		t.Fatal("NewTLSConnContext() error = nil, want handshake timeout")
	}
	if tlsClient != nil {
		t.Fatalf("NewTLSConnContext() conn = %v, want nil on error", tlsClient)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("NewTLSConnContext() error = %v, want %v", err, context.DeadlineExceeded)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("NewTLSConnContext() took %v, want about the 200ms timeout", elapsed)
	}
}

func TestNewTLSConnContextHonorsCanceledContext(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()
	defer func() { _ = clientConn.Close() }()
	go func() { _, _ = io.Copy(io.Discard, serverConn) }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := NewTLSConnContext(ctx, &deadlineIgnoringConn{Conn: clientConn}, time.Minute, &tls.Config{
		InsecureSkipVerify: true,
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("NewTLSConnContext() error = %v, want %v", err, context.Canceled)
	}
}
