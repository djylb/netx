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

func TestTLSClientClearsHandshakeDeadline(t *testing.T) {
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

	tlsClient, err := TLSClient(context.Background(), clientConn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "example.com",
	}, 300*time.Millisecond)
	if err != nil {
		t.Fatalf("TLSClient() error = %v", err)
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

func TestTLSClientNormalizesNonPositiveTimeout(t *testing.T) {
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

	tlsClient, err := TLSClient(context.Background(), clientConn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "example.com",
	}, 0)
	if err != nil {
		t.Fatalf("TLSClient() error = %v", err)
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

// deadlineIgnoringConn accepts deadlines but never enforces them, like a
// tunnelled stream without deadline support.
type deadlineIgnoringConn struct {
	net.Conn
}

func (c *deadlineIgnoringConn) SetDeadline(time.Time) error      { return nil }
func (c *deadlineIgnoringConn) SetReadDeadline(time.Time) error  { return nil }
func (c *deadlineIgnoringConn) SetWriteDeadline(time.Time) error { return nil }

func TestTLSClientBoundsHandshakeWhenDeadlinesIgnored(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()
	defer func() { _ = clientConn.Close() }()
	// The peer swallows the ClientHello and never answers.
	go func() { _, _ = io.Copy(io.Discard, serverConn) }()

	started := time.Now()
	tlsClient, err := TLSClient(context.Background(), &deadlineIgnoringConn{Conn: clientConn}, &tls.Config{
		InsecureSkipVerify: true,
	}, 200*time.Millisecond)
	elapsed := time.Since(started)
	if err == nil {
		_ = tlsClient.Close()
		t.Fatal("TLSClient() error = nil, want handshake timeout")
	}
	if tlsClient != nil {
		t.Fatalf("TLSClient() conn = %v, want nil on error", tlsClient)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("TLSClient() error = %v, want %v", err, context.DeadlineExceeded)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("TLSClient() took %v, want about the 200ms timeout", elapsed)
	}
}

func TestTLSClientHonorsCanceledContext(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()
	defer func() { _ = clientConn.Close() }()
	go func() { _, _ = io.Copy(io.Discard, serverConn) }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := TLSClient(ctx, &deadlineIgnoringConn{Conn: clientConn}, &tls.Config{
		InsecureSkipVerify: true,
	}, time.Minute)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("TLSClient() error = %v, want %v", err, context.Canceled)
	}
}

func TestTLSServerAndClient(t *testing.T) {
	cert := testSelfSignedCert(t)
	clientRaw, serverRaw := net.Pipe()
	spy := &closeSpyConn{Conn: clientRaw}

	serverErr := make(chan error, 1)
	go func() {
		tc, err := TLSServer(context.Background(), serverRaw, &tls.Config{Certificates: []tls.Certificate{cert}}, time.Second)
		if err != nil {
			serverErr <- err
			return
		}
		buf := make([]byte, 4)
		if _, err := io.ReadFull(tc, buf); err != nil {
			serverErr <- err
			return
		}
		_, err = tc.Write(buf)
		serverErr <- err
	}()

	tc, err := TLSClient(context.Background(), spy, &tls.Config{InsecureSkipVerify: true}, time.Second)
	if err != nil {
		t.Fatalf("TLSClient() error = %v", err)
	}
	// Close the pipe itself so no close_notify waits on an unread peer.
	defer func() { _ = clientRaw.Close() }()
	defer func() { _ = serverRaw.Close() }()
	if RawConnOf(tc) != net.Conn(spy) {
		t.Fatalf("RawConnOf(tls) = %v, want the raw conn", RawConnOf(tc))
	}
	// TimeoutConn composes with the handshake helpers.
	conn := NewTimeoutConn(tc, time.Second)
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo = %q, %v", buf, err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server error = %v", err)
	}
}

func TestTLSClientFailureClosesRaw(t *testing.T) {
	cert := testSelfSignedCert(t)
	clientRaw, serverRaw := net.Pipe()
	spy := &closeSpyConn{Conn: clientRaw}
	defer func() { _ = serverRaw.Close() }()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = tls.Server(serverRaw, &tls.Config{Certificates: []tls.Certificate{cert}}).Handshake()
	}()

	// The self-signed certificate does not verify.
	conn, err := TLSClient(context.Background(), spy, &tls.Config{ServerName: "example.com"}, 2*time.Second)
	if err == nil || conn != nil {
		t.Fatalf("TLSClient() = %v, %v; want nil and a verification error", conn, err)
	}
	if !spy.isClosed() {
		t.Fatal("raw conn was not closed after the failed handshake")
	}
	<-done

	if conn, err := TLSServer(context.Background(), nil, nil, time.Second); !errors.Is(err, net.ErrClosed) || conn != nil {
		t.Fatalf("TLSServer(nil) = %v, %v; want nil, %v", conn, err, net.ErrClosed)
	}
}
