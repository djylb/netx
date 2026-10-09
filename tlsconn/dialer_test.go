package tlsconn

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// forwardTo dials target whatever address it is asked for, recording it, as a
// proxy dialer does.
type forwardTo struct {
	target string
	asked  []string
	conns  []*closeSpyConn
}

func (f *forwardTo) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	f.asked = append(f.asked, address)
	c, err := (&net.Dialer{}).DialContext(ctx, network, f.target)
	if err != nil {
		return nil, err
	}
	spy := &closeSpyConn{Conn: c}
	f.conns = append(f.conns, spy)
	return spy, nil
}

// tlsEcho serves TLS with cert and echoes each connection.
func tlsEcho(t *testing.T, cert tls.Certificate) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String()
}

func TestDialerServerNameFromAddress(t *testing.T) {
	cert := testSelfSignedCert(t)
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	forward := &forwardTo{target: tlsEcho(t, cert)}
	cfg := &tls.Config{RootCAs: roots}
	d := &Dialer{Config: cfg, Forward: forward}

	// The certificate is for localhost, which comes from the dialed address.
	c, err := d.DialContext(context.Background(), "tcp", "localhost:443")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	tc, ok := c.(*tls.Conn)
	if !ok || tc.ConnectionState().ServerName != "localhost" {
		t.Fatalf("DialContext() = %T with server name %q", c, tc.ConnectionState().ServerName)
	}
	if _, err := io.WriteString(c, "ping"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo = %q, %v", buf, err)
	}
	_ = c.Close()
	if cfg.ServerName != "" || len(forward.asked) != 1 || forward.asked[0] != "localhost:443" {
		t.Fatalf("config server name %q, forward asked %v", cfg.ServerName, forward.asked)
	}

	// A configured ServerName wins, and a failed handshake closes the
	// connection.
	d.Config = &tls.Config{RootCAs: roots, ServerName: "example.com"}
	c, err = d.DialContext(context.Background(), "tcp", "localhost:443")
	var certErr *tls.CertificateVerificationError
	if !errors.As(err, &certErr) || c != nil {
		t.Fatalf("DialContext(example.com) = %v, %v; want a certificate error", c, err)
	}
	if spy := forward.conns[len(forward.conns)-1]; !spy.isClosed() {
		t.Fatal("connection not closed after the failed handshake")
	}
}

func TestDialerErrors(t *testing.T) {
	d := &Dialer{Forward: &forwardTo{target: "127.0.0.1:1"}}
	if _, err := d.Dial("tcp", "no-port"); err == nil {
		t.Error("address without port accepted")
	}
	if c, err := d.Dial("tcp", "localhost:1"); err == nil || c != nil {
		t.Errorf("Dial(closed port) = %v, %v; want the forward error", c, err)
	}

	// The handshake is bounded by Timeout when the peer stays silent.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_, _ = io.Copy(io.Discard, c)
			_ = c.Close()
		}
	}()
	start := time.Now()
	d = &Dialer{Config: &tls.Config{InsecureSkipVerify: true}, Timeout: 100 * time.Millisecond}
	if _, err := d.Dial("tcp", ln.Addr().String()); err == nil || time.Since(start) > 2*time.Second {
		t.Fatalf("silent peer: error = %v after %v", err, time.Since(start))
	}
}
