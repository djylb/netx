package tlsconn

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A load that fails, as one for a name without files does, pushes no
// working certificate out of a full cache.
func TestCertCacheFailedLoadKeepsEntries(t *testing.T) {
	dir := t.TempDir()
	c := &CertCache{MaxEntries: 2}
	for _, name := range []string{"a", "b"} {
		cert, _ := NewSelfSigned(SelfSignedOptions{})
		sub := filepath.Join(dir, name)
		if err := os.Mkdir(sub, 0o700); err != nil {
			t.Fatal(err)
		}
		certFile, keyFile := writeCert(t, sub, cert)
		if _, err := c.LoadFiles(certFile, keyFile); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.LoadFiles(filepath.Join(dir, "missing.crt"), filepath.Join(dir, "missing.key")); err == nil {
		t.Fatal("LoadFiles() of missing files succeeded")
	}
	if n := c.Len(); n != 2 {
		t.Fatalf("Len() = %d after a failed load, want the 2 certificates kept", n)
	}
}

// The longest validity does not wrap around into a certificate that has
// already expired.
func TestNewSelfSignedLongestValidity(t *testing.T) {
	cert, err := NewSelfSigned(SelfSignedOptions{ValidFor: math.MaxInt64})
	if err != nil {
		t.Fatal(err)
	}
	if cert.Leaf == nil || !cert.Leaf.NotAfter.After(time.Now().AddDate(100, 0, 0)) {
		t.Fatalf("NotAfter = %v, want centuries ahead", cert.Leaf.NotAfter)
	}
}

// Server without a config fails, closing raw, instead of panicking inside
// crypto/tls.
func TestServerNilConfig(t *testing.T) {
	raw, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	if _, err := Server(context.Background(), raw, nil, time.Second); !errors.Is(err, errNoServerConfig) {
		t.Fatalf("Server(nil config) error = %v, want %v", err, errNoServerConfig)
	}
	if _, err := raw.Write([]byte("x")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("raw Write() after a failed Server = %v, want it closed", err)
	}
}

// An address without a port, as a Forward dialer for Unix sockets takes, is
// dialed with the whole address as the server name.
func TestDialerAddressWithoutPort(t *testing.T) {
	refused := errors.New("forward called")
	var dialed string
	d := &Dialer{Forward: forwardFunc(func(_ context.Context, _, address string) (net.Conn, error) {
		dialed = address
		return nil, refused
	})}
	if _, err := d.DialContext(context.Background(), "unix", "/run/app.sock"); !errors.Is(err, refused) || dialed != "/run/app.sock" {
		t.Fatalf("DialContext() = %v after dialing %q, want the forward dialer's error", err, dialed)
	}
}

type forwardFunc func(ctx context.Context, network, address string) (net.Conn, error)

func (f forwardFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

// Loads still in flight do not count toward MaxEntries, so one that fails
// after others succeeded pushes no certificate out.
func TestCertCacheInFlightLoadDoesNotEvict(t *testing.T) {
	c := &CertCache{MaxEntries: 2}
	release := make(chan struct{})
	failed := make(chan struct{})
	go func() {
		_, _ = c.get("slow", false, func() (*tls.Certificate, error) {
			<-release
			return nil, errors.New("no such certificate")
		})
		close(failed)
	}()
	for c.Len() == 0 {
		time.Sleep(time.Millisecond) // the slow load is in flight
	}
	for _, key := range []string{"a", "b"} {
		if _, err := c.get(key, false, func() (*tls.Certificate, error) {
			cert, err := NewSelfSigned(SelfSignedOptions{})
			return &cert, err
		}); err != nil {
			t.Fatal(err)
		}
	}
	close(release)
	<-failed
	if n := c.Len(); n != 2 {
		t.Fatalf("Len() = %d, want the 2 loaded certificates", n)
	}
}
