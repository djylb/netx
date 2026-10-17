package tlsconn

import (
	"context"
	"errors"
	"io"
	"math"
	"net"
	"testing"
	"time"
)

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
	if _, err := Server(context.Background(), raw, nil); !errors.Is(err, errNoServerConfig) {
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
