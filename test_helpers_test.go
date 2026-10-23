package netx

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

type dummyAddr string

func (a dummyAddr) Network() string { return "tcp" }
func (a dummyAddr) String() string  { return string(a) }

type fakeNetError struct {
	msg       string
	temporary bool
	timeout   bool
}

func (e fakeNetError) Error() string   { return e.msg }
func (e fakeNetError) Temporary() bool { return e.temporary }
func (e fakeNetError) Timeout() bool   { return e.timeout }

type connStateProbe interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

type rawConnStateProbe interface {
	connStateProbe
	NetConn() net.Conn
}

func assertClosedConnState(t *testing.T, label string, c connStateProbe) {
	t.Helper()
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("%s Read() error = %v, want %v", label, err, net.ErrClosed)
	}
	if _, err := c.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("%s Write() error = %v, want %v", label, err, net.ErrClosed)
	}
	if err := c.SetDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("%s SetDeadline() error = %v, want %v", label, err, net.ErrClosed)
	}
	if err := c.SetReadDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("%s SetReadDeadline() error = %v, want %v", label, err, net.ErrClosed)
	}
	if err := c.SetWriteDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("%s SetWriteDeadline() error = %v, want %v", label, err, net.ErrClosed)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("%s Close() error = %v, want nil", label, err)
	}
	if got := c.LocalAddr(); got != nil {
		t.Fatalf("%s LocalAddr() = %v, want nil", label, got)
	}
	if got := c.RemoteAddr(); got != nil {
		t.Fatalf("%s RemoteAddr() = %v, want nil", label, got)
	}
}

func assertClosedRawConnState(t *testing.T, label string, c rawConnStateProbe) {
	t.Helper()
	if got := c.NetConn(); got != nil {
		t.Fatalf("%s RawConn() = %v, want nil", label, got)
	}
	assertClosedConnState(t, label, c)
}

// copyPlain copies src to dst as Relay and Copy do without a flow.
func copyPlain(dst io.Writer, src io.Reader) (int64, error) {
	return relayDirection(context.Background(), dst, src, nil)
}

// spliceable reports whether a copy from src to dst would splice.
func spliceable(dst io.Writer, src io.Reader) bool {
	var d relaySink
	d.init(dst)
	return canSplice(&d, newRelaySource(src))
}

// copyDatagramsOf copies src to dst as datagrams, as a relay does.
func copyDatagramsOf(ctx context.Context, dst io.Writer, src io.Reader, f *RelayFlow) (int64, error) {
	return copyDatagrams(ctx, dst, newRelaySource(src), f)
}

// sinkWriter returns what a copy into dst writes.
func sinkWriter(dst io.Writer) io.Writer {
	var d relaySink
	d.init(dst)
	return d.w
}
