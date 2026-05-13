package netx

import (
	"errors"
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
	GetRawConn() net.Conn
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
	if got := c.GetRawConn(); got != nil {
		t.Fatalf("%s GetRawConn() = %v, want nil", label, got)
	}
	assertClosedConnState(t, label, c)
}
