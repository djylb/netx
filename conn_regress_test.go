package netx

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// WrapConn without a parent takes addresses and deadlines from rwc itself
// when it is a net.Conn, not from the connection beneath its wrappers.
func TestWrapConnNilParentKeepsRWCWrappers(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	override := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 4242}
	c := WrapConn(NewAddrOverrideConn(a, override, nil), nil)
	if got := c.RemoteAddr(); got != override {
		t.Fatalf("RemoteAddr() = %v, want the override %v", got, override)
	}
	if raw := RawConnOf(c); raw != a {
		t.Fatalf("RawConnOf() = %v, want the pipe", raw)
	}
	var nilConn *net.TCPConn
	if got := WrapConn(nilConn, nil); got.LocalAddr() != nil {
		t.Fatalf("WrapConn(nil *TCPConn) LocalAddr() = %v, want nil", got.LocalAddr())
	}
}

func TestPrefixConnNilState(t *testing.T) {
	var nilPrefix *PrefixConn
	for name, c := range map[string]*PrefixConn{
		"NewPrefixConn(nil)": NewPrefixConn(nil, []byte("x")),
		"nil *PrefixConn":    nilPrefix,
		"zero PrefixConn":    {},
	} {
		assertClosedConnState(t, name, c)
	}
}

// A stream Read cut short by a deadline does not keep the timeout once the
// deadline has moved: the next Read returns the rest of the frame.
func TestFramedConnShortReadTimeoutNotKept(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()
	fc := NewFramedConn(client)
	buf := make([]byte, 64)

	wrote, done := make(chan struct{}), make(chan error, 1)
	go func() { _, _ = server.Write([]byte{0, 4, 'a', 'b'}); close(wrote) }()
	go func() {
		n, err := fc.Read(buf)
		if err == nil && string(buf[:n]) != "ab" {
			err = errors.New("read " + string(buf[:n]))
		}
		done <- err
	}()
	<-wrote
	_ = fc.SetReadDeadline(time.Now())
	if err := <-done; err != nil {
		t.Fatalf("first Read: %v", err)
	}
	_ = fc.SetReadDeadline(time.Time{})
	go func() { _, _ = server.Write([]byte("cd")) }()
	if n, err := fc.Read(buf); err != nil || string(buf[:n]) != "cd" {
		t.Fatalf("Read() after clearing the deadline = %q, %v, want %q", buf[:n], err, "cd")
	}
}

// An AddrOverrideConn passes its data through unchanged, so Relay looks
// through it for splicing and WriteTo copies the wrapped connection.
func TestAddrOverrideConnPassesDataThrough(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	c := NewAddrOverrideConn(a, &net.TCPAddr{Port: 1}, nil)
	if got := unwrapPrefix(c); got != a {
		t.Fatalf("unwrapPrefix() = %v, want the wrapped conn", got)
	}
	if got := unwrapPrefixWriter(NewPrefixConn(c, nil)); got != a {
		t.Fatalf("unwrapPrefixWriter() = %v, want the wrapped conn", got)
	}
	go func() { _, _ = b.Write([]byte("hello")); _ = b.Close() }()
	var out bytes.Buffer
	if n, err := c.WriteTo(&out); err != nil || n != 5 || out.String() != "hello" {
		t.Fatalf("WriteTo() = %d, %v, %q", n, err, out.String())
	}
	var nilConn *AddrOverrideConn
	if _, err := nilConn.WriteTo(io.Discard); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("nil WriteTo() error = %v, want %v", err, net.ErrClosed)
	}
}

// RawConnOf returns nil, not a nil pointer in an interface, for a nil
// connection, so that callers can check the result against nil.
func TestRawConnOfNilPointer(t *testing.T) {
	var tcp *net.TCPConn
	if got := RawConnOf(tcp); got != nil {
		t.Fatalf("RawConnOf(nil *net.TCPConn) = %#v, want nil", got)
	}
	if got := RawConnOf(NewPrefixConn(tcp, nil)); got != nil {
		t.Fatalf("RawConnOf(PrefixConn over nil) = %#v, want nil", got)
	}
}
