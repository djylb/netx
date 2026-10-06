package netx

import (
	"net"
	"testing"
)

func TestListenTCPContextAllowsNilContext(t *testing.T) {
	ln, err := ListenTCPContext(nil, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenTCPContext(nil) error = %v", err)
	}
	if err := ln.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestListenTCPAcceptsConnections(t *testing.T) {
	ln, err := ListenTCP("127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenTCP() error = %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	client, server := dialAccepted(t, ln)
	if server.LocalAddr().String() != ln.Addr().String() {
		t.Fatalf("server LocalAddr() = %v, want %v", server.LocalAddr(), ln.Addr())
	}
	if server.RemoteAddr().String() != client.LocalAddr().String() {
		t.Fatalf("server RemoteAddr() = %v, want %v", server.RemoteAddr(), client.LocalAddr())
	}
}

// dialAccepted connects to ln and returns both ends of the connection.
// Callers must close ln when the test ends.
func dialAccepted(t *testing.T, ln net.Listener) (client, server net.Conn) {
	t.Helper()

	type result struct {
		conn net.Conn
		err  error
	}
	accepted := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		accepted <- result{conn: c, err: err}
	}()

	client, err := net.Dial(ln.Addr().Network(), ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial(%v) error = %v", ln.Addr(), err)
	}
	t.Cleanup(func() { _ = client.Close() })

	r := <-accepted
	if r.err != nil {
		t.Fatalf("Accept() error = %v", r.err)
	}
	t.Cleanup(func() { _ = r.conn.Close() })
	return client, r.conn
}
