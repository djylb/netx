package transparent

import (
	"net"
	"testing"
)

// assertAccepts checks that ln accepts a connection on its own address and
// closes ln when the test ends.
func assertAccepts(t *testing.T, ln net.Listener) {
	t.Helper()
	t.Cleanup(func() { _ = ln.Close() })
	_, server := dialAccepted(t, ln)
	if server.LocalAddr().String() != ln.Addr().String() {
		t.Fatalf("server LocalAddr() = %v, want %v", server.LocalAddr(), ln.Addr())
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
