// Package nettest holds helpers shared by the tests of netx packages.
package nettest

import (
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// ServeEcho echoes each connection accepted from ln until the test ends,
// when it closes ln and the accepted connections and waits for its
// goroutines, and returns the address of ln.
func ServeEcho(t testing.TB, ln net.Listener) string {
	t.Helper()
	var (
		mu     sync.Mutex
		conns  []net.Conn
		closed bool
		wg     sync.WaitGroup
	)
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		closed = true
		for _, c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			if closed {
				// Accepted as the test ended.
				mu.Unlock()
				_ = c.Close()
				return
			}
			conns = append(conns, c)
			mu.Unlock()
			wg.Go(func() {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c)
			})
		}
	})
	return ln.Addr().String()
}

// AcceptWithin returns the next connection of l, failing the test if none
// comes within 2s.
func AcceptWithin(t testing.TB, l net.Listener) net.Conn {
	t.Helper()
	type result struct {
		c   net.Conn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := l.Accept()
		ch <- result{c, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("Accept() error = %v", r.err)
		}
		return r.c
	case <-time.After(2 * time.Second):
		t.Fatal("Accept() returned no connection within 2s")
		return nil
	}
}

// listenTCP opens a loopback listener with an ephemeral port.
func listenTCP(t testing.TB) net.Listener {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

// TCPPair returns the client and server ends of a loopback connection.
// Both ends are closed during test cleanup.
func TCPPair(t testing.TB) (net.Conn, net.Conn) {
	t.Helper()
	ln := listenTCP(t)
	defer func() { _ = ln.Close() }()
	var d net.Dialer
	client, err := d.DialContext(t.Context(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	server, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return client, server
}

// Serve runs a server on loopback and checks its result after closing it.
func Serve(t testing.TB, s interface {
	Serve(ln net.Listener) error
	Close() error
}, closed error) string {
	t.Helper()
	ln := listenTCP(t)
	done := make(chan error, 1)
	go func() { done <- s.Serve(ln) }()
	t.Cleanup(func() {
		_ = s.Close()
		_ = ln.Close()
		if err := <-done; !errors.Is(err, closed) {
			t.Errorf("Serve() = %v, want %v", err, closed)
		}
	})
	return ln.Addr().String()
}
