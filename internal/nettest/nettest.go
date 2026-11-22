// Package nettest holds helpers shared by the tests of netx packages.
package nettest

import (
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
