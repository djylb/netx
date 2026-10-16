// Package nettest holds helpers shared by the tests of netx packages.
package nettest

import (
	"io"
	"net"
	"sync"
	"testing"
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
