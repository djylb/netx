// Package nettest holds helpers shared by the tests of netx packages.
package nettest

import (
	"io"
	"net"
	"testing"
)

// ServeEcho echoes each connection accepted from ln until ln is closed,
// which happens when the test ends, and returns the address of ln.
func ServeEcho(t testing.TB, ln net.Listener) string {
	t.Helper()
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String()
}
