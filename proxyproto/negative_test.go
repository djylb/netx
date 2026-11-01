package proxyproto

import (
	"net"
	"testing"
	"time"

	"github.com/djylb/netx/internal/netutil"
)

// A negative HeaderTimeout means no timeout, as for
// http.Server.ReadHeaderTimeout; 0 means DefaultHeaderTimeout.
func TestNegativeHeaderTimeout(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	if c := NewConn(a, Config{HeaderTimeout: -1}); c.timeout != netutil.NoTimeout {
		t.Errorf("negative: %v", c.timeout)
	}
	if c := NewConn(a, Config{}); c.timeout != DefaultHeaderTimeout {
		t.Errorf("zero: %v", c.timeout)
	}
}

// With a negative HeaderTimeout a header that arrives late is read.
func TestNegativeHeaderTimeoutReads(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	c := NewConn(a, Config{HeaderTimeout: -1, Policy: Optional})
	defer func() { _ = c.Close() }()
	go func() {
		time.Sleep(50 * time.Millisecond)
		_, _ = b.Write([]byte("x"))
	}()
	buf := make([]byte, 1)
	if n, err := c.Read(buf); err != nil || n != 1 {
		t.Fatalf("Read = %d, %v", n, err)
	}
}
