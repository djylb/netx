package proxyproto

import (
	"net"
	"testing"
)

// A negative HeaderTimeout fails the Conn and Accept.
func TestNegativeHeaderTimeout(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	c := NewConn(a, Config{HeaderTimeout: -1})
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Error("Read")
	}
	_ = c.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := &Listener{Listener: ln, Config: Config{HeaderTimeout: -1}}
	defer func() { _ = l.Close() }()
	go func() {
		if c, err := net.Dial("tcp", ln.Addr().String()); err == nil {
			_ = c.Close()
		}
	}()
	if _, err := l.Accept(); err == nil {
		t.Error("Accept")
	}
}
