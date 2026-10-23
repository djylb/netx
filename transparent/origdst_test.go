package transparent

import (
	"errors"
	"net"
	"testing"
)

func TestOriginalDestinationRejectsNilConn(t *testing.T) {
	if _, _, err := OriginalDestination(nil); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("OriginalDestination(nil) error = %v, want %v", err, net.ErrClosed)
	}
	var tcp *net.TCPConn
	if _, _, err := OriginalDestination(tcp); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("OriginalDestination(nil *net.TCPConn) error = %v, want %v", err, net.ErrClosed)
	}
}

// netConnOf is a wrapper whose NetConn method returns next, or itself.
type netConnOf struct {
	net.Conn
	next net.Conn
}

func (c *netConnOf) NetConn() net.Conn {
	if c.next == nil {
		return c
	}
	return c.next
}

// Unwrapping stops at a nil pointer beneath a wrapper and at a wrapper that
// leads back to itself.
func TestInnermost(t *testing.T) {
	var tcp *net.TCPConn
	if got := innermost(&netConnOf{next: tcp}); got != nil {
		t.Fatalf("innermost(wrapper of nil *net.TCPConn) = %v, want nil", got)
	}
	loop := &netConnOf{}
	if got := innermost(loop); got != loop {
		t.Fatalf("innermost(cyclic wrapper) = %v, want the wrapper", got)
	}
	inner := &net.TCPConn{}
	if got := innermost(&netConnOf{next: &netConnOf{next: inner}}); got != inner {
		t.Fatalf("innermost(two wrappers) = %v, want the connection beneath them", got)
	}
}
