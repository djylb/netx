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
