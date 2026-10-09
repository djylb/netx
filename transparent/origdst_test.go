package transparent

import (
	"errors"
	"net"
	"testing"
)

func TestOriginalDestinationRejectsNilConn(t *testing.T) {
	if _, err := OriginalDestination(nil); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("OriginalDestination(nil) error = %v, want %v", err, net.ErrClosed)
	}
}
