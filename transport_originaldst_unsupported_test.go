//go:build !linux && !freebsd && !darwin

package netx

import (
	"errors"
	"net"
	"testing"
)

func TestOriginalDestinationUnsupported(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	if _, err := OriginalDestination(c1); !errors.Is(err, ErrOriginalDestinationUnsupported) {
		t.Fatalf("OriginalDestination() error = %v, want %v", err, ErrOriginalDestinationUnsupported)
	}
}
