//go:build !linux && !freebsd && !darwin

package transparent

import (
	"errors"
	"net"
	"testing"
)

func TestOriginalDestinationUnsupported(t *testing.T) {
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close() }()
	defer func() { _ = c2.Close() }()

	if _, err := OriginalDestination(c1); !errors.Is(err, ErrOriginalDestinationUnsupported) || !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("OriginalDestination() error = %v, want %v", err, ErrOriginalDestinationUnsupported)
	}
}
