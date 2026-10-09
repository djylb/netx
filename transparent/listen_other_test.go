//go:build !linux && !freebsd && !darwin

package transparent

import (
	"context"
	"errors"
	"testing"
)

func TestListenUnsupported(t *testing.T) {
	_, err := Listen(context.Background(), "127.0.0.1:0")
	if !errors.Is(err, ErrListenUnsupported) || !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("Listen() error = %v, want %v", err, ErrListenUnsupported)
	}
}
