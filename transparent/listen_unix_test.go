//go:build linux || freebsd

package transparent

import (
	"context"
	"errors"
	"syscall"
	"testing"
)

func TestListenSetsTransparentOption(t *testing.T) {
	ln, err := Listen(context.Background(), "127.0.0.1:0")
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		t.Skipf("transparent listening needs elevated privileges: %v", err)
	}
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	assertAccepts(t, ln)
}
