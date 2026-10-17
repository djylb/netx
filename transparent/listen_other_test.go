//go:build !linux && !freebsd && !darwin

package transparent

import (
	"context"
	"errors"
	"testing"
)

func TestListenUnsupported(t *testing.T) {
	_, err := Listen(context.Background(), "tcp", "127.0.0.1:0")
	if !errors.Is(err, ErrListenUnsupported) || !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("Listen() error = %v, want %v", err, ErrListenUnsupported)
	}
}

func TestControlUnsupported(t *testing.T) {
	if err := Control("tcp4", "127.0.0.1:0", nil); !errors.Is(err, ErrListenUnsupported) {
		t.Errorf("Control() error = %v, want %v", err, ErrListenUnsupported)
	}
	if err := ControlPacket("udp4", "127.0.0.1:0", nil); !errors.Is(err, ErrListenUnsupported) {
		t.Errorf("ControlPacket() error = %v, want %v", err, ErrListenUnsupported)
	}
}
