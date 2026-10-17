//go:build darwin

package transparent

import (
	"context"
	"errors"
	"testing"
)

func TestListenOnDarwin(t *testing.T) {
	ln, err := Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	assertAccepts(t, ln)
}

// pf rdr needs no socket option, and UDP is not supported.
func TestControlOnDarwin(t *testing.T) {
	if err := Control("tcp4", "127.0.0.1:0", nil); err != nil {
		t.Errorf("Control() error = %v, want nil", err)
	}
	if err := ControlPacket("udp4", "127.0.0.1:0", nil); !errors.Is(err, ErrListenUnsupported) {
		t.Errorf("ControlPacket() error = %v, want %v", err, ErrListenUnsupported)
	}
}
