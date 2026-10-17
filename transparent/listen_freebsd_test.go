package transparent

import (
	"errors"
	"testing"
)

func TestControlPacketUnsupportedOnFreeBSD(t *testing.T) {
	if err := ControlPacket("udp4", "127.0.0.1:0", nil); !errors.Is(err, ErrListenUnsupported) {
		t.Errorf("ControlPacket() error = %v, want %v", err, ErrListenUnsupported)
	}
}
