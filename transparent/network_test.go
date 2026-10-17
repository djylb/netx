package transparent

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestListenRejectsNetwork(t *testing.T) {
	var unknown net.UnknownNetworkError
	for _, network := range []string{"", "udp", "tcp5", "unix", "ip4"} {
		if _, err := Listen(context.Background(), network, "127.0.0.1:0"); !errors.As(err, &unknown) {
			t.Errorf("Listen(%q) error = %v, want UnknownNetworkError", network, err)
		}
	}
	for _, network := range []string{"", "tcp", "udp5", "unixgram"} {
		if _, err := ListenPacket(context.Background(), network, "127.0.0.1:0"); !errors.As(err, &unknown) {
			t.Errorf("ListenPacket(%q) error = %v, want UnknownNetworkError", network, err)
		}
	}
}
