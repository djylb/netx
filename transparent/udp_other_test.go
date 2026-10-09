//go:build !linux

package transparent

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
)

func TestUDPUnsupported(t *testing.T) {
	if _, err := ListenPacket(context.Background(), "127.0.0.1:0"); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("ListenPacket() error = %v", err)
	}
	if _, err := DialUDP(context.Background(), netip.MustParseAddrPort("127.0.0.1:1"), netip.MustParseAddrPort("127.0.0.1:2")); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("DialUDP() error = %v", err)
	}
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, _, _, err := ReadFromUDP(c, make([]byte, 1)); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("ReadFromUDP() error = %v", err)
	}
}
