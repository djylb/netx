package udpflow

import (
	"net"
	"syscall"
	"testing"
	"unsafe"
)

// A link-local IPv6 source read in a batch keeps its zone, from the scope
// ID that recvmmsg reports.
func TestBatchReaderKeepsZone(t *testing.T) {
	c, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skip(err)
	}
	defer func() { _ = c.Close() }()
	b := newBatchReader(c, 2, 64, 0)
	sa := (*syscall.RawSockaddrInet6)(unsafe.Pointer(&b.names[0]))
	sa.Family = syscall.AF_INET6
	sa.Addr = [16]byte{0xfe, 0x80, 15: 1}
	sa.Port = 0x3930
	sa.Scope_id = 1
	_, ap, _ := b.datagram(0)
	if ap.Addr().Zone() == "" {
		t.Fatalf("link-local source %v lost its zone (scope ID 1)", ap)
	}
}
