//go:build !linux

package netx

import (
	"net"
	"net/netip"
)

// batchReader reads several datagrams with one system call; see
// listener_packet_batch_linux.go. Elsewhere there is none.
type batchReader struct{}

func newBatchReader(_ *net.UDPConn, _, _, _ int) *batchReader { return nil }

func (*batchReader) read() (int, error) { return 0, nil }

func (*batchReader) datagram(_ int) ([]byte, netip.AddrPort, []byte) {
	return nil, netip.AddrPort{}, nil
}
