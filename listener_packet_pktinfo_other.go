//go:build !linux && !darwin && !windows

package netx

import (
	"net"
	"net/netip"
)

// Elsewhere a wildcard socket replies from the address routing picks; see
// listener_packet_pktinfo.go.

const pktinfoOOB = 0

func enablePacketInfo(*net.UDPConn) bool { return false }

func packetDst([]byte) (netip.Addr, uint32) { return netip.Addr{}, 0 }

func sourceOOB(netip.Addr, uint32) []byte { return nil }
