//go:build linux || darwin || windows

package netx

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"syscall"
	"testing"
)

// A received packet information message is read as its destination, on
// every platform's layout.
func TestPacketInfoRead(t *testing.T) {
	v4 := netip.MustParseAddr("192.0.2.7")
	var info4 [sizeofInet4Pktinfo]byte
	a4 := v4.As4()
	copy(info4[inet4PktinfoAddr:], a4[:])
	binary.NativeEndian.PutUint32(info4[inet4PktinfoIfindex:], 3)
	v6 := netip.MustParseAddr("2001:db8::7")
	var info6 [sizeofInet6Pktinfo]byte
	a6 := v6.As16()
	copy(info6[:16], a6[:])
	binary.NativeEndian.PutUint32(info6[16:], 4)
	mapped := netip.AddrFrom16(v4.As16())
	var infoMapped [sizeofInet6Pktinfo]byte
	am := mapped.As16()
	copy(infoMapped[:16], am[:])
	for _, tc := range []struct {
		want    netip.Addr
		name    string
		oob     []byte
		ifindex uint32
	}{
		{oob: putCmsg(syscall.IPPROTO_IP, ipPktinfoRecv, info4[:]), name: "ipv4", want: v4, ifindex: 3},
		{oob: putCmsg(syscall.IPPROTO_IPV6, ipv6Pktinfo, info6[:]), name: "ipv6", want: v6, ifindex: 4},
		{oob: putCmsg(syscall.IPPROTO_IPV6, ipv6Pktinfo, infoMapped[:]), name: "ipv4-mapped", want: v4},
		{oob: append(putCmsg(syscall.IPPROTO_IP, 999, []byte{1, 2, 3}), putCmsg(syscall.IPPROTO_IPV6, ipv6Pktinfo, info6[:])...), name: "after another message", want: v6, ifindex: 4},
	} {
		got, ifindex := packetDst(tc.oob)
		if got != tc.want || ifindex != tc.ifindex {
			t.Errorf("%s: read %v ifindex %d, want %v %d", tc.name, got, ifindex, tc.want, tc.ifindex)
		}
	}
	if got, _ := packetDst(nil); got.IsValid() {
		t.Errorf("no message: read %v", got)
	}
	short := putCmsg(syscall.IPPROTO_IPV6, ipv6Pktinfo, info6[:])
	if got, _ := packetDst(short[:len(short)-8]); got.IsValid() {
		t.Errorf("truncated message: read %v", got)
	}
}

// The message that a reply carries names its source where the platform
// reads it: IPv4 sources in an IPv4 message, IPv6 ones with the interface
// of a link-local address.
func TestPacketInfoSource(t *testing.T) {
	hl := cmsgHdrLen()
	v4 := netip.MustParseAddr("192.0.2.7")
	oob := sourceOOB(v4, 5)
	h := readCmsghdr(oob)
	a4 := v4.As4()
	if h.Level != syscall.IPPROTO_IP || h.Type != ipPktinfoSend || int(h.Len) != hl+sizeofInet4Pktinfo ||
		!bytes.Equal(oob[hl+inet4PktinfoSrc:hl+inet4PktinfoSrc+4], a4[:]) {
		t.Errorf("ipv4 source: header %+v, message % x", h, oob)
	}
	ll := netip.MustParseAddr("fe80::7")
	oob = sourceOOB(ll, 5)
	if got, ifindex := packetDst(oob); got != ll || ifindex != 5 {
		t.Errorf("link-local source: read back %v ifindex %d", got, ifindex)
	}
	g := netip.MustParseAddr("2001:db8::7")
	oob = sourceOOB(g, 5)
	if got, ifindex := packetDst(oob); got != g || ifindex != 0 {
		t.Errorf("global source: read back %v ifindex %d", got, ifindex)
	}
}
