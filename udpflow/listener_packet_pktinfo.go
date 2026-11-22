//go:build linux || darwin || windows

package udpflow

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"unsafe"
)

// A broadcast or multicast source can cause EINVAL even with a correctly
// formatted control message. Address classification is separate.
func isPacketSourceInvalidArgument(err error) bool {
	return errors.Is(err, errPktinfoInvalidArgument)
}

// A UDP socket bound to a wildcard address sends from the address that
// routing picks, which on a host with several addresses on the way to a
// peer need not be the one that the peer sent to; the peer, or a NAT on
// its path, then drops the reply. A PacketListener on such a socket asks
// for the destination of each datagram (IP_PKTINFO, IPV6_RECVPKTINFO) and
// sends the replies of each flow from its local destination. A socket
// bound to one address needs none of it.

// pktinfoOOB is the control buffer of one read: room for an IPv4 and an
// IPv6 packet information message.
const pktinfoOOB = 128

// enablePacketInfo turns on the destination address of received datagrams
// on c when c is bound to a wildcard address, and reports whether it did.
func enablePacketInfo(c *net.UDPConn) bool {
	if c == nil {
		return false
	}
	la, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok || la == nil || !la.IP.IsUnspecified() {
		return false
	}
	v6 := la.IP.To4() == nil
	raw, err := c.SyscallConn()
	if err != nil {
		return false
	}
	var serr error
	if err := raw.Control(func(fd uintptr) { serr = setPacketInfo(fd, v6) }); err != nil || serr != nil {
		return false
	}
	return true
}

// cmsghdr is the platform's control message header; its length field is
// cmsgLen wide.
type cmsghdr struct {
	Len   cmsgLen
	Level int32
	Type  int32
}

// cmsgAlignment is the alignment of control messages: that of the length
// field.
const cmsgAlignment = int(unsafe.Sizeof(cmsgLen(0)))

// cmsgAlign rounds n up to the alignment of control messages.
func cmsgAlign(n int) int { return (n + cmsgAlignment - 1) &^ (cmsgAlignment - 1) }

// cmsgHdrLen is the aligned length of a control message header.
func cmsgHdrLen() int { return cmsgAlign(int(unsafe.Sizeof(cmsghdr{}))) }

// readCmsghdr decodes the header at the start of b, which holds at least
// cmsgHdrLen bytes.
func readCmsghdr(b []byte) cmsghdr {
	var h cmsghdr
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&h)), unsafe.Sizeof(h)), b)
	return h
}

// putCmsg returns the control message of level and typ carrying data.
func putCmsg(level, typ int32, data []byte) []byte {
	hl := cmsgHdrLen()
	b := make([]byte, hl+cmsgAlign(len(data)))
	h := cmsghdr{Len: cmsgLen(hl + len(data)), Level: level, Type: typ}
	copy(b, unsafe.Slice((*byte)(unsafe.Pointer(&h)), unsafe.Sizeof(h)))
	copy(b[hl:], data)
	return b
}

// packetDst returns the destination address that the packet information
// in oob carries, unmapped, and its interface index; the zero Addr when
// there is none.
func packetDst(oob []byte) (netip.Addr, uint32) {
	hl := cmsgHdrLen()
	for len(oob) >= hl {
		h := readCmsghdr(oob)
		n, level, typ := int(h.Len), h.Level, h.Type
		if n < hl || n > len(oob) {
			return netip.Addr{}, 0
		}
		data := oob[hl:n]
		switch {
		case level == syscall.IPPROTO_IP && typ == ipPktinfoRecv && len(data) >= sizeofInet4Pktinfo:
			a := netip.AddrFrom4([4]byte(data[inet4PktinfoAddr : inet4PktinfoAddr+4]))
			return a, binary.NativeEndian.Uint32(data[inet4PktinfoIfindex:])
		case level == syscall.IPPROTO_IPV6 && typ == ipv6Pktinfo && len(data) >= sizeofInet6Pktinfo:
			a := netip.AddrFrom16([16]byte(data[:16])).Unmap()
			return a, binary.NativeEndian.Uint32(data[16:])
		}
		oob = oob[min(cmsgAlign(n), len(oob)):]
	}
	return netip.Addr{}, 0
}

// sourceOOB returns the control message that sends a datagram from src;
// ifindex is the interface of a link-local src, ignored otherwise. An
// IPv4 src takes an IPv4 message on an IPv6 socket too: its IPv4 output
// reads IPv4 messages only.
func sourceOOB(src netip.Addr, ifindex uint32) []byte {
	if src.Is4() {
		var info [sizeofInet4Pktinfo]byte
		a := src.As4()
		copy(info[inet4PktinfoSrc:], a[:])
		if src.IsLinkLocalUnicast() {
			binary.NativeEndian.PutUint32(info[inet4PktinfoIfindex:], ifindex)
		}
		return putCmsg(syscall.IPPROTO_IP, ipPktinfoSend, info[:])
	}
	var info [sizeofInet6Pktinfo]byte
	a := src.As16()
	copy(info[:16], a[:])
	if src.IsLinkLocalUnicast() {
		binary.NativeEndian.PutUint32(info[16:], ifindex)
	}
	return putCmsg(syscall.IPPROTO_IPV6, ipv6Pktinfo, info[:])
}
