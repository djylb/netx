package udpflow

import "syscall"

// Packet information on Linux and Android: struct cmsghdr's length is a
// size_t and messages align to it; struct in_pktinfo is {ifindex,
// spec_dst, addr}, where addr is a datagram's destination and spec_dst
// the source of a sent one.
// cmsgLen is the type of struct cmsghdr's length field.
type cmsgLen = uintptr

const (
	pktinfoInvalidArgument = syscall.EINVAL
	ipPktinfoRecv          = syscall.IP_PKTINFO
	ipPktinfoSend          = syscall.IP_PKTINFO
	ipv6Pktinfo            = syscall.IPV6_PKTINFO
	sizeofInet4Pktinfo     = 12
	sizeofInet6Pktinfo     = 20
	inet4PktinfoIfindex    = 0
	inet4PktinfoSrc        = 4
	inet4PktinfoAddr       = 8
)

func setPacketInfo(fd uintptr, v6 bool) error {
	if v6 {
		// IPv4 datagrams of a dual-stack socket come with an IPv6 message
		// holding the IPv4-mapped destination.
		return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_RECVPKTINFO, 1)
	}
	return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_PKTINFO, 1)
}
