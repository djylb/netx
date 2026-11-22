package netx

import "syscall"

// Packet information on macOS and iOS: struct cmsghdr's length is a
// socklen_t and messages align to 4 bytes; struct in_pktinfo is
// {ifindex, spec_dst, addr} as on Linux.
// cmsgLen is the type of struct cmsghdr's length field.
type cmsgLen = uint32

const (
	pktinfoInvalidArgument = syscall.EINVAL
	ipPktinfoRecv          = 26 // IP_RECVPKTINFO, the type of the message too
	ipPktinfoSend          = 26 // IP_PKTINFO
	ipv6Pktinfo            = 46 // IPV6_PKTINFO
	ipv6RecvPktinfo        = 61 // IPV6_RECVPKTINFO
	sizeofInet4Pktinfo     = 12
	sizeofInet6Pktinfo     = 20
	inet4PktinfoIfindex    = 0
	inet4PktinfoSrc        = 4
	inet4PktinfoAddr       = 8
)

func setPacketInfo(fd uintptr, v6 bool) error {
	if v6 {
		return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, ipv6RecvPktinfo, 1)
	}
	return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, ipPktinfoRecv, 1)
}
