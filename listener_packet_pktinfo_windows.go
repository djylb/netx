package netx

import "syscall"

// Packet information on Windows (WSARecvMsg, WSASendMsg): WSACMSGHDR's
// length is a SIZE_T and messages align to it; IN_PKTINFO is {addr,
// ifindex}, addr being a datagram's destination and the source of a sent
// one.
// cmsgLen is the type of struct cmsghdr's length field.
type cmsgLen = uintptr

const (
	ipPktinfoRecv       = 19 // IP_PKTINFO
	ipPktinfoSend       = 19
	ipv6Pktinfo         = 19 // IPV6_PKTINFO
	sizeofInet4Pktinfo  = 8
	sizeofInet6Pktinfo  = 20
	inet4PktinfoIfindex = 4
	inet4PktinfoSrc     = 0
	inet4PktinfoAddr    = 0
)

func setPacketInfo(fd uintptr, v6 bool) error {
	h := syscall.Handle(fd)
	if v6 {
		if err := syscall.SetsockoptInt(h, syscall.IPPROTO_IPV6, ipv6Pktinfo, 1); err != nil {
			return err
		}
		// a dual-stack socket reports IPv4 datagrams with IP_PKTINFO; an
		// IPv6-only one refuses the option, which costs nothing
		_ = syscall.SetsockoptInt(h, syscall.IPPROTO_IP, ipPktinfoRecv, 1)
		return nil
	}
	return syscall.SetsockoptInt(h, syscall.IPPROTO_IP, ipPktinfoRecv, 1)
}
