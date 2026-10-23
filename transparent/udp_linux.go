//go:build linux

package transparent

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"unsafe"

	"github.com/djylb/netx/internal/dgram"
	"github.com/djylb/netx/internal/netutil"
)

// packetErr reports no error: ListenPacket is supported.
func packetErr() error { return nil }

func readFromUDP(c *net.UDPConn, b []byte) (int, PacketInfo, error) {
	// Room for the original destination after other control messages the
	// socket may have been asked for, such as timestamps or IP_PKTINFO.
	var oob [512]byte
	n, oobn, flags, src, err := c.ReadMsgUDPAddrPort(b, oob[:])
	if err != nil {
		return n, PacketInfo{}, err
	}
	info := PacketInfo{Src: netutil.UnmapAddrPort(src)}
	laddr, _ := c.LocalAddr().(*net.UDPAddr)
	bound := netutil.UnmapAddrPort(laddr.AddrPort())
	dst, ok := origDstFromControl(oob[:oobn])
	if !ok {
		if flags&syscall.MSG_CTRUNC != 0 {
			// The local address would name the wrong destination.
			return n, info, ErrControlTruncated
		}
		info.Dst = bound
		return n, info, nil
	}
	info.Dst = dst
	if info.Redirected, err = datagramRedirected(c, dst, bound); err != nil {
		info.Redirected = false
		return n, info, fmt.Errorf("transparent: is %v local: %w", dst.Addr(), err)
	}
	return n, info, nil
}

// datagramRedirected reports whether a datagram addressed to dst reached c,
// bound to bound, through a redirect. A multicast or limited broadcast
// datagram was not. Only a redirect delivers one for
// another port, or, to a socket bound to one address, for another address.
// To a wildcard socket on its own port, a datagram was redirected unless dst
// is an address of this host, which isLocalAddrCached looks up.
func datagramRedirected(c *net.UDPConn, dst, bound netip.AddrPort) (bool, error) {
	switch {
	case isGroupAddr(dst.Addr()):
		// Broadcast and multicast reach the socket as one of their hosts;
		// a proxy must not send them on, nor answer from them.
		return false, nil
	case dst.Port() != bound.Port():
		return true, nil
	case !bound.Addr().IsUnspecified():
		return !sameAddrPort(dst, bound), nil
	}
	raw, err := c.SyscallConn()
	if err != nil {
		return false, err
	}
	return isRedirected(dst, bound, func(ip netip.Addr) (bool, error) {
		return isLocalAddrCached(raw, ip)
	})
}

// sameAddrPort reports whether a and b are the same address and port. Zones
// are ignored: one interface may be named by its name or by its index.
func sameAddrPort(a, b netip.AddrPort) bool {
	return a.Port() == b.Port() && a.Addr().WithZone("") == b.Addr().WithZone("")
}

// writeFrom sends b to to from c with from as its source address, which an
// IP_PKTINFO or IPV6_PKTINFO control message sets, so that a socket on a
// wildcard address answers from the address it was sent to rather than one
// the kernel picks for the route.
func writeFrom(c *net.UDPConn, b []byte, from, to netip.AddrPort) (int, error) {
	var oob []byte
	if ip := from.Addr().Unmap(); ip.Is4() {
		// struct in_pktinfo: ipi_ifindex, ipi_spec_dst, ipi_addr.
		oob = make([]byte, syscall.CmsgSpace(syscall.SizeofInet4Pktinfo))
		data := setCmsg(oob, syscall.IPPROTO_IP, syscall.IP_PKTINFO, syscall.SizeofInet4Pktinfo)
		a := ip.As4()
		copy(data[4:8], a[:])
	} else {
		// struct in6_pktinfo: ipi6_addr, ipi6_ifindex.
		oob = make([]byte, syscall.CmsgSpace(syscall.SizeofInet6Pktinfo))
		data := setCmsg(oob, syscall.IPPROTO_IPV6, syscall.IPV6_PKTINFO, syscall.SizeofInet6Pktinfo)
		a := ip.As16()
		copy(data[:16], a[:])
	}
	n, _, err := c.WriteMsgUDPAddrPort(b, oob, to)
	return n, err
}

// setCmsg writes the header of a control message of n bytes to oob and
// returns its data.
func setCmsg(oob []byte, level, typ, n int) []byte {
	h := (*syscall.Cmsghdr)(unsafe.Pointer(&oob[0]))
	h.Level, h.Type = int32(level), int32(typ)
	h.SetLen(syscall.CmsgLen(n))
	return oob[cmsgHeaderLen : cmsgHeaderLen+n]
}

// readDatagram waits until raw is readable, holding no buffer meanwhile, and
// reads one datagram into a buffer from dgram.Large, which the caller puts
// back.
func readDatagram(raw syscall.RawConn) (*[]byte, int, error) {
	var bp *[]byte
	var n int
	var opErr error
	err := raw.Read(func(fd uintptr) bool {
		bp = dgram.Large.Get()
		for {
			n, opErr = syscall.Read(int(fd), *bp)
			if opErr != syscall.EINTR {
				break
			}
		}
		if opErr == syscall.EAGAIN {
			dgram.Large.Put(bp)
			bp = nil
			return false
		}
		return true
	})
	if err == nil {
		err = opErr
	}
	if err != nil {
		if bp != nil {
			dgram.Large.Put(bp)
		}
		return nil, 0, err
	}
	return bp, max(n, 0), nil
}

// cmsgHeaderLen is the length of a control message header with its padding.
var cmsgHeaderLen = syscall.CmsgLen(0)

// origDstFromControl extracts IP_ORIGDSTADDR or IPV6_ORIGDSTADDR from the
// control messages of a received datagram. It walks them in place, where
// syscall.ParseSocketControlMessage would allocate for every datagram.
func origDstFromControl(oob []byte) (netip.AddrPort, bool) {
	var h syscall.Cmsghdr
	for len(oob) >= cmsgHeaderLen {
		// Copied out rather than cast, since oob need not be aligned.
		copy(unsafe.Slice((*byte)(unsafe.Pointer(&h)), unsafe.Sizeof(h)), oob)
		n := int(h.Len)
		if n < cmsgHeaderLen || n > len(oob) {
			break
		}
		data := oob[cmsgHeaderLen:n]
		switch {
		case h.Level == solIP && h.Type == ipRecvOrigDstAddr && len(data) >= 8:
			// struct sockaddr_in: family, port, address.
			ip := netip.AddrFrom4([4]byte(data[4:8]))
			return netip.AddrPortFrom(ip, binary.BigEndian.Uint16(data[2:4])), true
		case h.Level == solIPv6 && h.Type == ipv6RecvOrigDstAddr && len(data) >= 24:
			// struct sockaddr_in6: family, port, flow info, address, scope.
			ip := netip.AddrFrom16([16]byte(data[8:24]))
			if len(data) >= 28 {
				ip = ip.WithZone(scopeZone(ip, binary.NativeEndian.Uint32(data[24:28])))
			}
			return netip.AddrPortFrom(ip.Unmap(), binary.BigEndian.Uint16(data[2:4])), true
		}
		next := syscall.CmsgSpace(n - cmsgHeaderLen)
		if next >= len(oob) {
			break
		}
		oob = oob[next:]
	}
	return netip.AddrPort{}, false
}

func dialUDP(ctx context.Context, local, remote netip.AddrPort) (*net.UDPConn, error) {
	local, remote = netutil.UnmapAddrPort(local), netutil.UnmapAddrPort(remote)
	network := "udp6"
	if local.Addr().Is4() && remote.Addr().Is4() {
		network = "udp4"
	}
	d := net.Dialer{
		LocalAddr: net.UDPAddrFromAddrPort(local),
		Control: func(network, address string, c syscall.RawConn) error {
			if err := controlFD(c, func(fd int) error {
				return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			}); err != nil {
				return err
			}
			return Control(network, address, c)
		},
	}
	c, err := d.DialContext(ctx, network, remote.String())
	if err != nil {
		return nil, err
	}
	return c.(*net.UDPConn), nil
}
