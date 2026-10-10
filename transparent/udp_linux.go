//go:build linux

package transparent

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"unsafe"
)

const (
	ipRecvOrigDstAddr   = 0x14 // IP_RECVORIGDSTADDR, also the IP_ORIGDSTADDR message type
	ipv6RecvOrigDstAddr = 0x4a // IPV6_RECVORIGDSTADDR, also IPV6_ORIGDSTADDR
)

func listenPacket(ctx context.Context, address string) (*net.UDPConn, error) {
	lc := net.ListenConfig{Control: controlSocket(func(fd int) error {
		if err := setTransparent(fd); err != nil {
			return err
		}
		return setOptions(fd, []sockopt{
			{level: solIP, name: ipRecvOrigDstAddr},
			{level: solIPv6, name: ipv6RecvOrigDstAddr},
		})
	})}
	pc, err := lc.ListenPacket(ctx, "udp", address)
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}

func readFromUDP(c *net.UDPConn, b []byte) (int, netip.AddrPort, netip.AddrPort, error) {
	// Room for the original destination after other control messages the
	// socket may have been asked for, such as timestamps or IP_PKTINFO.
	var oob [512]byte
	n, oobn, flags, src, err := c.ReadMsgUDPAddrPort(b, oob[:])
	if err != nil {
		return n, netip.AddrPort{}, netip.AddrPort{}, err
	}
	src = unmapAddrPort(src)
	if dst, ok := origDstFromControl(oob[:oobn]); ok {
		return n, src, dst, nil
	}
	if flags&syscall.MSG_CTRUNC != 0 {
		// The local address would name the wrong destination.
		return n, src, netip.AddrPort{}, ErrControlTruncated
	}
	local, _ := c.LocalAddr().(*net.UDPAddr)
	return n, src, unmapAddrPort(local.AddrPort()), nil
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
	local, remote = unmapAddrPort(local), unmapAddrPort(remote)
	network := "udp6"
	if local.Addr().Is4() && remote.Addr().Is4() {
		network = "udp4"
	}
	d := net.Dialer{
		LocalAddr: net.UDPAddrFromAddrPort(local),
		Control: controlSocket(func(fd int) error {
			if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
				return err
			}
			return setTransparent(fd)
		}),
	}
	c, err := d.DialContext(ctx, network, remote.String())
	if err != nil {
		return nil, err
	}
	return c.(*net.UDPConn), nil
}

func unmapAddrPort(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// setTransparent sets IP_TRANSPARENT and IPV6_TRANSPARENT where the socket
// family has them.
func setTransparent(fd int) error {
	return setOptions(fd, []sockopt{
		{level: solIP, name: ipTransparent},
		{level: solIPv6, name: ipv6Transparent},
	})
}

type sockopt struct {
	level int
	name  int
}

// setOptions enables boolean socket options, skipping those the socket's
// family does not have, and returns the first other failure.
func setOptions(fd int, opts []sockopt) error {
	var firstErr error
	for _, opt := range opts {
		if err := syscall.SetsockoptInt(fd, opt.level, opt.name, 1); err != nil && !isIgnorableSockopt(err) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func isIgnorableSockopt(err error) bool {
	return errors.Is(err, syscall.ENOPROTOOPT) ||
		errors.Is(err, syscall.EINVAL) ||
		errors.Is(err, syscall.EAFNOSUPPORT)
}

// controlSocket adapts fn to net.ListenConfig.Control and net.Dialer.Control.
func controlSocket(fn func(fd int) error) func(string, string, syscall.RawConn) error {
	return func(_, _ string, raw syscall.RawConn) error {
		var sockErr error
		if err := raw.Control(func(fd uintptr) {
			sockErr = fn(int(fd))
		}); err != nil {
			return err
		}
		return sockErr
	}
}
