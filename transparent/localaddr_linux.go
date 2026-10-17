package transparent

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// soBindToIfindex is SO_BINDTOIFINDEX (Linux 5.0): the index of the device
// a socket is bound to, such as a VRF.
const soBindToIfindex = 62

// isLocalAddr reports whether ip is an address of this host: whether the
// routing table routes it as local, or, for IPv6, as anycast, such as the
// subnet-router anycast address of a forwarding host; `ip route get` shows
// the same. Broadcast and multicast addresses, which this host receives as
// a member of their network or group, count as its own too. Unlike binding it, this is not fooled by
// net.ipv4.ip_nonlocal_bind, and it covers every address of a local route,
// such as all of 127.0.0.0/8. When raw, the socket ip arrived at, is bound
// to a device, as to a VRF, the lookup is made through that device.
func isLocalAddr(raw syscall.RawConn, ip netip.Addr) (bool, error) {
	ifindex, err := boundIfindex(raw)
	if err != nil {
		return false, err
	}
	return routeIsLocal(ip, ifindex)
}

// boundIfindex returns the index of the device raw is bound to, or 0. Before
// Linux 5.0 it cannot be read, and is taken as 0.
func boundIfindex(raw syscall.RawConn) (int, error) {
	if raw == nil {
		return 0, nil
	}
	var ifindex int
	var optErr error
	if err := raw.Control(func(fd uintptr) {
		ifindex, optErr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, soBindToIfindex)
	}); err != nil {
		return 0, err
	}
	if errors.Is(optErr, syscall.ENOPROTOOPT) {
		return 0, nil
	}
	return ifindex, optErr
}

// routeIsLocal asks the routing table how it routes ip, through the device
// with index ifindex unless it is 0.
func routeIsLocal(ip netip.Addr, ifindex int) (bool, error) {
	ip = ip.Unmap()
	if isGroupAddr(ip) {
		return true, nil
	}
	family, bits := syscall.AF_INET6, 128
	if ip.Is4() {
		family, bits = syscall.AF_INET, 32
	}
	addr := ip.AsSlice()

	// struct nlmsghdr, struct rtmsg, then RTA_DST and, with a device, RTA_OIF.
	const seq = 1
	dstLen := syscall.SizeofRtAttr + len(addr)
	reqLen := syscall.NLMSG_HDRLEN + syscall.SizeofRtMsg + dstLen
	if ifindex != 0 {
		reqLen += syscall.SizeofRtAttr + 4
	}
	req := make([]byte, reqLen)
	h := (*syscall.NlMsghdr)(unsafe.Pointer(&req[0]))
	h.Len = uint32(len(req))
	h.Type = syscall.RTM_GETROUTE
	h.Flags = syscall.NLM_F_REQUEST
	h.Seq = seq
	rtm := req[syscall.NLMSG_HDRLEN:]
	rtm[0], rtm[1] = byte(family), byte(bits) // rtm_family, rtm_dst_len
	attr := rtm[syscall.SizeofRtMsg:]
	binary.NativeEndian.PutUint16(attr[0:2], uint16(dstLen))
	binary.NativeEndian.PutUint16(attr[2:4], syscall.RTA_DST)
	copy(attr[syscall.SizeofRtAttr:], addr)
	if ifindex != 0 {
		attr = attr[dstLen:]
		binary.NativeEndian.PutUint16(attr[0:2], uint16(syscall.SizeofRtAttr+4))
		binary.NativeEndian.PutUint16(attr[2:4], syscall.RTA_OIF)
		binary.NativeEndian.PutUint32(attr[syscall.SizeofRtAttr:], uint32(ifindex))
	}

	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return false, fmt.Errorf("netlink socket: %w", err)
	}
	defer func() { _ = syscall.Close(fd) }()
	if err := syscall.Sendto(fd, req, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return false, fmt.Errorf("netlink send: %w", err)
	}
	buf := make([]byte, 4096)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			return false, fmt.Errorf("netlink receive: %w", err)
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return false, fmt.Errorf("netlink receive: %w", err)
		}
		for _, m := range msgs {
			if m.Header.Seq != seq {
				continue
			}
			switch m.Header.Type {
			case syscall.RTM_NEWROUTE:
				if len(m.Data) < syscall.SizeofRtMsg {
					return false, errors.New("netlink: short route message")
				}
				switch typ := m.Data[7]; typ { // rtm_type
				case syscall.RTN_LOCAL, syscall.RTN_BROADCAST, syscall.RTN_MULTICAST:
					return true, nil
				default:
					return typ == syscall.RTN_ANYCAST && ip.Is6(), nil
				}
			case syscall.NLMSG_ERROR:
				if len(m.Data) < 4 {
					return false, errors.New("netlink: short error message")
				}
				errno := syscall.Errno(-int32(binary.NativeEndian.Uint32(m.Data[:4])))
				if errno == 0 {
					continue // an acknowledgement
				}
				return false, routeLookupError(errno)
			}
		}
	}
}

// isLocalAddrCached is isLocalAddr for every datagram: addresses found local
// are remembered for a minute, so that only datagrams to other addresses ask
// the routing table. Only local answers are kept, so that an address added
// meanwhile is not reported as redirected, which would loop; at worst one
// removed meanwhile is reported as direct. At most localAddrsMax are kept.
func isLocalAddrCached(raw syscall.RawConn, ip netip.Addr) (bool, error) {
	ifindex, err := boundIfindex(raw)
	if err != nil {
		return false, err
	}
	key := localAddrKey{ip: ip.Unmap(), ifindex: ifindex}
	localAddrs.Lock()
	if now := time.Now(); localAddrs.set == nil || now.After(localAddrs.expires) {
		localAddrs.set, localAddrs.expires = make(map[localAddrKey]struct{}), now.Add(time.Minute)
	}
	_, ok := localAddrs.set[key]
	localAddrs.Unlock()
	if ok {
		return true, nil
	}
	local, err := routeIsLocal(key.ip, ifindex)
	if err != nil || !local {
		return false, err
	}
	localAddrs.Lock()
	if len(localAddrs.set) >= localAddrsMax {
		clear(localAddrs.set)
	}
	localAddrs.set[key] = struct{}{}
	localAddrs.Unlock()
	return true, nil
}

// localAddrsMax bounds the addresses isLocalAddrCached keeps: far more than a
// host has, but a local route such as 127.0.0.0/8 covers millions.
const localAddrsMax = 4096

type localAddrKey struct {
	ip      netip.Addr
	ifindex int
}

var localAddrs struct {
	sync.Mutex
	set     map[localAddrKey]struct{}
	expires time.Time
}

// routeLookupError returns nil for the errors of a lookup that found no
// route, or an unreachable or prohibit route. Local routes are always found,
// so these mean not local. Others, including the EINVAL of a blackhole route
// or of a malformed request, are returned.
func routeLookupError(errno syscall.Errno) error {
	switch errno {
	case syscall.ENETUNREACH, syscall.EHOSTUNREACH, syscall.EACCES:
		return nil
	}
	return fmt.Errorf("netlink route lookup: %w", errno)
}

// isGroupAddr reports whether ip is a multicast address or the limited
// broadcast address 255.255.255.255, which reach every member host rather
// than one.
func isGroupAddr(ip netip.Addr) bool {
	return ip.IsMulticast() || ip == netip.AddrFrom4([4]byte{255, 255, 255, 255})
}
