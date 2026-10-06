package netx

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

const (
	pfOut       = 2
	natLookLen  = 4*16 + 4*4 + 4*1 // sizeof(struct pfioc_natlook)
	iocOut      = 0x40000000
	iocIn       = 0x80000000
	iocInOut    = iocIn | iocOut
	iocParmMask = 0x1FFF
	// diocNatLook is _IOWR('D', 23, struct pfioc_natlook) == 0xc0544417.
	diocNatLook = iocInOut | ((natLookLen & iocParmMask) << 16) | ('D' << 8) | 23
)

// pfiocNatlook mirrors XNU's struct pfioc_natlook. The xport fields are
// union pf_state_xport, whose first two bytes hold a TCP or UDP port in
// network byte order.
type pfiocNatlook struct {
	saddr, daddr, rsaddr, rdaddr       [16]byte
	sxport, dxport, rsxport, rdxport   [4]byte
	af, proto, protoVariant, direction uint8
}

func (nl *pfiocNatlook) setPorts(src, dst int) {
	binary.BigEndian.PutUint16(nl.sxport[:2], uint16(src))
	binary.BigEndian.PutUint16(nl.dxport[:2], uint16(dst))
}

func (nl *pfiocNatlook) redirectPort() int {
	return int(binary.BigEndian.Uint16(nl.rdxport[:2]))
}

// OriginalDestination returns the pre-redirect destination of an accepted
// TCP connection.
//
// On Linux it reads SO_ORIGINAL_DST or IP6T_SO_ORIGINAL_DST (REDIRECT/DNAT),
// and on FreeBSD it queries pf with DIOCNATLOOK. If that lookup fails, both
// fall back to conn's local address, which is the target for TPROXY or
// IP_BINDANY sockets. A direct, non-redirected connection therefore yields its
// own local address rather than an error. On macOS it queries pf with
// DIOCNATLOOK, which XNU only allows for root, and has no fallback. On other
// platforms it returns ErrOriginalDestinationUnsupported. A nil conn returns
// net.ErrClosed.
func OriginalDestination(conn net.Conn) (*net.TCPAddr, error) {
	if conn == nil {
		return nil, net.ErrClosed
	}
	fd, err := syscall.Open("/dev/pf", syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open /dev/pf: %v", err)
	}
	defer syscall.Close(fd)

	var nl pfiocNatlook

	nl.direction = pfOut

	var raIP, laIP net.IP
	var raPort, laPort int

	switch ra := conn.RemoteAddr().(type) {
	case *net.TCPAddr:
		raIP = ra.IP
		raPort = ra.Port
		nl.proto = syscall.IPPROTO_TCP
	case *net.UDPAddr:
		raIP = ra.IP
		raPort = ra.Port
		nl.proto = syscall.IPPROTO_UDP
	}

	switch la := conn.LocalAddr().(type) {
	case *net.TCPAddr:
		laIP = la.IP
		laPort = la.Port
	case *net.UDPAddr:
		laIP = la.IP
		laPort = la.Port
	}

	if raIP.To4() != nil {
		// IPv4
		nl.af = syscall.AF_INET
		if laIP.IsUnspecified() {
			laIP = net.ParseIP("127.0.0.1")
		}
		copy(nl.saddr[:net.IPv4len], raIP.To4())
		copy(nl.daddr[:net.IPv4len], laIP.To4())
	} else if raIP.To16() != nil {
		// IPv6
		nl.af = syscall.AF_INET6
		if laIP.IsUnspecified() {
			laIP = net.ParseIP("::1")
		}
		copy(nl.saddr[:], raIP)
		copy(nl.daddr[:], laIP)
	}

	nl.setPorts(raPort, laPort)

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), diocNatLook, uintptr(unsafe.Pointer(&nl)))
	if errno != 0 {
		return nil, fmt.Errorf("failed to get redirected address: %v", errno)
	}

	odPort := nl.redirectPort()
	var odIP net.IP
	switch nl.af {
	case syscall.AF_INET:
		odIP = make(net.IP, net.IPv4len)
		copy(odIP, nl.rdaddr[:net.IPv4len])
	case syscall.AF_INET6:
		odIP = make(net.IP, net.IPv6len)
		copy(odIP, nl.rdaddr[:])
	default:
		return nil, fmt.Errorf("unsupported address family: %d", nl.af)
	}

	return &net.TCPAddr{IP: odIP, Port: odPort}, nil
}
