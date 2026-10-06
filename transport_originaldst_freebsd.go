package netx

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"
)

const (
	sysPFIN        = 0x1        // PF_IN
	sysPFOUT       = 0x2        // PF_OUT
	sysDIOCNATLOOK = 0xc04c4417 // _IOWR('D', 23, struct pfioc_natlook)
)

// pfiocNatlook mirrors struct pfioc_natlook. pf copies the port fields
// to and from its state keys unchanged, so they hold ports in network byte
// order, as on the wire.
type pfiocNatlook struct {
	Saddr     [16]byte /* pf_addr */
	Daddr     [16]byte /* pf_addr */
	Rsaddr    [16]byte /* pf_addr */
	Rdaddr    [16]byte /* pf_addr */
	Sport     [2]byte  /* u_int16_t */
	Dport     [2]byte  /* u_int16_t */
	Rsport    [2]byte  /* u_int16_t */
	Rdport    [2]byte  /* u_int16_t */
	Af        uint8
	Proto     uint8
	Direction uint8
	Pad       [1]byte
}

const sizeofPfiocNatlook = 0x4c

func (nl *pfiocNatlook) setPorts(src, dst int) {
	binary.BigEndian.PutUint16(nl.Sport[:], uint16(src))
	binary.BigEndian.PutUint16(nl.Dport[:], uint16(dst))
}

func (nl *pfiocNatlook) redirectPort() int {
	return int(binary.BigEndian.Uint16(nl.Rdport[:]))
}

func pfIoctl(s uintptr, ioc int, b []byte) error {
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, s, uintptr(ioc), uintptr(unsafe.Pointer(&b[0]))); errno != 0 {
		return error(errno)
	}
	return nil
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
	dst, err := redirectedDestinationFromPF(conn)
	if err == nil {
		return dst, nil
	}
	localDst, localErr := transparentDestinationFromLocalAddr(conn.LocalAddr())
	if localErr == nil {
		return localDst, nil
	}
	return nil, fmt.Errorf("failed to get transparent address: pf=%v local=%v", err, localErr)
}

func redirectedDestinationFromPF(conn net.Conn) (*net.TCPAddr, error) {
	f, err := os.Open("/dev/pf")
	if err != nil {
		return nil, fmt.Errorf("failed to open /dev/pf: %v", err)
	}
	defer f.Close()

	fd := f.Fd()
	b := make([]byte, sizeofPfiocNatlook)
	nl := (*pfiocNatlook)(unsafe.Pointer(&b[0]))

	var raIP, laIP net.IP
	var raPort, laPort int
	switch ra := conn.RemoteAddr().(type) {
	case *net.TCPAddr:
		raIP = ra.IP
		raPort = ra.Port
		nl.Proto = syscall.IPPROTO_TCP
	case *net.UDPAddr:
		raIP = ra.IP
		raPort = ra.Port
		nl.Proto = syscall.IPPROTO_UDP
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
		if laIP.IsUnspecified() {
			laIP = net.ParseIP("127.0.0.1")
		}
		copy(nl.Saddr[:net.IPv4len], raIP.To4())
		copy(nl.Daddr[:net.IPv4len], laIP.To4())
		nl.Af = syscall.AF_INET
	}

	if raIP.To16() != nil && raIP.To4() == nil {
		if laIP.IsUnspecified() {
			laIP = net.ParseIP("::1")
		}
		copy(nl.Saddr[:], raIP)
		copy(nl.Daddr[:], laIP)
		nl.Af = syscall.AF_INET6
	}

	nl.setPorts(raPort, laPort)

	ioc := uintptr(sysDIOCNATLOOK)
	for _, dir := range []byte{sysPFOUT, sysPFIN} {
		nl.Direction = dir
		err = pfIoctl(fd, int(ioc), b)
		if err == nil || !errors.Is(err, syscall.ENOENT) {
			break
		}
	}

	if err != nil {
		return nil, fmt.Errorf("ioctl failed: %v", err)
	}

	odPort := nl.redirectPort()
	var odIP net.IP
	switch nl.Af {
	case syscall.AF_INET:
		odIP = make(net.IP, net.IPv4len)
		copy(odIP, nl.Rdaddr[:net.IPv4len])
	case syscall.AF_INET6:
		odIP = make(net.IP, net.IPv6len)
		copy(odIP, nl.Rdaddr[:])
	default:
		return nil, fmt.Errorf("unsupported address family: %d", nl.Af)
	}

	return &net.TCPAddr{IP: odIP, Port: odPort}, nil
}
