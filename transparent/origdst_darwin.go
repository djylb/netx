package transparent

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
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

func (nl *pfiocNatlook) setPorts(src, dst uint16) {
	binary.BigEndian.PutUint16(nl.sxport[:2], src)
	binary.BigEndian.PutUint16(nl.dxport[:2], dst)
}

func (nl *pfiocNatlook) redirectPort() uint16 {
	return binary.BigEndian.Uint16(nl.rdxport[:2])
}

// lookupRedirect returns the destination that pf translated conn from, or
// an error wrapping errNotRedirected when it has none.
func lookupRedirect(conn net.Conn, _ syscall.RawConn, local netip.AddrPort) (netip.AddrPort, error) {
	key, err := natlookKeyOf(conn, local)
	if err != nil {
		return netip.AddrPort{}, err
	}
	fd, err := syscall.Open("/dev/pf", syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("open /dev/pf: %w", err)
	}
	defer func() {
		// Closing the lookup descriptor must not replace the lookup result.
		_ = syscall.Close(fd)
	}()

	nl := pfiocNatlook{
		saddr:     key.saddr,
		daddr:     key.daddr,
		af:        key.af,
		proto:     syscall.IPPROTO_TCP,
		direction: pfOut,
	}
	nl.setPorts(key.sport, key.dport)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), diocNatLook, uintptr(unsafe.Pointer(&nl)))
	switch {
	case errors.Is(errno, syscall.ENOENT):
		return netip.AddrPort{}, fmt.Errorf("%w: no pf state: %w", errNotRedirected, errno)
	case errno != 0:
		return netip.AddrPort{}, fmt.Errorf("DIOCNATLOOK: %w", errno)
	}
	return natlookAddr(nl.af, &nl.rdaddr, nl.redirectPort())
}
