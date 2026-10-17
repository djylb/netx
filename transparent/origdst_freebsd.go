package transparent

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
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

func (nl *pfiocNatlook) setPorts(src, dst uint16) {
	binary.BigEndian.PutUint16(nl.Sport[:], src)
	binary.BigEndian.PutUint16(nl.Dport[:], dst)
}

func (nl *pfiocNatlook) redirectPort() uint16 {
	return binary.BigEndian.Uint16(nl.Rdport[:])
}

func pfIoctl(s uintptr, ioc int, b []byte) error {
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, s, uintptr(ioc), uintptr(unsafe.Pointer(&b[0]))); errno != 0 {
		return error(errno)
	}
	return nil
}

// lookupRedirect returns the destination that pf translated conn from, or
// an error wrapping errNotRedirected when it has none.
func lookupRedirect(conn net.Conn, _ syscall.RawConn, local netip.AddrPort) (netip.AddrPort, error) {
	key, err := natlookKeyOf(conn, local)
	if err != nil {
		return netip.AddrPort{}, err
	}
	f, err := os.Open("/dev/pf")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENXIO) || errors.Is(err, syscall.ENODEV) {
			// No pf, so nothing redirected the connection.
			return netip.AddrPort{}, fmt.Errorf("%w: open /dev/pf: %w", errNotRedirected, err)
		}
		return netip.AddrPort{}, fmt.Errorf("failed to open /dev/pf: %w", err)
	}
	defer func() { _ = f.Close() }()

	fd := f.Fd()
	b := make([]byte, sizeofPfiocNatlook)
	nl := (*pfiocNatlook)(unsafe.Pointer(&b[0]))
	nl.Saddr, nl.Daddr, nl.Af, nl.Proto = key.saddr, key.daddr, key.af, syscall.IPPROTO_TCP
	nl.setPorts(key.sport, key.dport)

	ioc := uintptr(sysDIOCNATLOOK)
	for _, dir := range []byte{sysPFOUT, sysPFIN} {
		nl.Direction = dir
		err = pfIoctl(fd, int(ioc), b)
		if err == nil || !errors.Is(err, syscall.ENOENT) {
			break
		}
	}

	if errors.Is(err, syscall.ENOENT) {
		return netip.AddrPort{}, fmt.Errorf("%w: no pf state: %w", errNotRedirected, err)
	}
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("ioctl failed: %w", err)
	}

	return natlookAddr(nl.Af, &nl.Rdaddr, nl.redirectPort())
}
