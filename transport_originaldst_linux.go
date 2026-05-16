package netx

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

const soOriginalDst = 80

// OriginalDestination returns the original destination address for a transparent TCP connection.
func OriginalDestination(conn net.Conn) (*net.TCPAddr, error) {
	if conn == nil {
		return nil, net.ErrClosed
	}
	dst, err := redirectedDestinationFromConn(conn)
	if err == nil {
		return dst, nil
	}
	localDst, localErr := transparentDestinationFromLocalAddr(conn.LocalAddr())
	if localErr == nil {
		return localDst, nil
	}
	return nil, fmt.Errorf("failed to get transparent address: redirect=%v local=%v", err, localErr)
}

func redirectedDestinationFromConn(conn net.Conn) (*net.TCPAddr, error) {
	sysconn, ok := conn.(syscall.Conn)
	if !ok {
		return nil, fmt.Errorf("connection does not support SyscallConn")
	}
	raw, err := sysconn.SyscallConn()
	if err != nil {
		return nil, err
	}

	var dst *net.TCPAddr
	var opErr error

	err = raw.Control(func(fd uintptr) {
		// IPv4
		var sa4 syscall.RawSockaddrInet4
		sz4 := uint32(unsafe.Sizeof(sa4))
		_, _, errno4 := syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			uintptr(syscall.SOL_IP),
			uintptr(soOriginalDst),
			uintptr(unsafe.Pointer(&sa4)),
			uintptr(unsafe.Pointer(&sz4)),
			0,
		)
		if errno4 == 0 {
			ip := net.IPv4(sa4.Addr[0], sa4.Addr[1], sa4.Addr[2], sa4.Addr[3])
			port := int(sa4.Port>>8)&0xff | int(sa4.Port&0xff)<<8
			dst = &net.TCPAddr{IP: ip, Port: port}
			return
		}

		// IPv6
		var sa6 syscall.RawSockaddrInet6
		sz6 := uint32(unsafe.Sizeof(sa6))
		_, _, errno6 := syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			uintptr(syscall.SOL_IPV6),
			uintptr(soOriginalDst),
			uintptr(unsafe.Pointer(&sa6)),
			uintptr(unsafe.Pointer(&sz6)),
			0,
		)
		if errno6 == 0 {
			ip := append(net.IP(nil), sa6.Addr[:]...)
			port := int(sa6.Port>>8)&0xff | int(sa6.Port&0xff)<<8
			dst = &net.TCPAddr{IP: ip, Port: port}
			return
		}

		opErr = fmt.Errorf("not a redirected connection (errno4=%v, errno6=%v)", errno4, errno6)
	})

	if err != nil {
		return nil, err
	}
	if opErr != nil {
		return nil, opErr
	}
	return dst, nil
}
