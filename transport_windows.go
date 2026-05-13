package netx

import (
	"errors"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

const sioKeepaliveVals = 0x98000004

var errInvalidKeepAliveParams = errors.New("tcp keepalive parameters must be positive")

type tcpKeepalive struct {
	OnOff             uint32
	KeepAliveTime     uint32
	KeepAliveInterval uint32
}

func SetTcpKeepAliveParams(tc *net.TCPConn, idle, intvl, probes int) error {
	switch {
	case tc == nil:
		return net.ErrClosed
	case idle <= 0 || intvl <= 0 || probes <= 0:
		return errInvalidKeepAliveParams
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return err
	}
	ka := tcpKeepalive{
		OnOff:             1,
		KeepAliveTime:     uint32(idle * 1000),
		KeepAliveInterval: uint32(intvl * 1000),
	}
	var bytesReturned uint32
	var serr error
	err = raw.Control(func(fd uintptr) {
		serr = windows.WSAIoctl(windows.Handle(fd),
			sioKeepaliveVals,
			(*byte)(unsafe.Pointer(&ka)), uint32(unsafe.Sizeof(ka)),
			nil, 0,
			&bytesReturned,
			nil, 0)
	})
	if err != nil {
		return err
	}
	return serr
}
