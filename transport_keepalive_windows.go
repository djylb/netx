package netx

import (
	"net"
	"syscall"
	"time"
	"unsafe"
)

const sioKeepaliveVals = 0x98000004

type tcpKeepalive struct {
	OnOff             uint32
	KeepAliveTime     uint32
	KeepAliveInterval uint32
}

// SetTCPKeepAlive sets TCP keepalive parameters on tc.
func SetTCPKeepAlive(tc *net.TCPConn, cfg TCPKeepAliveConfig) error {
	if err := validateTCPKeepAliveConfig(tc, cfg); err != nil {
		return err
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return err
	}
	ka := tcpKeepalive{
		OnOff:             1,
		KeepAliveTime:     durationMilliseconds(cfg.Idle),
		KeepAliveInterval: durationMilliseconds(cfg.Interval),
	}
	var bytesReturned uint32
	var serr error
	err = raw.Control(func(fd uintptr) {
		serr = syscall.WSAIoctl(syscall.Handle(fd),
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

func durationMilliseconds(d time.Duration) uint32 {
	milliseconds := d / time.Millisecond
	if d%time.Millisecond != 0 {
		milliseconds++
	}
	if milliseconds > time.Duration(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(milliseconds)
}
