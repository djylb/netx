//go:build freebsd

package transparent

import "syscall"

const (
	ipBindAny   = 0x18
	ipv6BindAny = 0x40
)

// listenErr reports no error: Listen is supported.
func listenErr() error { return nil }

var bindAnyOpts = []sockopt{
	{level: syscall.IPPROTO_IP, name: ipBindAny},
	{level: syscall.IPPROTO_IPV6, name: ipv6BindAny},
}

func control(_, _ string, c syscall.RawConn) error {
	return controlFD(c, func(fd int) error { return setOptions(fd, bindAnyOpts) })
}

//goland:noinspection GoUnusedParameter
func controlPacket(string, string, syscall.RawConn) error {
	return ErrListenUnsupported
}
