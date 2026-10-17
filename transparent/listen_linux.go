//go:build linux

package transparent

import "syscall"

const (
	solIP               = 0x0
	solIPv6             = 0x29
	ipTransparent       = 0x13
	ipv6Transparent     = 0x4b
	ipRecvOrigDstAddr   = 0x14 // IP_RECVORIGDSTADDR, also the IP_ORIGDSTADDR message type
	ipv6RecvOrigDstAddr = 0x4a // IPV6_RECVORIGDSTADDR, also IPV6_ORIGDSTADDR
)

// listenErr reports no error: Listen is supported.
func listenErr() error { return nil }

var (
	transparentOpts = []sockopt{
		{level: solIP, name: ipTransparent},
		{level: solIPv6, name: ipv6Transparent},
	}
	origDstOpts = []sockopt{
		{level: solIP, name: ipRecvOrigDstAddr},
		{level: solIPv6, name: ipv6RecvOrigDstAddr},
	}
)

func control(_, _ string, c syscall.RawConn) error {
	return controlFD(c, func(fd int) error { return setOptions(fd, transparentOpts) })
}

func controlPacket(_, _ string, c syscall.RawConn) error {
	return controlFD(c, func(fd int) error {
		if err := setOptions(fd, transparentOpts); err != nil {
			return err
		}
		return setOptions(fd, origDstOpts)
	})
}
