package udpflow

import "syscall"

// reusePortSupport reports nil: Linux spreads unicast datagrams over
// SO_REUSEPORT sockets.
func reusePortSupport() error { return nil }

func setReusePort(c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soReusePort, 1)
	}); err != nil {
		return err
	}
	return serr
}
