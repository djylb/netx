//go:build !windows && !plan9

package netutil

import "syscall"

// AddrNotAvailableErrnos are the platform errors for an unavailable address.
var AddrNotAvailableErrnos = []syscall.Errno{syscall.EADDRNOTAVAIL}
