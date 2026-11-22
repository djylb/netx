package netutil

import "syscall"

// wsaAddrNotAvailable is WSAEADDRNOTAVAIL, distinct from syscall.EADDRNOTAVAIL.
const wsaAddrNotAvailable syscall.Errno = 10049

// AddrNotAvailableErrnos are the platform errors for an unavailable address.
var AddrNotAvailableErrnos = []syscall.Errno{wsaAddrNotAvailable, syscall.EADDRNOTAVAIL}
