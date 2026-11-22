package netutil

import "syscall"

// errWSAAddrNotAvailable is WSAEADDRNOTAVAIL, distinct from syscall.EADDRNOTAVAIL.
const errWSAAddrNotAvailable syscall.Errno = 10049

// AddrNotAvailableErrnos are the platform errors for an unavailable address.
var AddrNotAvailableErrnos = []syscall.Errno{errWSAAddrNotAvailable, syscall.EADDRNOTAVAIL}
