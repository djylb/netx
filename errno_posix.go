//go:build !windows && !plan9

package netx

import "syscall"

// platformErrnos are the errnos of each errnoID; see errors.go.
// errnoValue is the type of the errors in platformErrnos.
type errnoValue = syscall.Errno

var platformErrnos = [numErrnoIDs][]errnoValue{
	eConnReset:    {syscall.ECONNRESET},
	eConnAborted:  {syscall.ECONNABORTED},
	ePipe:         {syscall.EPIPE},
	eConnRefused:  {syscall.ECONNREFUSED},
	eHostUnreach:  {syscall.EHOSTUNREACH},
	eNetUnreach:   {syscall.ENETUNREACH},
	eAccess:       {syscall.EACCES},
	ePerm:         {syscall.EPERM},
	eTimedOut:     {syscall.ETIMEDOUT},
	eAddrInUse:    {syscall.EADDRINUSE},
	eAddrNotAvail: {syscall.EADDRNOTAVAIL},
	eMsgSize:      {syscall.EMSGSIZE},
}
