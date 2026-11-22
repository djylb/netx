//go:build !windows && !plan9

package netx

import (
	"syscall"

	"github.com/djylb/netx/internal/netutil"
)

// platformErrnos are the errnos of each errnoID; see errors.go.
// errnoError is the type of the errors in platformErrnos.
type errnoError = syscall.Errno

var platformErrnos = [numErrnoIDs][]errnoError{
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
	eAddrNotAvail: netutil.AddrNotAvailableErrnos,
	eMsgSize:      {syscall.EMSGSIZE},
}
