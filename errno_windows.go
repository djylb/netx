//go:build windows

package netx

import "syscall"

// Winsock reports socket failures as WSAE* codes. The syscall.E* constants on
// Windows are invented values that the network stack never returns, and package
// syscall exports only a few WSAE* names, so the codes are spelled out here.
const (
	errAccessDenied     syscall.Errno = 5     // ERROR_ACCESS_DENIED
	errNetnameDeleted   syscall.Errno = 64    // ERROR_NETNAME_DELETED
	errWSAEACCES        syscall.Errno = 10013 // WSAEACCES
	errWSAEMSGSIZE      syscall.Errno = 10040 // WSAEMSGSIZE
	errWSAEADDRINUSE    syscall.Errno = 10048 // WSAEADDRINUSE
	errWSAEADDRNOTAVAIL syscall.Errno = 10049 // WSAEADDRNOTAVAIL
	errWSAENETUNREACH   syscall.Errno = 10051 // WSAENETUNREACH
	errWSAECONNABORTED  syscall.Errno = 10053 // WSAECONNABORTED
	errWSAECONNRESET    syscall.Errno = 10054 // WSAECONNRESET
	errWSAESHUTDOWN     syscall.Errno = 10058 // WSAESHUTDOWN
	errWSAETIMEDOUT     syscall.Errno = 10060 // WSAETIMEDOUT
	errWSAECONNREFUSED  syscall.Errno = 10061 // WSAECONNREFUSED
	errWSAEHOSTUNREACH  syscall.Errno = 10065 // WSAEHOSTUNREACH
)

// platformErrnos are the errnos of each errnoID; see errors.go. The
// invented syscall.E* values stay in the tables for errors built by portable
// code.
// errnoError is the type of the errors in platformErrnos.
type errnoError = syscall.Errno

var platformErrnos = [numErrnoIDs][]errnoError{
	eConnReset:    {errWSAECONNRESET, errNetnameDeleted, syscall.ECONNRESET},
	eConnAborted:  {errWSAECONNABORTED, syscall.ECONNABORTED},
	ePipe:         {errWSAESHUTDOWN, syscall.EPIPE},
	eConnRefused:  {errWSAECONNREFUSED, syscall.ECONNREFUSED},
	eHostUnreach:  {errWSAEHOSTUNREACH, syscall.EHOSTUNREACH},
	eNetUnreach:   {errWSAENETUNREACH, syscall.ENETUNREACH},
	eAccess:       {errWSAEACCES, errAccessDenied, syscall.EACCES},
	ePerm:         {syscall.EPERM},
	eTimedOut:     {errWSAETIMEDOUT, syscall.ETIMEDOUT},
	eAddrInUse:    {errWSAEADDRINUSE, syscall.EADDRINUSE},
	eAddrNotAvail: {errWSAEADDRNOTAVAIL, syscall.EADDRNOTAVAIL},
	eMsgSize:      {errWSAEMSGSIZE, syscall.EMSGSIZE},
}
