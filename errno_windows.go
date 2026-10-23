//go:build windows

package netx

import "syscall"

// Winsock reports socket failures as WSAE* codes. The syscall.E* constants on
// Windows are invented values that the network stack never returns, and package
// syscall exports only a few WSAE* names, so the codes are spelled out here.
const (
	errorAccessDenied   syscall.Errno = 5     // ERROR_ACCESS_DENIED
	errorNetnameDeleted syscall.Errno = 64    // ERROR_NETNAME_DELETED
	wsaEACCES           syscall.Errno = 10013 // WSAEACCES
	wsaEMSGSIZE         syscall.Errno = 10040 // WSAEMSGSIZE
	wsaEADDRINUSE       syscall.Errno = 10048 // WSAEADDRINUSE
	wsaEADDRNOTAVAIL    syscall.Errno = 10049 // WSAEADDRNOTAVAIL
	wsaENETUNREACH      syscall.Errno = 10051 // WSAENETUNREACH
	wsaECONNABORTED     syscall.Errno = 10053 // WSAECONNABORTED
	wsaECONNRESET       syscall.Errno = 10054 // WSAECONNRESET
	wsaESHUTDOWN        syscall.Errno = 10058 // WSAESHUTDOWN
	wsaETIMEDOUT        syscall.Errno = 10060 // WSAETIMEDOUT
	wsaECONNREFUSED     syscall.Errno = 10061 // WSAECONNREFUSED
	wsaEHOSTUNREACH     syscall.Errno = 10065 // WSAEHOSTUNREACH
)

// platformErrnos are the errnos of each errnoID; see errors.go. The
// invented syscall.E* values stay in the tables for errors built by portable
// code.
// errnoValue is the type of the errors in platformErrnos.
type errnoValue = syscall.Errno

var platformErrnos = [numErrnoIDs][]errnoValue{
	eConnReset:    {wsaECONNRESET, errorNetnameDeleted, syscall.ECONNRESET},
	eConnAborted:  {wsaECONNABORTED, syscall.ECONNABORTED},
	ePipe:         {wsaESHUTDOWN, syscall.EPIPE},
	eConnRefused:  {wsaECONNREFUSED, syscall.ECONNREFUSED},
	eHostUnreach:  {wsaEHOSTUNREACH, syscall.EHOSTUNREACH},
	eNetUnreach:   {wsaENETUNREACH, syscall.ENETUNREACH},
	eAccess:       {wsaEACCES, errorAccessDenied, syscall.EACCES},
	ePerm:         {syscall.EPERM},
	eTimedOut:     {wsaETIMEDOUT, syscall.ETIMEDOUT},
	eAddrInUse:    {wsaEADDRINUSE, syscall.EADDRINUSE},
	eAddrNotAvail: {wsaEADDRNOTAVAIL, syscall.EADDRNOTAVAIL},
	eMsgSize:      {wsaEMSGSIZE, syscall.EMSGSIZE},
}
