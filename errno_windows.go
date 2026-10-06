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
	wsaENETUNREACH      syscall.Errno = 10051 // WSAENETUNREACH
	wsaECONNABORTED     syscall.Errno = 10053 // WSAECONNABORTED
	wsaECONNRESET       syscall.Errno = 10054 // WSAECONNRESET
	wsaESHUTDOWN        syscall.Errno = 10058 // WSAESHUTDOWN
	wsaETIMEDOUT        syscall.Errno = 10060 // WSAETIMEDOUT
	wsaECONNREFUSED     syscall.Errno = 10061 // WSAECONNREFUSED
	wsaEHOSTUNREACH     syscall.Errno = 10065 // WSAEHOSTUNREACH
)

// Errno tables used by the error classifiers in errors.go. The invented
// syscall.E* values stay in the tables for errors built by portable code.
var (
	connResetErrnos   = []error{wsaECONNRESET, errorNetnameDeleted, syscall.ECONNRESET}
	connAbortedErrnos = []error{wsaECONNABORTED, syscall.ECONNABORTED}
	brokenPipeErrnos  = []error{wsaESHUTDOWN, syscall.EPIPE}
	connRefusedErrnos = []error{wsaECONNREFUSED, syscall.ECONNREFUSED}
	hostUnreachErrnos = []error{wsaEHOSTUNREACH, syscall.EHOSTUNREACH}
	netUnreachErrnos  = []error{wsaENETUNREACH, syscall.ENETUNREACH}
	accessErrnos      = []error{wsaEACCES, errorAccessDenied, syscall.EACCES}
	permErrnos        = []error{syscall.EPERM}
	timedOutErrnos    = []error{wsaETIMEDOUT, syscall.ETIMEDOUT}
)
