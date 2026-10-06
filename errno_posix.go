//go:build !windows && !plan9

package netx

import "syscall"

// Errno tables used by the error classifiers in errors.go.
var (
	connResetErrnos   = []error{syscall.ECONNRESET}
	connAbortedErrnos = []error{syscall.ECONNABORTED}
	brokenPipeErrnos  = []error{syscall.EPIPE}
	connRefusedErrnos = []error{syscall.ECONNREFUSED}
	hostUnreachErrnos = []error{syscall.EHOSTUNREACH}
	netUnreachErrnos  = []error{syscall.ENETUNREACH}
	accessErrnos      = []error{syscall.EACCES}
	permErrnos        = []error{syscall.EPERM}
	timedOutErrnos    = []error{syscall.ETIMEDOUT}
)
