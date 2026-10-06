//go:build plan9

package netx

import "syscall"

// Plan 9 reports network failures as error strings and package syscall has no
// errno for most of them, so those classifiers rely on their text fallback.
var (
	connResetErrnos   []error
	connAbortedErrnos []error
	brokenPipeErrnos  []error
	connRefusedErrnos []error
	hostUnreachErrnos []error
	netUnreachErrnos  []error
	accessErrnos      = []error{syscall.EACCES}
	permErrnos        = []error{syscall.EPERM}
	timedOutErrnos    = []error{syscall.ETIMEDOUT}
)

// errnoParts returns no fields: plan9 errors carry no errno, and the Go
// versions netx supports may not define syscall.Errno on plan9.
func errnoParts(error) []string { return nil }
