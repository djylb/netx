//go:build !plan9

package memnet

import "syscall"

// The errors a connection reports as the system words them, for errors.Is.
var (
	errCodeReset   error = syscall.ECONNRESET
	errCodeRefused error = syscall.ECONNREFUSED
)
