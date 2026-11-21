package memnet

import "syscall"

// Plan 9 has no errno values: its errors are the strings the kernel
// returns, so the connection errors are named after them.
var (
	errCodeReset   = syscall.NewError("connection reset by peer")
	errCodeRefused = syscall.NewError("connection refused")
)
