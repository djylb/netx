//go:build !plan9

package netx

import (
	"errors"
	"fmt"
	"syscall"
)

// errnoParts returns the errno fields of DescribeNetError. errno_name is only
// set for the errnos in the classifier tables; the system message of any other
// errno is already part of err.
func errnoParts(err error) []string {
	errno, ok := extractErrno(err)
	if !ok {
		return nil
	}
	parts := []string{fmt.Sprintf("errno=%d", errno)}
	if name := errnoName(errno); name != "" {
		parts = append(parts, "errno_name="+name)
	}
	return parts
}

func extractErrno(err error) (syscall.Errno, bool) {
	if err == nil {
		return 0, false
	}
	if errno, ok := errors.AsType[syscall.Errno](err); ok {
		return errno, true
	}
	return 0, false
}

// errnoName maps the platform errnos in the classifier tables to their POSIX
// names (WSAECONNRESET becomes ECONNRESET, for example) and returns "" for
// other errnos.
func errnoName(errno syscall.Errno) string {
	err := error(errno)
	switch {
	case errorIsAny(err, connResetErrnos):
		return "ECONNRESET"
	case errorIsAny(err, connAbortedErrnos):
		return "ECONNABORTED"
	case errorIsAny(err, brokenPipeErrnos):
		return "EPIPE"
	case errorIsAny(err, connRefusedErrnos):
		return "ECONNREFUSED"
	case errorIsAny(err, hostUnreachErrnos):
		return "EHOSTUNREACH"
	case errorIsAny(err, netUnreachErrnos):
		return "ENETUNREACH"
	case errorIsAny(err, accessErrnos):
		return "EACCES"
	case errorIsAny(err, permErrnos):
		return "EPERM"
	case errorIsAny(err, timedOutErrnos):
		return "ETIMEDOUT"
	default:
		return ""
	}
}
