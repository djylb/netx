package netx

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

// The classifiers below match the platform errno first, so they work whatever
// the system language is, and then fall back to well-known English messages
// for errors that only carry text.

// IsTimeout reports whether err is a timeout. It matches ETIMEDOUT
// (WSAETIMEDOUT on Windows) anywhere in the chain first, then the first
// net.Error's Timeout method, and only then English timeout messages.
func IsTimeout(err error) bool {
	if err == nil {
		return false
	}
	// Checked first because Errno.Timeout is false for WSAETIMEDOUT on Windows.
	if errorIsAny(err, timedOutErrnos) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return ne.Timeout()
	}
	s := strings.ToLower(strings.ReplaceAll(err.Error(), " ", ""))
	return strings.Contains(s, "timeout") ||
		strings.Contains(s, "timedout") ||
		strings.Contains(s, "didnotproperlyrespondafteraperiodoftime")
}

// IsClosed reports whether err comes from using a closed connection or
// listener: net.ErrClosed, io.ErrClosedPipe, or the "use of closed network
// connection" text that some wrappers pass on without the error value.
func IsClosed(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
		return true
	}
	return strings.Contains(err.Error(), "use of closed network connection")
}

// IsConnReset reports whether err looks like a connection reset.
func IsConnReset(err error) bool {
	if err == nil {
		return false
	}
	if errorIsAny(err, connResetErrnos) {
		return true
	}
	msg := normalizeNetErrorText(err)
	return strings.Contains(msg, "connectionresetbypeer") ||
		strings.Contains(msg, "forciblyclosedbytheremotehost") ||
		strings.Contains(msg, "networknameisnolongeravailable")
}

// IsConnAborted reports whether err looks like an aborted connection.
func IsConnAborted(err error) bool {
	if err == nil {
		return false
	}
	if errorIsAny(err, connAbortedErrnos) {
		return true
	}
	msg := normalizeNetErrorText(err)
	return strings.Contains(msg, "connectionaborted") ||
		strings.Contains(msg, "connectionwasaborted") ||
		strings.Contains(msg, "softwarecausedconnectionabort")
}

// IsBrokenPipe reports whether err looks like a broken pipe.
func IsBrokenPipe(err error) bool {
	if err == nil {
		return false
	}
	if errorIsAny(err, brokenPipeErrnos) {
		return true
	}
	msg := normalizeNetErrorText(err)
	return strings.Contains(msg, "brokenpipe") ||
		strings.Contains(msg, "sockethadalreadybeenshutdown")
}

// IsConnRefused reports whether err looks like a refused connection attempt.
func IsConnRefused(err error) bool {
	if err == nil {
		return false
	}
	if errorIsAny(err, connRefusedErrnos) {
		return true
	}
	msg := normalizeNetErrorText(err)
	return strings.Contains(msg, "connectionrefused") ||
		strings.Contains(msg, "activelyrefusedit")
}

// IsHostUnreachable reports whether err looks like an unreachable host.
// DNS lookup failures are not included; check for *net.DNSError separately.
func IsHostUnreachable(err error) bool {
	if err == nil {
		return false
	}
	if errorIsAny(err, hostUnreachErrnos) {
		return true
	}
	msg := normalizeNetErrorText(err)
	return strings.Contains(msg, "noroutetohost") ||
		strings.Contains(msg, "hostunreachable") ||
		strings.Contains(msg, "hostisunreachable") ||
		strings.Contains(msg, "unreachablehost")
}

// IsNetworkUnreachable reports whether err looks like an unreachable network.
func IsNetworkUnreachable(err error) bool {
	if err == nil {
		return false
	}
	if errorIsAny(err, netUnreachErrnos) {
		return true
	}
	msg := normalizeNetErrorText(err)
	return strings.Contains(msg, "networkunreachable") ||
		strings.Contains(msg, "networkisunreachable") ||
		strings.Contains(msg, "unreachablenetwork")
}

// IsPermissionDenied reports whether err looks like a permission failure
// (EACCES or EPERM), such as a connect blocked by a local firewall rule.
func IsPermissionDenied(err error) bool {
	if err == nil {
		return false
	}
	if errorIsAny(err, accessErrnos) || errorIsAny(err, permErrnos) {
		return true
	}
	msg := normalizeNetErrorText(err)
	return strings.Contains(msg, "permissiondenied") ||
		strings.Contains(msg, "operationnotpermitted") ||
		strings.Contains(msg, "accessisdenied") ||
		strings.Contains(msg, "forbiddenbyitsaccesspermissions")
}

// NetErrorKind returns a stable string category for common network errors:
// "none", "rst", "aborted", "broken_pipe", "refused", "host_unreachable",
// "network_unreachable", "permission_denied", "timeout", "unexpected_eof",
// "eof", "closed" or "other".
func NetErrorKind(err error) string {
	switch {
	case err == nil:
		return "none"
	case IsConnReset(err):
		return "rst"
	case IsConnAborted(err):
		return "aborted"
	case IsBrokenPipe(err):
		return "broken_pipe"
	case IsConnRefused(err):
		return "refused"
	case IsHostUnreachable(err):
		return "host_unreachable"
	case IsNetworkUnreachable(err):
		return "network_unreachable"
	case IsPermissionDenied(err):
		return "permission_denied"
	case IsTimeout(err):
		return "timeout"
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "unexpected_eof"
	case errors.Is(err, io.EOF):
		return "eof"
	case IsClosed(err):
		return "closed"
	default:
		return "other"
	}
}

// DescribeNetError returns a compact diagnostic string for a network error.
// For the errno classes recognised by NetErrorKind it adds errno_name with the
// POSIX name (ECONNRESET also for WSAECONNRESET, for example), which does not
// depend on the platform or the system language. Other errnos are reported as
// errno=<number> only; their system message is part of err.
func DescribeNetError(err error, c net.Conn) string {
	if err == nil {
		return "kind=none"
	}

	parts := []string{
		fmt.Sprintf("kind=%s", NetErrorKind(err)),
		fmt.Sprintf("err=%q", err.Error()),
	}

	if c != nil {
		if local := c.LocalAddr(); local != nil {
			parts = append(parts, fmt.Sprintf("local=%s", local.String()))
		}
		if remote := c.RemoteAddr(); remote != nil {
			parts = append(parts, fmt.Sprintf("remote=%s", remote.String()))
		}
	}

	parts = append(parts, fmt.Sprintf("timeout=%t", IsTimeout(err)))

	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if opErr.Op != "" {
			parts = append(parts, fmt.Sprintf("op=%s", opErr.Op))
		}
		if opErr.Net != "" {
			parts = append(parts, fmt.Sprintf("net=%s", opErr.Net))
		}
		if opErr.Source != nil {
			parts = append(parts, fmt.Sprintf("source=%s", opErr.Source.String()))
		}
		if opErr.Addr != nil {
			parts = append(parts, fmt.Sprintf("addr=%s", opErr.Addr.String()))
		}
	}

	var sysErr *os.SyscallError
	if errors.As(err, &sysErr) {
		parts = append(parts, fmt.Sprintf("syscall=%s", sysErr.Syscall))
	}

	parts = append(parts, errnoParts(err)...)

	return strings.Join(parts, " ")
}

func normalizeNetErrorText(err error) string {
	s := strings.ToLower(err.Error())
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, "_", "")
	return s
}

// errorIsAny reports whether errors.Is(err, target) holds for any target.
func errorIsAny(err error, targets []error) bool {
	for _, target := range targets {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}
