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
	return err != nil && isTimeout(&errText{err: err})
}

func isTimeout(t *errText) bool {
	// Checked first because Errno.Timeout is false for WSAETIMEDOUT on Windows.
	if errorIsAny(t.err, timedOutErrnos) {
		return true
	}
	if ne, ok := errors.AsType[net.Error](t.err); ok {
		return ne.Timeout()
	}
	// Spaces are kept so that words such as "runtime output" do not match.
	s := t.lower()
	return strings.Contains(s, "timeout") ||
		strings.Contains(s, "timed out") ||
		strings.Contains(s, "did not properly respond after a period of time")
}

// IsClosed reports whether err comes from using a closed connection or
// listener: net.ErrClosed, io.ErrClosedPipe, or the "use of closed network
// connection" text that some wrappers pass on without the error value.
func IsClosed(err error) bool {
	return err != nil && isClosed(&errText{err: err})
}

func isClosed(t *errText) bool {
	if errors.Is(t.err, net.ErrClosed) || errors.Is(t.err, io.ErrClosedPipe) {
		return true
	}
	return strings.Contains(t.text(), "use of closed network connection")
}

// IsConnReset reports whether err looks like a connection reset.
func IsConnReset(err error) bool {
	return err != nil && isConnReset(&errText{err: err})
}

func isConnReset(t *errText) bool {
	return errorIsAny(t.err, connResetErrnos) || t.has(
		"connectionresetbypeer",
		"forciblyclosedbytheremotehost",
		"networknameisnolongeravailable")
}

// IsConnAborted reports whether err looks like an aborted connection.
func IsConnAborted(err error) bool {
	return err != nil && isConnAborted(&errText{err: err})
}

func isConnAborted(t *errText) bool {
	return errorIsAny(t.err, connAbortedErrnos) || t.has(
		"connectionaborted",
		"connectionwasaborted",
		"softwarecausedconnectionabort")
}

// IsBrokenPipe reports whether err looks like a broken pipe.
func IsBrokenPipe(err error) bool {
	return err != nil && isBrokenPipe(&errText{err: err})
}

func isBrokenPipe(t *errText) bool {
	return errorIsAny(t.err, brokenPipeErrnos) || t.has(
		"brokenpipe",
		"sockethadalreadybeenshutdown")
}

// IsConnRefused reports whether err looks like a refused connection attempt.
func IsConnRefused(err error) bool {
	return err != nil && isConnRefused(&errText{err: err})
}

func isConnRefused(t *errText) bool {
	return errorIsAny(t.err, connRefusedErrnos) || t.has(
		"connectionrefused",
		"activelyrefusedit")
}

// IsHostUnreachable reports whether err looks like an unreachable host.
// DNS lookup failures are not included; check for *net.DNSError separately.
func IsHostUnreachable(err error) bool {
	return err != nil && isHostUnreachable(&errText{err: err})
}

func isHostUnreachable(t *errText) bool {
	return errorIsAny(t.err, hostUnreachErrnos) || t.has(
		"noroutetohost",
		"hostunreachable",
		"hostisunreachable",
		"unreachablehost")
}

// IsNetworkUnreachable reports whether err looks like an unreachable network.
func IsNetworkUnreachable(err error) bool {
	return err != nil && isNetworkUnreachable(&errText{err: err})
}

func isNetworkUnreachable(t *errText) bool {
	return errorIsAny(t.err, netUnreachErrnos) || t.has(
		"networkunreachable",
		"networkisunreachable",
		"unreachablenetwork")
}

// IsPermissionDenied reports whether err looks like a permission failure
// (EACCES or EPERM), such as a connect blocked by a local firewall rule.
func IsPermissionDenied(err error) bool {
	return err != nil && isPermissionDenied(&errText{err: err})
}

func isPermissionDenied(t *errText) bool {
	return errorIsAny(t.err, accessErrnos) || errorIsAny(t.err, permErrnos) || t.has(
		"permissiondenied",
		"operationnotpermitted",
		"accessisdenied",
		"forbiddenbyitsaccesspermissions")
}

// NetErrorKind returns a stable string category for common network errors:
// "none", "rst", "aborted", "broken_pipe", "refused", "host_unreachable",
// "network_unreachable", "permission_denied", "timeout", "unexpected_eof",
// "eof", "closed" or "other".
func NetErrorKind(err error) string {
	if err == nil {
		return "none"
	}
	return netErrorKind(&errText{err: err})
}

// netErrorKind is NetErrorKind for a non-nil error. The classifiers share t,
// so the error is formatted and normalized at most once.
func netErrorKind(t *errText) string {
	switch {
	case isConnReset(t):
		return "rst"
	case isConnAborted(t):
		return "aborted"
	case isBrokenPipe(t):
		return "broken_pipe"
	case isConnRefused(t):
		return "refused"
	case isHostUnreachable(t):
		return "host_unreachable"
	case isNetworkUnreachable(t):
		return "network_unreachable"
	case isPermissionDenied(t):
		return "permission_denied"
	case isTimeout(t):
		return "timeout"
	case errors.Is(t.err, io.ErrUnexpectedEOF):
		return "unexpected_eof"
	case errors.Is(t.err, io.EOF):
		return "eof"
	case isClosed(t):
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

	t := &errText{err: err}
	parts := []string{
		"kind=" + netErrorKind(t),
		fmt.Sprintf("err=%q", t.text()),
	}

	if c != nil {
		if local := c.LocalAddr(); local != nil {
			parts = append(parts, fmt.Sprintf("local=%s", local.String()))
		}
		if remote := c.RemoteAddr(); remote != nil {
			parts = append(parts, fmt.Sprintf("remote=%s", remote.String()))
		}
	}

	parts = append(parts, fmt.Sprintf("timeout=%t", isTimeout(t)))

	if opErr, ok := errors.AsType[*net.OpError](err); ok {
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

	if sysErr, ok := errors.AsType[*os.SyscallError](err); ok {
		parts = append(parts, fmt.Sprintf("syscall=%s", sysErr.Syscall))
	}

	parts = append(parts, errnoParts(err)...)

	return strings.Join(parts, " ")
}

// errText holds the text of an error for the classifiers' fallbacks. Each
// form is computed on first use, so that NetErrorKind, which may try every
// classifier, formats and normalizes the error only once.
type errText struct {
	err  error
	raw  string // err.Error()
	low  string // raw in lower case
	norm string // low without spaces, hyphens and underscores
	have uint8  // which of raw, low and norm are set
}

const (
	haveRaw uint8 = 1 << iota
	haveLow
	haveNorm
)

func (t *errText) text() string {
	if t.have&haveRaw == 0 {
		t.raw = t.err.Error()
		t.have |= haveRaw
	}
	return t.raw
}

func (t *errText) lower() string {
	if t.have&haveLow == 0 {
		t.low = strings.ToLower(t.text())
		t.have |= haveLow
	}
	return t.low
}

// has reports whether the normalized text contains any of subs.
func (t *errText) has(subs ...string) bool {
	if t.have&haveNorm == 0 {
		t.norm = stripSeparators(t.lower())
		t.have |= haveNorm
	}
	for _, sub := range subs {
		if strings.Contains(t.norm, sub) {
			return true
		}
	}
	return false
}

// stripSeparators removes the spaces, hyphens and underscores from s, so that
// "connection reset by peer" and "connection-reset" variants compare alike.
func stripSeparators(s string) string {
	if !strings.ContainsAny(s, " -_") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := range len(s) {
		switch c := s[i]; c {
		case ' ', '-', '_':
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
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
