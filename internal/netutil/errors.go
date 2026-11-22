package netutil

import (
	"errors"
	"io"
	"net"
	"strings"
)

// IsClosed reports a closed network connection, including wrappers that
// only preserve the standard error text.
func IsClosed(err error) bool {
	return err != nil && (IsClosedValue(err) || IsClosedText(err.Error()))
}

// IsClosedValue matches the closed-connection sentinel errors.
func IsClosedValue(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe)
}

// IsClosedText matches the usual error text of a closed connection.
func IsClosedText(message string) bool {
	return strings.Contains(message, "use of closed network connection")
}

// IsAddrNotAvailable reports an unavailable source or bind address.
func IsAddrNotAvailable(err error) bool {
	return err != nil && MatchAddrNotAvailable(isAddrNotAvailableValue(err), func() string {
		return StripSeparators(strings.ToLower(err.Error()))
	})
}

// MatchAddrNotAvailable applies the same rule as IsAddrNotAvailable to a
// cached match against AddrNotAvailableErrnos and a normalized error message.
// It calls normalized only if the errno did not match.
func MatchAddrNotAvailable(errnoMatched bool, normalized func() string) bool {
	if errnoMatched {
		return true
	}
	s := normalized()
	return strings.Contains(s, "cannotassignrequestedaddress") ||
		strings.Contains(s, "requestedaddressisnotvalidinitscontext")
}

// StripSeparators removes spaces, hyphens and underscores so text such as
// "connection reset by peer" and "connection-reset" compares alike.
func StripSeparators(s string) string {
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

// RawOpError reports an error of syscall.RawConn's Read or Write, whose
// operation is "raw-read" or "raw-write", as one of Read or Write, op.
func RawOpError(err error, op string) error {
	if err == nil {
		return nil
	}
	if oe, ok := errors.AsType[*net.OpError](err); ok {
		if rawOp, raw := strings.CutPrefix(oe.Op, "raw-"); !raw || rawOp != op {
			return err
		}
		e := *oe
		e.Op = op
		return &e
	}
	return err
}
