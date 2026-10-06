package netx

import (
	"errors"
	"net"
	"strings"
	"time"
)

// DefaultTimeout is used when a helper receives a non-positive timeout.
const DefaultTimeout = 5 * time.Second

func normalizeLinkTimeout(timeout time.Duration) time.Duration {
	if timeout <= 0 {
		return DefaultTimeout
	}
	return timeout
}

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
