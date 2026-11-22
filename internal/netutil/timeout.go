package netutil

import (
	"errors"
	"net"
	"os"
	"time"
)

// IsDeadlineTimeout reports whether err matches an expired I/O deadline or the
// first net.Error in its chain reports a timeout.
func IsDeadlineTimeout(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	ne, ok := errors.AsType[net.Error](err)
	return ok && ne.Timeout()
}

// NoTimeout stands for a timeout of none: deadlines that far ahead never
// pass, and adding it to the time cannot overflow.
const NoTimeout time.Duration = 1 << 62

// Timeout returns the timeout a setting d selects: def for 0, NoTimeout
// for a negative d, as for http.Server.IdleTimeout, and d otherwise.
func Timeout(d, def time.Duration) time.Duration {
	switch {
	case d == 0:
		return def
	case d < 0:
		return NoTimeout
	}
	return d
}
