package netutil

import "time"

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
