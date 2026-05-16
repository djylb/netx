package netx

import "errors"

// ErrOriginalDestinationUnsupported is returned when original destination lookup is unavailable.
var ErrOriginalDestinationUnsupported = errors.New("original destination lookup is not supported on this platform")
