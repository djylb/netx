package transparent

import (
	"errors"
	"fmt"
)

// ErrOriginalDestinationUnsupported is returned by OriginalDestination on
// platforms without a lookup. It matches errors.ErrUnsupported.
var ErrOriginalDestinationUnsupported = fmt.Errorf("transparent: original destination lookup is not supported on this platform: %w", errors.ErrUnsupported)
