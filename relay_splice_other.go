//go:build !linux

package netx

import (
	"context"
	"io"
)

// spliceCopy is splice where there is none: it copies nothing and returns
// false.
func spliceCopy(_ context.Context, _ io.Writer, _ io.Reader, _ *RelayFlow) (int64, bool, error) {
	return 0, false, nil
}
