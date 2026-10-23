//go:build !linux

package netx

import "context"

// spliceCopy is splice where there is none: it copies nothing and returns
// false.
func spliceCopy(_ context.Context, _ *relaySink, _ *relaySource, _ *RelayFlow) (int64, bool, error) {
	return 0, false, nil
}
