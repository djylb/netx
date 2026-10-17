//go:build !unix

package netx

import "io"

// socketSource returns nil: waiting for a socket to become readable without
// reading it needs a Unix poller.
func socketSource(io.Reader) relaySocket { return nil }
