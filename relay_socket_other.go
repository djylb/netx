//go:build !unix

package netx

// socketSource returns nil: waiting for a socket to become readable without
// reading it needs a Unix poller.
func socketSource(*relaySource) relaySocket { return nil }
