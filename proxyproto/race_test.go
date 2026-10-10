//go:build race

package proxyproto

// raceEnabled reports whether the race detector is on; it makes sync.Pool
// drop items at random, so pooling cannot be measured.
const raceEnabled = true
