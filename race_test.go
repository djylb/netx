//go:build race

package netx

// raceEnabled reports whether the race detector, which makes sync.Pool drop
// a quarter of its Puts, is on.
const raceEnabled = true
