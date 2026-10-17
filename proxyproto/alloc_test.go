//go:build !race && !js && !wasip1

// The race detector adds allocations, and js/wasm keeps less in a sync.Pool
// across runs, so the allocation counts are checked only without them.

package proxyproto

import (
	"io"
	"testing"
)

// Writing a small header allocates nothing.
func TestHeaderWriteToAllocs(t *testing.T) {
	small, err := NewHeader(V2, tcp("192.0.2.1", 1), tcp("192.0.2.2", 2))
	if err != nil {
		t.Fatal(err)
	}
	if allocs := testing.AllocsPerRun(100, func() { _, _ = small.WriteTo(io.Discard) }); allocs != 0 {
		t.Fatalf("WriteTo() allocates %v times, want 0", allocs)
	}
}
