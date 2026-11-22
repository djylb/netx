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

func TestReadDatagramAllocs(t *testing.T) {
	for _, tt := range []struct {
		name       string
		mode       DatagramMode
		wire       []byte
		wantHeader bool
		maxAllocs  float64
	}{
		{name: "Auto without a header", mode: DatagramAuto, wire: []byte("query")},
		{
			name:       "Each with a v2 DGRAM header",
			mode:       DatagramEach,
			wire:       append(wireOf(V2, udp("192.0.2.1", 1), udp("192.0.2.2", 2)), "query"...),
			wantHeader: true,
			maxAllocs:  5, // The header and two UDP addresses with their IP bytes.
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			msgs := [][]byte{tt.wire}
			raw := &datagramScript{}
			c := NewConn(raw, Config{Datagram: tt.mode})
			buf := make([]byte, 5)
			var (
				n   int
				h   *Header
				err error
			)
			allocs := testing.AllocsPerRun(100, func() {
				raw.msgs = msgs
				n, h, err = c.ReadDatagram(buf)
			})
			if err != nil || string(buf[:n]) != "query" || (h != nil) != tt.wantHeader {
				t.Fatalf("ReadDatagram() = %q, %v, %v", buf[:n], h, err)
			}
			if allocs > tt.maxAllocs {
				t.Fatalf("ReadDatagram() allocates %v times, want at most %v", allocs, tt.maxAllocs)
			}
		})
	}
}
