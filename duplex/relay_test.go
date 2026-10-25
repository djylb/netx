package duplex_test

import (
	"io"
	"testing"

	"github.com/djylb/netx"
	"github.com/djylb/netx/duplex"
)

// Relay between two joined connections passes data and half-closes on.
func TestRelayHalfClose(t *testing.T) {
	noLeaks(t)
	in1r, in1w := io.Pipe()
	out1r, out1w := io.Pipe()
	in2r, in2w := io.Pipe()
	out2r, out2w := io.Pipe()
	a, b := duplex.Join(in1r, out1w), duplex.Join(in2r, out2w)

	got := make(chan string, 2)
	for _, r := range []io.Reader{out1r, out2r} {
		go func() {
			data, _ := io.ReadAll(r)
			got <- string(data)
		}()
	}
	go func() {
		_, _ = in1w.Write([]byte("ping"))
		_ = in1w.Close()
		_, _ = in2w.Write([]byte("pong!"))
		_ = in2w.Close()
	}()
	up, down, err := netx.Relay(t.Context(), a, b, netx.WithRelayHalfClose())
	if up != 4 || down != 5 || err != nil {
		t.Fatalf("Relay = %d, %d, %v", up, down, err)
	}
	if x, y := <-got, <-got; x+y != "pingpong!" && x+y != "pong!ping" {
		t.Fatalf("got %q and %q", x, y)
	}
}
