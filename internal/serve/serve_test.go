package serve

import (
	"net"
	"sync/atomic"
	"testing"
)

type closeCounter struct {
	net.Conn
	closed atomic.Int32
}

func (c *closeCounter) Close() error { c.closed.Add(1); return nil }

// Close leaves a connection handed off to its relay open, which ends it, and
// refuses a hand-off once it has started.
func TestHandOff(t *testing.T) {
	var tr Tracker
	var plain, owned net.Conn = &closeCounter{}, &closeCounter{}
	for _, c := range []*net.Conn{&plain, &owned} {
		if !tr.TrackConn(c, true) {
			t.Fatal("TrackConn refused")
		}
	}
	if !tr.HandOff(&owned) {
		t.Fatal("HandOff refused before Close")
	}
	if err := tr.Close(nil); err != nil {
		t.Fatal(err)
	}
	if n := plain.(*closeCounter).closed.Load(); n != 1 {
		t.Errorf("plain connection closed %d times, want 1", n)
	}
	if n := owned.(*closeCounter).closed.Load(); n != 0 {
		t.Errorf("handed-off connection closed %d times, want 0", n)
	}
	if tr.HandOff(&plain) {
		t.Error("HandOff succeeded after Close")
	}
	if got := tr.ActiveConns(); got != 2 {
		t.Errorf("ActiveConns() = %d, want both still counted until they end", got)
	}
}
