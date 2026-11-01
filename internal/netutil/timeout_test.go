package netutil

import (
	"testing"
	"time"
)

func TestTimeout(t *testing.T) {
	for _, tt := range []struct{ d, want time.Duration }{{0, time.Second}, {-1, NoTimeout}, {time.Minute, time.Minute}} {
		if got := Timeout(tt.d, time.Second); got != tt.want {
			t.Errorf("Timeout(%v) = %v", tt.d, got)
		}
	}
	if d := time.Until(time.Now().Add(NoTimeout)); d < 100*365*24*time.Hour {
		t.Errorf("NoTimeout ahead by %v", d)
	}
}
