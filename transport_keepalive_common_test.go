package netx

import (
	"testing"
	"time"
)

func TestCeilDuration(t *testing.T) {
	tests := []struct {
		name string
		d    time.Duration
		unit time.Duration
		max  int64
		want int64
	}{
		{name: "exact", d: 3 * time.Second, unit: time.Second, max: 10, want: 3},
		{name: "rounds up", d: 1500 * time.Millisecond, unit: time.Second, max: 10, want: 2},
		{name: "caps", d: 20 * time.Second, unit: time.Second, max: 10, want: 10},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ceilDuration(tt.d, tt.unit, tt.max); got != tt.want {
				t.Fatalf("ceilDuration(%v, %v, %d) = %d, want %d", tt.d, tt.unit, tt.max, got, tt.want)
			}
		})
	}
}

func TestDurationSeconds(t *testing.T) {
	if got := durationSeconds(1500 * time.Millisecond); got != 2 {
		t.Fatalf("durationSeconds(1.5s) = %d, want 2", got)
	}
}
