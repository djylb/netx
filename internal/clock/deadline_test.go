package clock

import (
	"testing"
	"time"
)

func TestDeadlineStopReleasesTimer(t *testing.T) {
	d := MakeDeadline()
	defer d.Stop()
	future := time.Now().Add(time.Hour)
	d.Set(future)
	d.Stop()
	if d.timer != nil {
		t.Fatal("deadline timer was kept after Stop")
	}
	d.Set(future)
	if d.timer != nil {
		t.Fatal("Set armed a stopped deadline")
	}
}
