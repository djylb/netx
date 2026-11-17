package dgram

import (
	"runtime"
	"strconv"
	"testing"
	"time"
)

type benchConn struct{ q Queue }

func newBenchTable(idle time.Duration) *Table[int, *benchConn] {
	t := new(Table[int, *benchConn])
	t.Init(TableOptions[*benchConn]{Queue: func(c *benchConn) *Queue { return &c.q },
		Shutdown: func(*benchConn, error) {}, Backlog: 1, Idle: idle})
	return t
}

// BenchmarkTable looks connections up from all cores in tables of a few and
// of a million connections, and reports the table's memory per connection
// with an idle timeout, beyond the connections themselves.
func BenchmarkTable(b *testing.B) {
	for _, n := range []int{10, 1 << 20} {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			conns := make([]*benchConn, n)
			for i := range conns {
				conns[i] = new(benchConn)
			}
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			t := newBenchTable(time.Hour)
			for i, c := range conns {
				t.Add(i, c, false)
			}
			runtime.GC()
			runtime.ReadMemStats(&after)
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				i := 0
				for pb.Next() {
					t.Get(i % n)
					i += 7
				}
			})
			b.StopTimer()
			b.ReportMetric(float64(after.HeapInuse-before.HeapInuse)/float64(n), "B/conn")
			t.Close(nil)
		})
	}
}
