package netx_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/djylb/netx"
)

// byteLimiter is a shared bandwidth limit for RelayFlow: Done charges what
// passed, which may put the limiter in debt, and Wait waits the debt out, so
// a relay idle in a read holds none of the allowance. It is safe for
// concurrent use by many relays.
type byteLimiter struct {
	mu     sync.Mutex
	rate   float64 // bytes per second
	burst  float64
	tokens float64
	last   time.Time
}

func newByteLimiter(bytesPerSecond, burst int64) *byteLimiter {
	return &byteLimiter{rate: float64(bytesPerSecond), burst: float64(burst), tokens: float64(burst), last: time.Now()}
}

// refill adds the tokens earned since the last call; l.mu is held.
func (l *byteLimiter) refill(now time.Time) {
	l.tokens = min(l.burst, l.tokens+now.Sub(l.last).Seconds()*l.rate)
	l.last = now
}

// Wait blocks while the limiter is in debt and then lets up to n bytes pass.
func (l *byteLimiter) Wait(ctx context.Context, n int64) (int64, error) {
	for {
		l.mu.Lock()
		l.refill(time.Now())
		if l.tokens >= 1 {
			allowed := min(n, int64(l.tokens))
			l.mu.Unlock()
			return allowed, nil
		}
		wait := time.Duration((1 - l.tokens) / l.rate * float64(time.Second))
		l.mu.Unlock()
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return 0, ctx.Err()
		case <-t.C:
		}
	}
}

// Done charges the bytes that passed.
func (l *byteLimiter) Done(n int64) error {
	l.mu.Lock()
	l.refill(time.Now())
	l.tokens -= float64(n)
	l.mu.Unlock()
	return nil
}

// Limit the bandwidth that a user's relays share.
func ExampleWithRelayFlows_limit() {
	user := newByteLimiter(64<<10, 16<<10) // 64 KiB/s, bursts of 16 KiB
	flow := netx.RelayFlow{Wait: user.Wait, Done: user.Done}

	client, front := net.Pipe()
	back, backend := net.Pipe()
	go func() { _, _ = io.Copy(io.Discard, backend) }()
	go func() { _, _, _ = netx.Relay(context.Background(), front, back, netx.WithRelayFlows(flow, flow)) }()

	start := time.Now()
	_, _ = client.Write(make([]byte, 48<<10)) // 16 KiB at once, then 32 KiB at 64 KiB/s
	_ = client.Close()
	fmt.Println(time.Since(start) >= 400*time.Millisecond)
	// Output: true
}
