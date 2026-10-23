package netx

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// stubDialer dials by address: "fail" fails at once, "hang" waits for its
// context, and others connect after the delay that delays gives them.
type stubDialer struct {
	delays map[string]time.Duration
	mu     sync.Mutex
	dialed []string
	conns  []*countedCloseConn
}

func (d *stubDialer) DialContext(ctx context.Context, _, address string) (net.Conn, error) {
	d.mu.Lock()
	d.dialed = append(d.dialed, address)
	d.mu.Unlock()
	switch address {
	case "fail":
		return nil, errors.New("refused")
	case "hang":
		<-ctx.Done()
		return nil, ctx.Err()
	case "deadline":
		// As net.Dialer, whose own deadline can pass before ctx reports it.
		if dl, ok := ctx.Deadline(); ok {
			time.Sleep(time.Until(dl))
		}
		return nil, os.ErrDeadlineExceeded
	case "nil":
		return nil, nil
	case "both":
		c := &countedCloseConn{}
		d.mu.Lock()
		d.conns = append(d.conns, c)
		d.mu.Unlock()
		return c, errors.New("half done")
	}
	time.Sleep(d.delays[address])
	c := &countedCloseConn{}
	d.mu.Lock()
	d.conns = append(d.conns, c)
	d.mu.Unlock()
	return c, nil
}

func TestDialAny(t *testing.T) {
	ctx := context.Background()
	t.Run("a failure starts the next at once", func(t *testing.T) {
		d := &dialAnyCase{Addresses: []string{"fail", "b"}, Stagger: time.Hour, Forward: &stubDialer{}}
		start := time.Now()
		if _, addr, err := d.DialAny(ctx, "tcp"); err != nil || addr != "b" || time.Since(start) > time.Second {
			t.Fatalf("Dial() = %q, %v after %v", addr, err, time.Since(start))
		}
	})
	t.Run("a slow address does not hold up the next", func(t *testing.T) {
		d := &dialAnyCase{Addresses: []string{"hang", "b"}, Stagger: 20 * time.Millisecond, Forward: &stubDialer{}}
		if _, addr, err := d.DialAny(ctx, "tcp"); err != nil || addr != "b" {
			t.Fatalf("Dial() = %q, %v", addr, err)
		}
	})
	t.Run("the first preferred address wins when it connects in time", func(t *testing.T) {
		f := &stubDialer{}
		d := &dialAnyCase{Addresses: []string{"a", "b"}, Stagger: time.Second, Forward: f}
		if _, addr, err := d.DialAny(ctx, "tcp"); err != nil || addr != "a" || len(f.dialed) != 1 {
			t.Fatalf("Dial() = %q, %v; dialed %v", addr, err, f.dialed)
		}
	})
	t.Run("late connections are closed", func(t *testing.T) {
		f := &stubDialer{delays: map[string]time.Duration{"a": 100 * time.Millisecond}}
		d := &dialAnyCase{Addresses: []string{"a", "b"}, Stagger: 10 * time.Millisecond, Forward: f}
		c, addr, err := d.DialAny(ctx, "tcp")
		if err != nil || addr != "b" {
			t.Fatalf("Dial() = %q, %v", addr, err)
		}
		waitUntil(t, func() bool {
			f.mu.Lock()
			defer f.mu.Unlock()
			return len(f.conns) == 2
		})
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, fc := range f.conns {
			if net.Conn(fc) != c && fc.Calls() == 0 {
				waitUntil(t, func() bool { return fc.Calls() == 1 })
			}
		}
	})
	t.Run("all failing returns every error", func(t *testing.T) {
		d := &dialAnyCase{Addresses: []string{"fail", "fail"}, Forward: &stubDialer{}}
		_, _, err := d.DialAny(ctx, "tcp")
		if err == nil || len(err.(interface{ Unwrap() []error }).Unwrap()) != 2 ||
			!strings.HasPrefix(err.Error(), "fail: refused") {
			t.Fatalf("DialAny() error = %v, want both, prefixed by address", err)
		}
	})
	t.Run("the context ends the dial", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
		defer cancel()
		d := &dialAnyCase{Addresses: []string{"hang", "hang"}, Stagger: 10 * time.Millisecond, Forward: &stubDialer{}}
		if _, _, err := d.DialAny(ctx, "tcp"); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Dial() error = %v, want the deadline", err)
		}
	})
	t.Run("a deadline reports as the context's", func(t *testing.T) {
		d := &dialAnyCase{Addresses: []string{"deadline"}, Forward: &stubDialer{}}
		for range 20 {
			// The attempt's failure and Done race, as with net.Dialer.
			ctx, cancel := context.WithTimeout(ctx, 5*time.Millisecond)
			_, _, err := d.DialAny(ctx, "tcp")
			cancel()
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("Dial() error = %v, want the context's deadline", err)
			}
		}
	})
	t.Run("odd Forward results fail and are closed", func(t *testing.T) {
		f := &stubDialer{}
		d := &dialAnyCase{Addresses: []string{"nil", "both"}, Forward: f}
		if c, _, err := d.DialAny(ctx, "tcp"); c != nil || err == nil {
			t.Fatalf("Dial() = %v, %v; want an error", c, err)
		}
		if f.conns[0].Calls() != 1 {
			t.Fatal("a connection returned with an error was not closed")
		}
	})
	t.Run("no addresses", func(t *testing.T) {
		if _, _, err := (&dialAnyCase{}).DialAny(ctx, "tcp"); !errors.Is(err, ErrNoDialAttempts) {
			t.Fatalf("DialAny() without addresses error = %v, want ErrNoDialAttempts", err)
		}
	})
	t.Run("real TCP", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Skip(err)
		}
		defer func() { _ = ln.Close() }()
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				_ = c.Close()
			}
		}()
		d := &dialAnyCase{Addresses: []string{"127.0.0.1:1", ln.Addr().String()}}
		c, addr, err := d.DialAny(ctx, "tcp")
		if err != nil || addr != ln.Addr().String() {
			t.Fatalf("DialAny() = %q, %v", addr, err)
		}
		_ = c.Close()
	})
}

// DialFirst races different kinds of attempts and reports the winner's index.
func TestDialFirst(t *testing.T) {
	ctx := context.Background()
	f := &stubDialer{}
	via := func(address string) func(context.Context) (net.Conn, error) {
		return func(ctx context.Context) (net.Conn, error) { return f.DialContext(ctx, "tcp", address) }
	}
	c, i, err := DialFirst(ctx, 0, via("fail"), via("hang"), via("b"))
	if err != nil || c == nil || i != 2 {
		t.Fatalf("DialFirst() = %v, %d, %v; want the third", c, i, err)
	}
	if _, i, err := DialFirst(ctx, time.Hour); i != -1 || !errors.Is(err, ErrNoDialAttempts) {
		t.Fatalf("DialFirst() without attempts = %d, %v", i, err)
	}
	if _, i, err := DialFirst(ctx, time.Hour, via("fail")); i != -1 || err == nil {
		t.Fatalf("failing DialFirst() = %d, %v", i, err)
	}
}

// dialAnyCase holds the arguments of a DialAny call.
type dialAnyCase struct {
	Addresses []string
	Stagger   time.Duration
	Forward   ContextDialer
}

func (c *dialAnyCase) DialAny(ctx context.Context, network string) (net.Conn, string, error) {
	d := &RaceDialer{Stagger: c.Stagger}
	if c.Forward != nil {
		d.Dialers = []ContextDialer{c.Forward}
	}
	return d.DialAny(ctx, network, c.Addresses...)
}

// A RaceDialer races its dialers to one address and is a ContextDialer.
func TestRaceDialer(t *testing.T) {
	ctx := context.Background()
	fast := &stubDialer{}
	var d ContextDialer = &RaceDialer{Dialers: []ContextDialer{failDialer{}, fast}, Stagger: time.Hour}
	if c, err := d.DialContext(ctx, "tcp", "x"); err != nil || c == nil {
		t.Fatalf("DialContext() = %v, %v; want the second dialer's connection", c, err)
	}
	// Every dialer for the first address, then for the next.
	c, addr, err := (&RaceDialer{Dialers: []ContextDialer{failDialer{}, fast}, Stagger: time.Hour}).DialAny(ctx, "tcp", "a", "b")
	if err != nil || c == nil || addr != "a" {
		t.Fatalf("DialAny() = %v, %q, %v; want the second dialer's connection to the first address", c, addr, err)
	}
	var none *RaceDialer
	if _, _, err := none.DialAny(ctx, "tcp"); !errors.Is(err, ErrNoDialAttempts) {
		t.Fatalf("DialAny() without addresses = %v, want ErrNoDialAttempts", err)
	}
}

type failDialer struct{}

func (failDialer) DialContext(_ context.Context, _, _ string) (net.Conn, error) {
	return nil, errors.New("refused")
}
