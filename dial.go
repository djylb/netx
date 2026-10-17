package netx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// DefaultDialStagger is how long DialFirst waits for an attempt before it
// starts the next when stagger is not positive.
const DefaultDialStagger = 300 * time.Millisecond

// ContextDialer dials connections. *net.Dialer implements it, as do the
// dialers of the proxydial, socks5 and tlsconn packages.
type ContextDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// ErrNoDialAttempts is returned by DialFirst without attempts, by DialAny
// without addresses and by a RaceDialer without dialers.
var ErrNoDialAttempts = errors.New("netx: nothing to dial")

// errNoConn is the failure of an attempt that returned neither a connection
// nor an error.
var errNoConn = errors.New("netx: dialer returned no connection")

// DialFirst runs attempts, which may dial in different ways, such as directly
// and through a relay, and returns the first connection made and the index of
// the attempt that made it. It starts them in order, starting the next while
// earlier ones go on whenever one has not connected within stagger, or at
// once when one fails; a non-positive stagger means DefaultDialStagger. The
// other attempts are cancelled, and connections they still make are closed.
//
// When none connects, it returns -1 and the errors of every attempt, joined,
// or ctx's error when ctx ended the dial. An attempt that returns a
// connection with an error fails, and its connection is closed.
func DialFirst(ctx context.Context, stagger time.Duration, attempts ...func(context.Context) (net.Conn, error)) (net.Conn, int, error) {
	if len(attempts) == 0 {
		return nil, -1, ErrNoDialAttempts
	}
	if stagger <= 0 {
		stagger = DefaultDialStagger
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Buffered for every attempt, so that none blocks once DialFirst returns.
	results := make(chan dialResult, len(attempts))
	timer := time.NewTimer(stagger)
	defer timer.Stop()
	var (
		next    int // the next attempt to start
		running int
		errs    []error
	)
	start := func() {
		i, attempt := next, attempts[next]
		next++
		running++
		go func() {
			c, err := attempt(ctx)
			results <- dialResult{c, i, err}
		}()
		timer.Reset(stagger)
	}
	start()
	// A failure starts the next attempt, so one runs until all have ended.
	for running > 0 {
		select {
		case r := <-results:
			running--
			if r.err == nil && r.conn == nil {
				r.err = errNoConn
			}
			if r.err == nil {
				cancel()
				go closeLate(results, running)
				return r.conn, r.index, nil
			}
			if r.conn != nil {
				_ = r.conn.Close() // returned with its error
			}
			errs = append(errs, r.err)
			if next < len(attempts) && ctx.Err() == nil {
				start() // a failure starts the next at once
			}
		case <-timer.C:
			if next < len(attempts) {
				start()
			}
		case <-ctx.Done():
			go closeLate(results, running)
			return nil, -1, ctx.Err()
		}
	}
	// The attempts can fail on ctx's deadline, as net.Dialer's own deadline,
	// before ctx reports it.
	if err := ctx.Err(); err != nil {
		return nil, -1, err
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return nil, -1, context.DeadlineExceeded
	}
	return nil, -1, errors.Join(errs...)
}

// DialAny dials one of several addresses of a service, such as the entry
// points of a cluster, with DialFirst: one attempt per address, in order of
// preference, each dialed with d, nil meaning a zero net.Dialer. It returns
// the connection and the address that it connects to. When none connects, it
// returns ErrNoDialAttempts without addresses, ctx's error when ctx ended the
// dial, or else the errors of every attempt, joined, each naming its address.
func DialAny(ctx context.Context, stagger time.Duration, d ContextDialer, network string, addresses ...string) (net.Conn, string, error) {
	if d == nil {
		d = &net.Dialer{}
	}
	attempts := make([]func(context.Context) (net.Conn, error), len(addresses))
	for i, address := range addresses {
		attempts[i] = func(ctx context.Context) (net.Conn, error) {
			c, err := d.DialContext(ctx, network, address)
			if err != nil && !strings.Contains(err.Error(), address) {
				err = fmt.Errorf("%s: %w", address, err)
			}
			return c, err
		}
	}
	c, i, err := DialFirst(ctx, stagger, attempts...)
	if err != nil {
		return nil, "", err
	}
	return c, addresses[i], nil
}

// RaceDialer dials an address through several dialers, such as directly and
// through a relay or several proxies, with DialFirst, and returns the first
// connection made. It is a ContextDialer, so that it can stand where one
// goes, such as an http.Transport's DialContext or a proxy dialer's Forward.
// Its fields must not change while it dials.
type RaceDialer struct {
	// Dialers are the dialers to race, in order of preference.
	Dialers []ContextDialer
	// Stagger is how long an attempt runs alone before the next one
	// starts; DefaultDialStagger if not positive.
	Stagger time.Duration
}

// DialContext dials address through each of d's dialers, as DialFirst
// starts them, and returns the first connection made. When none connects, it
// returns ErrNoDialAttempts without dialers, ctx's error when ctx ended the
// dial, or else the errors of every attempt, joined.
func (d *RaceDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	attempts := make([]func(context.Context) (net.Conn, error), len(d.Dialers))
	for i, dialer := range d.Dialers {
		attempts[i] = func(ctx context.Context) (net.Conn, error) {
			return dialer.DialContext(ctx, network, address)
		}
	}
	c, _, err := DialFirst(ctx, d.Stagger, attempts...)
	return c, err
}

// dialResult is the end of one DialFirst attempt.
type dialResult struct {
	conn  net.Conn
	index int
	err   error
}

// closeLate closes the connections that the n attempts still running make.
func closeLate(results <-chan dialResult, n int) {
	for range n {
		if r := <-results; r.conn != nil {
			_ = r.conn.Close()
		}
	}
}
