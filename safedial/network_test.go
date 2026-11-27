package safedial

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/djylb/netx"
	"github.com/djylb/timeshim"
)

type testNetwork struct {
	resolve func(context.Context, string) ([]netip.Addr, error)
	dial    dialerFunc
}

func (n testNetwork) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	return n.dial(ctx, network, addr)
}

func (n testNetwork) Resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	return n.resolve(ctx, host)
}

type sourceNetwork struct {
	testNetwork
	dialFrom func(context.Context, string, netip.Addr, string) (net.Conn, error)
}

func (n sourceNetwork) DialFrom(ctx context.Context, network string, local netip.Addr, addr string) (net.Conn, error) {
	return n.dialFrom(ctx, network, local, addr)
}

func TestNetworkChecksResolvedAddresses(t *testing.T) {
	mapped := netip.MustParseAddr("::ffff:192.0.2.1")
	allowed := netip.MustParseAddr("192.0.2.2")
	answers := []netip.Addr{netip.IPv6Loopback(), mapped, allowed, allowed}
	resolves := 0
	var forward recordDialer
	d := Dialer{
		Network: testNetwork{
			resolve: func(_ context.Context, host string) ([]netip.Addr, error) {
				if host != "service.example" {
					t.Errorf("Resolve host = %q", host)
				}
				resolves++
				return answers, nil
			},
			dial: forward.DialContext,
		},
		Policy: DenyPrefixes(netip.PrefixFrom(mapped.Unmap(), 32)),
	}
	c, err := d.DialContext(t.Context(), "tcp4", "service.example:443")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if got := forward.addresses(); !slices.Equal(got, []string{"192.0.2.2:443"}) {
		t.Errorf("Dial sent to %v", got)
	}
	if resolves != 1 || answers[1] != mapped {
		t.Errorf("Resolve called %d times; answers = %v", resolves, answers)
	}
}

func TestNetworkLocalAddress(t *testing.T) {
	local := netip.MustParseAddr("fe80::2%zone")
	var forward recordDialer
	d := Dialer{
		Network: sourceNetwork{
			testNetwork: testNetwork{dial: forward.DialContext},
			dialFrom: func(ctx context.Context, network string, bind netip.Addr, dest string) (net.Conn, error) {
				if bind != local || network != "udp" || dest != "[fe80::1%remote]:100" {
					t.Errorf("DialFrom(%s, %s, %q)", network, bind, dest)
				}
				return forward.DialContext(ctx, network, dest)
			},
		},
		LocalAddr: local,
		Policy:    All(),
	}
	c, err := d.DialContext(t.Context(), "udp", "[fe80::1%remote]:100")
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if _, err := d.DialContext(t.Context(), "tcp", "192.0.2.1:443"); !errors.Is(err, ErrLocalAddrFamily) || !netx.IsNetworkUnreachable(err) {
		t.Errorf("family mismatch = %v", err)
	}
	d.Network = testNetwork{dial: forward.DialContext}
	if _, err := d.DialContext(t.Context(), "tcp", "[fe80::1%remote]:100"); !errors.Is(err, ErrLocalAddrUnsupported) || !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("network without source binding returned %v", err)
	}
	d.Forward = &forward
	if _, err := d.DialContext(t.Context(), "tcp", "[fe80::1%remote]:100"); !errors.Is(err, ErrLocalAddrUnsupported) {
		t.Errorf("explicit forward with source binding returned %v", err)
	}
	if got := forward.addresses(); !slices.Equal(got, []string{"[fe80::1%remote]:100"}) {
		t.Errorf("forward calls = %v", got)
	}
}

func TestNetworkOverrides(t *testing.T) {
	const host = "service.example"
	var injected, override recordDialer
	d := Dialer{
		Network: testNetwork{
			resolve: func(context.Context, string) ([]netip.Addr, error) {
				return nil, errors.New("unexpected fallback resolution")
			},
			dial: injected.DialContext,
		},
		Forward:  &override,
		Resolver: newFakeResolver(map[string][]string{host: {"192.0.2.1"}}),
		Policy:   All(),
	}
	c, err := d.DialContext(t.Context(), "tcp4", host+":443")
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if got := override.addresses(); !slices.Equal(got, []string{"192.0.2.1:443"}) || len(injected.addresses()) != 0 {
		t.Errorf("forward calls: override %v, network %v", got, injected.addresses())
	}
}

func TestNetworkDoesNotDialAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var forward recordDialer
	d := Dialer{Network: testNetwork{dial: forward.DialContext}, Policy: All()}
	c, err := d.DialContext(ctx, "tcp", "192.0.2.1:443")
	if c != nil {
		_ = c.Close()
	}
	if !errors.Is(err, context.Canceled) || len(forward.addresses()) != 0 {
		t.Errorf("canceled dial returned %v, forward calls = %v", err, forward.addresses())
	}
}

func TestNetworkStaggerClock(t *testing.T) {
	const delay = time.Second
	clock := timeshim.NewFake(time.Time{})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	starts, firstDone := make(chan string, 2), make(chan struct{})
	first := netip.MustParseAddrPort("[2001:db8::1]:443")
	second := netip.MustParseAddrPort("192.0.2.1:443")
	var forward recordDialer
	d := Dialer{
		Network: testNetwork{
			resolve: func(context.Context, string) ([]netip.Addr, error) {
				return []netip.Addr{first.Addr(), second.Addr()}, nil
			},
			dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				starts <- address
				if address == first.String() {
					defer close(firstDone)
					<-ctx.Done()
					return nil, ctx.Err()
				}
				return forward.DialContext(ctx, network, address)
			},
		},
		Policy: All(), Stagger: delay, Clock: clock,
	}
	done := make(chan error, 1)
	go func() {
		c, err := d.DialContext(ctx, "tcp", "service.example:443")
		if c != nil {
			_ = c.Close()
		}
		done <- err
	}()
	select {
	case addr := <-starts:
		if addr != first.String() {
			t.Fatalf("dialed %s first", addr)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	clock.Advance(delay - 1)
	select {
	case addr := <-starts:
		t.Fatalf("dialed %s before stagger", addr)
	default:
	}
	clock.Advance(1)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case <-firstDone:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if got := forward.addresses(); !slices.Equal(got, []string{second.String()}) || clock.Pending() != 0 {
		t.Errorf("winning dials = %v, pending timers = %d", got, clock.Pending())
	}
}
