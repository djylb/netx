package safedial

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/djylb/netx"
)

// Network resolves host names and dials the IP literals selected by Dialer.
// Implementations must be safe for concurrent use and honor cancellation.
// Dialer reads the returned address slice without modifying it.
type Network interface {
	Dial(ctx context.Context, network, address string) (net.Conn, error)
	Resolve(ctx context.Context, host string) ([]netip.Addr, error)
}

// NetworkFrom is the optional capability of a Network to dial from a
// specified local address. The supplied destination is an IP literal.
type NetworkFrom interface {
	DialFrom(ctx context.Context, network string, local netip.Addr, address string) (net.Conn, error)
}

// ErrLocalAddrUnsupported means the configured dialer cannot bind LocalAddr.
// It also matches errors.ErrUnsupported.
var ErrLocalAddrUnsupported = fmt.Errorf("safedial: cannot bind local address: %w", errors.ErrUnsupported)

// ErrLocalAddrFamily means a local and remote IP address have different families.
var ErrLocalAddrFamily = errors.New("safedial: network unreachable for local address family")

type dialContextFunc func(context.Context, string, string) (net.Conn, error)

func (f dialContextFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

func (d *Dialer) forward(network string) (netx.ContextDialer, error) {
	if d == nil {
		return &zeroDialer, nil
	}
	local := d.LocalAddr.Unmap()
	if !local.IsValid() {
		switch {
		case d.Forward != nil:
			return d.Forward, nil
		case d.Network != nil:
			return dialContextFunc(d.Network.Dial), nil
		default:
			return &zeroDialer, nil
		}
	}
	if d.Forward != nil {
		return nil, ErrLocalAddrUnsupported
	}

	var dial dialContextFunc
	if d.Network != nil {
		n, ok := d.Network.(NetworkFrom)
		if !ok {
			return nil, ErrLocalAddrUnsupported
		}
		dial = func(ctx context.Context, network, address string) (net.Conn, error) {
			return n.DialFrom(ctx, network, local, address)
		}
	} else {
		bind := netip.AddrPortFrom(local, 0)
		var addr net.Addr = net.TCPAddrFromAddrPort(bind)
		if network[0] == 'u' {
			addr = net.UDPAddrFromAddrPort(bind)
		}
		dial = (&net.Dialer{LocalAddr: addr}).DialContext
	}

	return dialContextFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		remote, err := netip.ParseAddrPort(address)
		if err != nil {
			return nil, err
		}
		if remote.Addr().Is4() != local.Is4() {
			return nil, &net.OpError{Op: "dial", Net: network, Err: ErrLocalAddrFamily}
		}
		return dial(ctx, network, address)
	}), nil
}
