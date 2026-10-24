package safedial

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/djylb/netx"
	"github.com/djylb/netx/internal/netutil"
)

// ErrDenied matches every *DeniedError: a target that the policy refuses.
var ErrDenied = errors.New("safedial: destination denied")

// ErrRemoteMismatch is the reason of a *DeniedError for a connection whose
// remote address is not the address dialed, with Dialer.VerifyRemoteAddr.
var ErrRemoteMismatch = errors.New("safedial: connected to another address than dialed")

// DeniedError reports a target that the policy refused, or a connection
// that reached another address than the one dialed. It matches ErrDenied
// and Reason with errors.Is.
type DeniedError struct {
	// Target is the target refused: a host name before it is resolved, an
	// address that it resolved to, the first one refused when all of them
	// are, or an IP address dialed as such.
	Target Target
	// Reason is the error that the policy returned, such as ErrScope or
	// ErrPort, or ErrRemoteMismatch.
	Reason error
}

func (e *DeniedError) Error() string {
	reason := "denied"
	if e.Reason != nil {
		reason = strings.TrimPrefix(e.Reason.Error(), "safedial: ")
	}
	return "safedial: " + e.Target.Network + " " + e.Target.String() + ": " + reason
}

// Unwrap returns ErrDenied and Reason.
func (e *DeniedError) Unwrap() []error { return []error{ErrDenied, e.Reason} }

// Resolver looks up the IP addresses of host names, as *net.Resolver does;
// network is "ip", "ip4" or "ip6".
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Dialer dials only the destinations that its Policy allows, for a program
// that connects on behalf of a party it trusts less, such as a tunnel
// client told by a server where to connect, a proxy, or a sender of
// webhooks. It is a netx.ContextDialer, so that it can stand where one
// goes, such as an http.Transport's DialContext.
//
// DialContext parses the address with ParseTarget, so that an IP address
// in any form, also a legacy IPv4 form that a resolver might read as an
// address, is checked as an address. It checks a host name before
// resolving it, then resolves it once and checks every address, and dials
// only the addresses allowed, as IP literals, through Forward. As the check
// binds to the address dialed, a name cannot reach a refused address by
// resolving differently on a later lookup, as in DNS rebinding, and CNAME
// chains do not matter. An HTTP client that follows redirects dials each
// new host through the Dialer again, so redirects are checked too; its
// Transport's Proxy must be nil, as a proxy would resolve and reach the
// names on its own, which no check here can cover, and a Forward that is a
// proxy dialer gets the addresses alone, which reach what they reach from
// the proxy's network.
//
// The zero Dialer, and a nil one, dial with a zero net.Dialer, resolve with
// net.DefaultResolver and allow DefaultPolicy. Its fields must not change
// while it dials or its packet wrappers send.
type Dialer struct {
	// Forward dials the addresses allowed, given as IP literals; a zero
	// net.Dialer if nil. It may be any dialer, such as a netx.RaceDialer
	// or a proxy dialer.
	Forward netx.ContextDialer
	// Resolver resolves host names; net.DefaultResolver if nil.
	Resolver Resolver
	// Policy decides which targets may be reached; DefaultPolicy if nil.
	Policy Policy
	// Stagger is how long the dial of one address of a name runs alone
	// before that of the next starts, as in netx.DialFirst, which also
	// starts the next at once when one fails; netx.DefaultDialStagger if
	// not positive.
	Stagger time.Duration
	// VerifyRemoteAddr, if set, closes a connection whose RemoteAddr is
	// not the address dialed and returns a *DeniedError with
	// ErrRemoteMismatch, for a Forward that might connect elsewhere. It
	// must not be set with a Forward that reports another address, such as
	// a proxy dialer whose connections report the proxy's.
	VerifyRemoteAddr bool
}

var zeroDialer net.Dialer

// errNoConn fails a dial that returned neither a connection nor an error.
var errNoConn = errors.New("safedial: dialer returned no connection")

func (d *Dialer) policy() Policy {
	if d == nil || d.Policy == nil {
		return defaultPolicy
	}
	return d.Policy
}

func (d *Dialer) resolver() Resolver {
	if d == nil || d.Resolver == nil {
		return net.DefaultResolver
	}
	return d.Resolver
}

func (d *Dialer) forward() netx.ContextDialer {
	if d == nil || d.Forward == nil {
		return &zeroDialer
	}
	return d.Forward
}

// check returns a *DeniedError when the policy refuses t, and for a target
// with neither an address nor a name, such as the zero address, whatever
// the policy, as a socket sends to it on the local host.
func (d *Dialer) check(t Target) error {
	if !t.Addr.IsValid() && t.Name == "" {
		return &DeniedError{Target: t, Reason: scopeErrors[netx.ScopeInvalid]}
	}
	if reason := d.policy().Check(t); reason != nil {
		return &DeniedError{Target: t, Reason: reason}
	}
	return nil
}

// Check checks a datagram's or connection's destination ap on network,
// such as "udp", against the policy, unmapped and with its zone apart as
// Target describes, and returns a *DeniedError when the policy refuses it.
// An invalid address, such as that of a *net.UDPAddr without an IP, which
// sockets send to on the local host, is always refused. It does not
// allocate when the policy allows ap and does not allocate
// itself, as the policies of this package do not, so that a relay can
// check every datagram.
func (d *Dialer) Check(network string, ap netip.AddrPort) error {
	t := addrTarget(ap.Addr())
	t.Network, t.Port = network, ap.Port()
	return d.check(t)
}

// Lookup returns the addresses, with their zones, that DialContext would
// dial for network and address, in that order: the IP address of an IP
// literal, or the addresses that a host name resolves to, once, that the
// policy allows, without duplicates and those of another family than
// network's, interleaved by family starting with the first, as Happy
// Eyeballs dials them. It returns a *DeniedError when the policy refuses
// the name or address, or every address that the name resolves to.
func (d *Dialer) Lookup(ctx context.Context, network, address string) ([]netip.AddrPort, error) {
	t, err := ParseTarget(network, address)
	if err != nil {
		return nil, err
	}
	if t.Addr.IsValid() {
		if !familyFits(network, t.Addr) {
			return nil, &net.AddrError{Err: "no suitable address", Addr: address}
		}
		if err := d.check(t); err != nil {
			return nil, err
		}
		return []netip.AddrPort{t.AddrPort()}, nil
	}
	if err := d.check(t); err != nil {
		return nil, err
	}
	ips, err := d.resolver().LookupNetIP(ctx, lookupNetwork(network), t.Name)
	if err != nil {
		return nil, err
	}
	var (
		allowed []netip.AddrPort
		denied  error
	)
	for _, ip := range ips {
		at := addrTarget(ip)
		if !at.Addr.IsValid() || !familyFits(network, at.Addr) {
			continue
		}
		at.Network, at.Name, at.Port = network, t.Name, t.Port
		ap := at.AddrPort()
		if containsAddrPort(allowed, ap) {
			continue
		}
		if err := d.check(at); err != nil {
			if denied == nil {
				denied = err
			}
			continue
		}
		allowed = append(allowed, ap)
	}
	switch {
	case len(allowed) > 0:
		return interleave(allowed), nil
	case denied != nil:
		return nil, denied
	}
	return nil, &net.DNSError{Err: "no suitable address", Name: t.Name, IsNotFound: true}
}

// DialContext dials address on network, "tcp", "tcp4", "tcp6", "udp",
// "udp4" or "udp6", through Forward, at the addresses that Lookup returns:
// one at a time, the next one starting after Stagger or once the one
// before has failed, as netx.DialFirst runs them, so that the first to
// connect wins. A refusal by the policy returns a *DeniedError without
// dialing. When every dial fails, it returns ctx's error when ctx ended the
// dial, or else the errors of every attempt, joined. The name is resolved
// once; the context bounds the lookup and the dials.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	addrs, err := d.Lookup(ctx, network, address)
	if err != nil {
		return nil, err
	}
	var (
		c      net.Conn
		dialed netip.AddrPort
	)
	if len(addrs) == 1 {
		dialed = addrs[0]
		c, err = d.forward().DialContext(ctx, network, dialed.String())
		switch {
		case err == nil && c == nil:
			err = errNoConn
		case err != nil && c != nil:
			_ = c.Close() // returned with its error
		}
	} else {
		strs := make([]string, len(addrs))
		for i, ap := range addrs {
			strs[i] = ap.String()
		}
		var stagger time.Duration
		if d != nil {
			stagger = d.Stagger
		}
		var addr string
		race := netx.RaceDialer{Dialers: []netx.ContextDialer{d.forward()}, Stagger: stagger}
		c, addr, err = race.DialAny(ctx, network, strs...)
		if err == nil {
			dialed = addrs[indexOf(strs, addr)]
		}
	}
	if err != nil {
		return nil, err
	}
	if d != nil && d.VerifyRemoteAddr {
		want := netip.AddrPortFrom(dialed.Addr().Unmap().WithZone(""), dialed.Port())
		if got := netutil.PeerAddrPort(c.RemoteAddr()); got != want {
			_ = c.Close()
			t := addrTarget(got.Addr())
			t.Network, t.Port = network, got.Port()
			return nil, &DeniedError{Target: t, Reason: ErrRemoteMismatch}
		}
	}
	return c, nil
}

// lookupNetwork returns the network to resolve names on for network.
func lookupNetwork(network string) string {
	switch network[len(network)-1] {
	case '4':
		return "ip4"
	case '6':
		return "ip6"
	}
	return "ip"
}

// familyFits reports whether network, such as "tcp4", can dial a, which is
// unmapped.
func familyFits(network string, a netip.Addr) bool {
	switch network[len(network)-1] {
	case '4':
		return a.Is4()
	case '6':
		return a.Is6()
	}
	return true
}

func containsAddrPort(aps []netip.AddrPort, ap netip.AddrPort) bool {
	for _, x := range aps {
		if x == ap {
			return true
		}
	}
	return false
}

func indexOf(strs []string, s string) int {
	for i, x := range strs {
		if x == s {
			return i
		}
	}
	return 0
}

// interleave orders addrs by alternating families, starting with the
// family of the first and keeping the order within each, as RFC 8305 does.
func interleave(addrs []netip.AddrPort) []netip.AddrPort {
	if len(addrs) < 3 {
		return addrs // in order whatever their families
	}
	first := addrs[0].Addr().Is4()
	var same, other []netip.AddrPort
	for _, ap := range addrs {
		if ap.Addr().Is4() == first {
			same = append(same, ap)
		} else {
			other = append(other, ap)
		}
	}
	out := addrs[:0:0]
	for i := range max(len(same), len(other)) {
		if i < len(same) {
			out = append(out, same[i])
		}
		if i < len(other) {
			out = append(out, other[i])
		}
	}
	return out
}
