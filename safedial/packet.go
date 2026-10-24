package safedial

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/djylb/netx"
	"github.com/djylb/netx/internal/dgram"
	"github.com/djylb/netx/internal/netutil"
)

// ErrLookupBusy drops a datagram to a host name that a packet wrapper is
// looking up, or is to look up, while it holds as many datagrams, or runs
// as many lookups, as it may.
var ErrLookupBusy = errors.New("safedial: too many datagrams wait for name lookups")

// lookupTimeout bounds each lookup of a host name by the packet wrappers.
const lookupTimeout = 10 * time.Second

// packetNetwork is the network of the targets that the packet wrappers
// check.
const packetNetwork = "udp"

// AddrPacketConn sends datagrams to destinations named by a netx.Addr, an IP
// address or a host name, and receives replies, in the shape of the
// outbound side of a SOCKS5 UDP association (socks5.PacketConn), which the
// wrapper that WrapAddrPacketConn returns therefore is.
type AddrPacketConn interface {
	// WriteTo sends p to dst. It must not retain p.
	WriteTo(p []byte, dst netx.Addr) (int, error)
	// ReadFrom reads the next datagram and returns its source.
	ReadFrom(p []byte) (n int, src netx.Addr, err error)
	// Close closes the connection and unblocks ReadFrom.
	Close() error
}

// guard checks the destinations of datagrams and resolves the host names
// among them, holding the datagrams to a name while it is looked up.
type guard struct {
	d     *Dialer
	names *dgram.Lookups[[]netip.Addr] // unmapped, IPv4 first, zones kept
}

// newGuard returns a guard whose held datagrams go to send.
func newGuard(d *Dialer, send func(p []byte, ap netip.AddrPort)) *guard {
	g := &guard{d: d}
	g.names = dgram.NewLookups(lookupTimeout, ErrLookupBusy, g.lookup,
		func(p []byte, name string, addrs []netip.Addr, port uint16) {
			if ap, err := g.pick(addrs, name, port); err == nil {
				send(p, ap)
			}
		})
	return g
}

func (g *guard) close() { g.names.Close() }

// route checks a datagram to name and port and returns the address to send
// it to, or holds a copy of p until name resolves, and reports whether it
// did.
func (g *guard) route(p []byte, name string, port uint16) (ap netip.AddrPort, held bool, err error) {
	t, err := nameTarget(name)
	if err != nil {
		return netip.AddrPort{}, false, err
	}
	t.Network, t.Port = packetNetwork, port
	if err := g.d.check(t); err != nil {
		return netip.AddrPort{}, false, err
	}
	if t.Addr.IsValid() { // a legacy IPv4 form
		return t.AddrPort(), false, nil
	}
	addrs, held, err := g.names.Route(p, t.Name, port)
	if err != nil || held {
		return netip.AddrPort{}, held, err
	}
	ap, err = g.pick(addrs, t.Name, port)
	return ap, false, err
}

// pick returns the first of addrs, the addresses of name, that the policy
// allows for port, or the refusal of the first.
func (g *guard) pick(addrs []netip.Addr, name string, port uint16) (netip.AddrPort, error) {
	var denied error
	for _, a := range addrs {
		t := addrTarget(a)
		t.Network, t.Name, t.Port = packetNetwork, name, port
		err := g.d.check(t)
		if err == nil {
			return t.AddrPort(), nil
		}
		if denied == nil {
			denied = err
		}
	}
	return netip.AddrPort{}, denied
}

// lookup resolves name into its addresses, unmapped, without duplicates and
// IPv4 first, which IPv4 and dual-stack sockets both reach.
func (g *guard) lookup(ctx context.Context, name string) ([]netip.Addr, error) {
	ips, err := g.d.resolver().LookupNetIP(ctx, "ip", name)
	if err != nil {
		return nil, err
	}
	var addrs []netip.Addr
	for _, ip := range ips {
		t := addrTarget(ip)
		if a := t.Addr.WithZone(t.Zone); t.Addr.IsValid() && !slices.Contains(addrs, a) {
			addrs = append(addrs, a)
		}
	}
	slices.SortStableFunc(addrs, func(a, b netip.Addr) int {
		switch {
		case a.Is4() == b.Is4():
			return 0
		case a.Is4():
			return -1
		}
		return 1
	})
	if len(addrs) == 0 {
		return nil, &net.DNSError{Err: "no suitable address", Name: name, IsNotFound: true}
	}
	return addrs, nil
}

// WrapAddrPacketConn returns c with every destination checked against d's
// policy, for a relay that sends datagrams to destinations that a less
// trusted party names, such as a SOCKS5 server's UDP associations: it can
// stand for the socks5.PacketConn that a DatagramRelay or a Server's
// DialPacket sends through. WriteTo sends a datagram to an IP address that
// the policy allows through c, and fails with a *DeniedError, dropping it,
// for one that the policy refuses; c gets the address checked, unmapped
// and without a name, and the zero netx.Addr stands for 0.0.0.0, which
// DefaultPolicy refuses. ReadFrom delivers datagrams from any source,
// as a full-cone NAT does.
//
// A host name is checked as ParseTarget and Dialer.DialContext check it, a
// legacy IPv4 form as an address, and resolved with d's Resolver by the
// wrapper itself, so that c gets IP addresses alone and never resolves:
// each datagram goes to the first address of the name, IPv4 first, that
// the policy allows for its port, without a zone, as netx.Addr has none.
// Lookups are cached for a minute, failures for five seconds, up to 1024
// names; WriteTo does not wait for a lookup, but holds a copy of the
// datagram and sends it once the name resolves, in order with the later
// datagrams to the name, or drops it. Up to 64 names are looked up at
// once, each holding up to 16 datagrams, and up to 256 KiB in all; WriteTo
// fails with ErrLookupBusy beyond these bounds, dropping the datagram as a
// full socket buffer would. Close cancels the lookups, whose goroutines
// end within ten seconds also with a resolver that does not see the
// cancellation at once, and closes c.
//
// Checking a datagram to an IP address does not allocate.
func (d *Dialer) WrapAddrPacketConn(c AddrPacketConn) AddrPacketConn {
	w := &addrPacketConn{c: c}
	w.g = newGuard(d, func(p []byte, ap netip.AddrPort) {
		_, _ = c.WriteTo(p, netx.Addr{IP: ap.Addr().WithZone(""), Port: ap.Port()})
	})
	return w
}

type addrPacketConn struct {
	c AddrPacketConn
	g *guard
}

func (w *addrPacketConn) WriteTo(p []byte, dst netx.Addr) (int, error) {
	if dst.IP.IsValid() || dst.Name == "" {
		ip := dst.IP
		if !ip.IsValid() {
			ip = netip.IPv4Unspecified()
		}
		ip = ip.Unmap().WithZone("") // as checked
		if err := w.g.d.Check(packetNetwork, netip.AddrPortFrom(ip, dst.Port)); err != nil {
			return 0, err
		}
		return w.c.WriteTo(p, netx.Addr{IP: ip, Port: dst.Port})
	}
	ap, held, err := w.g.route(p, dst.Name, dst.Port)
	switch {
	case err != nil:
		return 0, err
	case held:
		return len(p), nil
	}
	return w.c.WriteTo(p, netx.Addr{IP: ap.Addr().WithZone(""), Port: ap.Port()})
}

func (w *addrPacketConn) ReadFrom(p []byte) (int, netx.Addr, error) { return w.c.ReadFrom(p) }

func (w *addrPacketConn) Close() error {
	w.g.close()
	return w.c.Close()
}

// udpAddrPortWriter and udpAddrPortReader are the methods of *net.UDPConn
// that send and receive without allocating.
type (
	udpAddrPortWriter interface {
		WriteToUDPAddrPort(p []byte, ap netip.AddrPort) (int, error)
	}
	udpAddrPortReader interface {
		ReadFromUDPAddrPort(p []byte) (int, netip.AddrPort, error)
	}
)

// PacketConn is a net.PacketConn whose every destination is checked
// against a Dialer's policy, for a relay that sends datagrams to
// destinations that a less trusted party names; WrapPacketConn makes it.
// WriteTo and WriteToUDPAddrPort send a datagram to an address that the
// policy allows, and fail with a *DeniedError, dropping it, for one that
// the policy refuses, and for an address without an IP, such as a
// *net.UDPAddr whose IP is nil, which sockets send to on the local host.
// Reads deliver datagrams from any source, as a full-cone NAT does. Its
// other methods are those of the net.PacketConn it
// wraps.
type PacketConn struct {
	net.PacketConn
	g *guard
	w udpAddrPortWriter // the PacketConn's, or nil
}

// WrapPacketConn returns c with every destination checked against d's
// policy. A destination that is a netx.Addr with a host name, which WriteTo
// takes as a net.Addr, is resolved and held as WrapAddrPacketConn
// describes, and sent to as a *net.UDPAddr. Checking a datagram to an IP
// address does not allocate.
func (d *Dialer) WrapPacketConn(c net.PacketConn) *PacketConn {
	w := &PacketConn{PacketConn: c}
	w.w, _ = c.(udpAddrPortWriter)
	w.g = newGuard(d, func(p []byte, ap netip.AddrPort) { _, _ = w.writeAddrPort(p, ap, nil) })
	return w
}

// writeAddrPort sends p to ap, with addr, if not nil, the same address as
// a net.Addr for a PacketConn without WriteToUDPAddrPort.
func (c *PacketConn) writeAddrPort(p []byte, ap netip.AddrPort, addr net.Addr) (int, error) {
	if c.w != nil {
		return c.w.WriteToUDPAddrPort(p, ap)
	}
	if addr == nil {
		addr = net.UDPAddrFromAddrPort(ap)
	}
	return c.PacketConn.WriteTo(p, addr)
}

// WriteTo sends p to addr, a *net.UDPAddr, a netx.Addr or another address
// whose String is "host:port", if the policy allows it.
func (c *PacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if a, ok := addr.(*net.UDPAddr); ok && a != nil {
		ap := a.AddrPort()
		if err := c.g.d.Check(packetNetwork, ap); err != nil {
			return 0, err
		}
		return c.writeAddrPort(p, ap, a)
	}
	dst := netx.AddrFromNetAddr(addr)
	if dst.IsZero() {
		return 0, &net.OpError{Op: "write", Net: packetNetwork, Addr: addr, Err: netx.ErrInvalidAddr}
	}
	if dst.IP.IsValid() {
		return c.WriteToUDPAddrPort(p, netip.AddrPortFrom(dst.IP, dst.Port))
	}
	ap, held, err := c.g.route(p, dst.Name, dst.Port)
	switch {
	case err != nil:
		return 0, err
	case held:
		return len(p), nil
	}
	return c.writeAddrPort(p, ap, nil)
}

// WriteToUDPAddrPort sends p to ap if the policy allows it, without
// allocating with a *net.UDPConn.
func (c *PacketConn) WriteToUDPAddrPort(p []byte, ap netip.AddrPort) (int, error) {
	if err := c.g.d.Check(packetNetwork, ap); err != nil {
		return 0, err
	}
	return c.writeAddrPort(p, ap, nil)
}

// ReadFromUDPAddrPort reads a datagram and returns its source, from any
// address.
func (c *PacketConn) ReadFromUDPAddrPort(p []byte) (int, netip.AddrPort, error) {
	if r, ok := c.PacketConn.(udpAddrPortReader); ok {
		return r.ReadFromUDPAddrPort(p)
	}
	n, addr, err := c.ReadFrom(p)
	return n, netutil.PeerAddrPort(addr), err
}

// Close cancels the lookups of host names and closes the wrapped
// connection.
func (c *PacketConn) Close() error {
	c.g.close()
	return c.PacketConn.Close()
}
