package socks5

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/djylb/netx"
	"github.com/djylb/netx/internal/netutil"
)

// Dialer dials TCP connections through a SOCKS5, SOCKS4 or SOCKS4a proxy
// with the CONNECT command, and opens UDP associations through a SOCKS5
// proxy with ListenPacket. Host names are sent to the proxy, which resolves
// them, unless Resolver is set.
//
// For SOCKS over TLS, set Forward to a dialer that returns TLS connections,
// such as a *tls.Dialer or a tlsconn.Dialer.
type Dialer struct {
	// ProxyAddr is the proxy's host:port.
	ProxyAddr string
	// SOCKS4 speaks SOCKS4, or SOCKS4a for host names, instead of SOCKS5.
	// IPv6 targets and UDP cannot be reached with it.
	SOCKS4 bool
	// Username and Password are offered with SOCKS5 username/password
	// authentication (RFC 1929) when Username is not empty; no
	// authentication is offered as well. SOCKS4 sends Username as the user
	// ID and ignores Password.
	Username string
	Password string
	// Resolver, if set, resolves host names on the client so that the proxy
	// receives addresses, as SOCKS4 servers without the 4a extension need.
	// SOCKS4 uses the first IPv4 address, SOCKS5 the first address.
	Resolver *net.Resolver
	// Forward dials the proxy; nil means a zero net.Dialer.
	Forward netx.ContextDialer
}

// Dial is DialContext with a background context, for code that expects a
// dialer without a context.
func (d *Dialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

// DialContext connects to address through the proxy: it dials the proxy with
// Forward and runs Handshake for CmdConnect. ctx bounds the whole dial,
// including name resolution, and the returned connection has no deadline
// set. A non-success reply is returned as a *ReplyError, and networks other
// than tcp, tcp4 and tcp6 as an error matching errors.ErrUnsupported.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("socks5: network %q: %w", network, errors.ErrUnsupported)
	}
	dst, err := netx.ParseAddr(address)
	if err != nil {
		return nil, fmt.Errorf("socks5: invalid target %q: %w", address, err)
	}
	if dst, err = d.resolve(ctx, network, dst); err != nil {
		return nil, err
	}
	if d.SOCKS4 && dst.IP.Unmap().Is6() {
		return nil, fmt.Errorf("%w: SOCKS4 cannot carry IPv6 address %v", ErrAddrType, dst.IP)
	}
	c, err := d.dialProxy(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := d.Handshake(ctx, c, CmdConnect, dst); err != nil {
		return nil, err
	}
	return c, nil
}

// Handshake runs the client side of a request for cmd to dst on c, a
// connection to the proxy, and returns the bound address of the server's
// reply: for CmdConnect the address the proxy connects from, for
// CmdUDPAssociate the address to send datagrams to, which servers often
// leave unspecified. dst is sent as it is, without Resolver. SOCKS4 has no
// UDP ASSOCIATE and returns an error matching errors.ErrUnsupported for it.
//
// ctx bounds the handshake as with netx.DoHandshake, and c has no deadline
// set after a success. A non-success reply is returned as a *ReplyError. On
// failure c is closed, as by netx.DoHandshake.
func (d *Dialer) Handshake(ctx context.Context, c net.Conn, cmd Command, dst netx.Addr) (netx.Addr, error) {
	if d.SOCKS4 && cmd == CmdUDPAssociate {
		_ = c.Close()
		return netx.Addr{}, fmt.Errorf("socks5: SOCKS4 %v: %w", cmd, errors.ErrUnsupported)
	}
	var bound netx.Addr
	err := netx.DoHandshake(ctx, c, func() (err error) {
		bound, err = d.request(c, cmd, dst)
		return err
	})
	if err != nil {
		return netx.Addr{}, err
	}
	return bound, nil
}

func (d *Dialer) dialProxy(ctx context.Context) (net.Conn, error) {
	var forward netx.ContextDialer = &net.Dialer{}
	if d.Forward != nil {
		forward = d.Forward
	}
	return forward.DialContext(ctx, "tcp", d.ProxyAddr)
}

// resolve looks dst's name up with d.Resolver, if set, in the address family
// of network.
func (d *Dialer) resolve(ctx context.Context, network string, dst netx.Addr) (netx.Addr, error) {
	if d.Resolver == nil || dst.IP.IsValid() {
		return dst, nil
	}
	family := "ip"
	switch {
	case d.SOCKS4, network == "tcp4":
		family = "ip4"
	case network == "tcp6":
		family = "ip6"
	}
	ip, err := lookupFirst(ctx, d.Resolver, family, dst.Name)
	if err != nil {
		return netx.Addr{}, err
	}
	return netx.Addr{IP: ip, Port: dst.Port}, nil
}

// lookupFirst returns the first address of name in family.
func lookupFirst(ctx context.Context, r *net.Resolver, family, name string) (netip.Addr, error) {
	ips, err := r.LookupNetIP(ctx, family, name)
	if err != nil {
		return netip.Addr{}, err
	}
	if len(ips) == 0 {
		return netip.Addr{}, &net.DNSError{Err: "no suitable address", Name: name, IsNotFound: true}
	}
	return ips[0].Unmap(), nil
}

// request writes the request and reads the reply in d's protocol version.
func (d *Dialer) request(c net.Conn, cmd Command, dst netx.Addr) (netx.Addr, error) {
	if d.SOCKS4 {
		if err := WriteRequest4(c, cmd, dst, d.Username); err != nil {
			return netx.Addr{}, err
		}
		return ReadReply4(c)
	}
	methods := []Method{MethodNoAuth}
	if d.Username != "" {
		methods = append(methods, MethodUserPass)
	}
	if err := WriteMethods(c, methods...); err != nil {
		return netx.Addr{}, err
	}
	method, err := ReadMethod(c)
	if err != nil {
		return netx.Addr{}, err
	}
	switch {
	case method == MethodNoAuth:
	case method == MethodUserPass && d.Username != "":
		if err := WriteUserPass(c, d.Username, d.Password); err != nil {
			return netx.Addr{}, err
		}
		if err := ReadUserPassStatus(c); err != nil {
			return netx.Addr{}, err
		}
	default:
		return netx.Addr{}, fmt.Errorf("socks5: server selected unoffered %v", method)
	}
	if err := WriteRequest(c, cmd, dst); err != nil {
		return netx.Addr{}, err
	}
	return ReadReply(c)
}

// ListenPacket opens a UDP association through the SOCKS5 proxy: it dials
// the proxy with Forward, opens a local UDP socket with
// netx.ListenEphemeralUDP and runs Handshake for CmdUDPAssociate, announcing
// the socket's port. ctx bounds the setup only. The association lasts until
// the UDPConn is closed, which closes the control connection, or until the
// proxy ends the control connection, which closes the UDPConn.
//
// The datagrams go from the local socket straight to the proxy's relay, and
// proxies accept them only from the IP address of the control connection, so
// Forward must reach the proxy from that address. SOCKS4 has no UDP and
// returns an error matching errors.ErrUnsupported.
//
// A *UDPConn is a PacketConn, so a Server can relay its own clients' UDP
// associations through the proxy with it as DialPacket.
func (d *Dialer) ListenPacket(ctx context.Context) (*UDPConn, error) {
	if d.SOCKS4 {
		return nil, fmt.Errorf("socks5: SOCKS4 %v: %w", CmdUDPAssociate, errors.ErrUnsupported)
	}
	ctrl, err := d.dialProxy(ctx)
	if err != nil {
		return nil, err
	}
	pc, err := netx.ListenEphemeralUDP(ctx, nil)
	if err != nil {
		_ = ctrl.Close()
		return nil, err
	}
	// The address is left unspecified: the proxy takes it from the control
	// connection, as a NAT may rewrite it.
	announced := netx.Addr{Port: uint16(pc.LocalAddr().(*net.UDPAddr).Port)}
	bound, err := d.Handshake(ctx, ctrl, CmdUDPAssociate, announced)
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	relay, err := d.relayAddr(ctx, ctrl, bound)
	if err != nil {
		_ = ctrl.Close()
		_ = pc.Close()
		return nil, err
	}
	u := &UDPConn{ctrl: ctrl, pc: pc, relay: relay}
	go u.watch()
	return u, nil
}

// relayAddr returns the address to send datagrams to from the bound address
// of a UDP ASSOCIATE reply: a name resolved, and an unspecified address,
// which servers often reply, replaced with the proxy's.
func (d *Dialer) relayAddr(ctx context.Context, ctrl net.Conn, bound netx.Addr) (netip.AddrPort, error) {
	if bound.Port == 0 {
		return netip.AddrPort{}, fmt.Errorf("%w: UDP relay port 0", ErrInvalidAddr)
	}
	resolver := d.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	ip := bound.IP.Unmap().WithZone("")
	if !ip.IsValid() && bound.Name != "" {
		var err error
		if ip, err = lookupFirst(ctx, resolver, "ip", bound.Name); err != nil {
			return netip.AddrPort{}, err
		}
	}
	remote := netutil.PeerAddrPort(ctrl.RemoteAddr()).Addr()
	switch {
	case !ip.IsValid() || ip.IsUnspecified():
		// Servers often reply 0.0.0.0: the relay is where the client
		// reached the proxy.
		ip = remote
	case !remote.IsValid() || remote == ip || remote.IsLoopback():
	case localIP(ip):
		// A proxy behind a NAT or a port mapping, such as in a container,
		// replies its own loopback, private or link-local address; the
		// address it was reached at demonstrably leads to it.
		ip = remote
	}
	if !ip.IsValid() {
		// A control connection without an IP address, such as a tunneled
		// stream, leaves the proxy's own address.
		proxy, err := netx.ParseAddr(d.ProxyAddr)
		if err != nil {
			return netip.AddrPort{}, err
		}
		if ip = proxy.IP; !ip.IsValid() {
			if ip, err = lookupFirst(ctx, resolver, "ip", proxy.Name); err != nil {
				return netip.AddrPort{}, err
			}
		}
	}
	return netip.AddrPortFrom(ip, bound.Port), nil
}

// localIP reports whether ip is reachable only within a host or a private
// network.
func localIP(ip netip.Addr) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()
}

// UDPConn is a UDP association opened by Dialer.ListenPacket. WriteTo sends
// datagrams through the proxy's relay and ReadFrom receives the replies,
// taking only datagrams from the relay. It is safe for concurrent use.
type UDPConn struct {
	ctrl  net.Conn
	pc    *net.UDPConn
	relay netip.AddrPort
	once  sync.Once
}

// WriteTo sends p to dst through the proxy, which resolves a domain name. It
// returns len(p) on success.
func (u *UDPConn) WriteTo(p []byte, dst netx.Addr) (int, error) {
	bp := udpBufPool.Get().(*[]byte)
	defer udpBufPool.Put(bp)
	b, err := AppendDatagram((*bp)[:0], dst, p)
	if err != nil {
		return 0, err
	}
	if _, err := u.pc.WriteToUDPAddrPort(b, u.relay); err != nil {
		return 0, err
	}
	return len(p), nil
}

// ReadFrom reads the next reply into p and returns its source. A reply
// longer than p is truncated. Datagrams from other senders than the relay,
// and malformed or fragmented ones, are dropped. After the association ends
// it returns an error matching net.ErrClosed.
func (u *UDPConn) ReadFrom(p []byte) (int, netx.Addr, error) {
	bp := udpBufPool.Get().(*[]byte)
	defer udpBufPool.Put(bp)
	buf := *bp
	for {
		n, src, err := u.pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			return 0, netx.Addr{}, err
		}
		if netutil.UnmapAddrPort(src) != u.relay {
			continue
		}
		addr, h, err := DecodeDatagram(buf[:n])
		if err != nil {
			continue
		}
		return copy(p, buf[h:n]), addr, nil
	}
}

// Close ends the association: it closes the control connection and the
// local socket, which unblocks ReadFrom. Calls after the first return nil.
func (u *UDPConn) Close() error {
	var err error
	u.once.Do(func() {
		err = errors.Join(u.ctrl.Close(), u.pc.Close())
	})
	return err
}

// watch ends the association when the proxy ends the control connection,
// which carries nothing after the reply.
func (u *UDPConn) watch() {
	_, _ = io.Copy(io.Discard, u.ctrl)
	_ = u.Close()
}

// LocalAddr returns the address of the local UDP socket.
func (u *UDPConn) LocalAddr() net.Addr { return u.pc.LocalAddr() }

// RelayAddr returns the proxy's relay address that datagrams are sent to.
func (u *UDPConn) RelayAddr() netip.AddrPort { return u.relay }

// SetDeadline sets the read and write deadlines of the local socket.
func (u *UDPConn) SetDeadline(t time.Time) error { return u.pc.SetDeadline(t) }

// SetReadDeadline sets the deadline for ReadFrom.
func (u *UDPConn) SetReadDeadline(t time.Time) error { return u.pc.SetReadDeadline(t) }

// SetWriteDeadline sets the deadline for WriteTo.
func (u *UDPConn) SetWriteDeadline(t time.Time) error { return u.pc.SetWriteDeadline(t) }

// AsNetPacketConn returns u as a net.PacketConn, for code that sends and
// receives with net.Addr. Its ReadFrom reports a source with an IP address as
// a *net.UDPAddr and one with a domain name as a netx.Addr. Its WriteTo
// takes a netx.Addr, which keeps a domain name for the proxy to resolve, or
// any net.Addr whose String is "host:port", such as a *net.UDPAddr. Closing
// it closes u.
func (u *UDPConn) AsNetPacketConn() net.PacketConn { return netPacketConn{u} }

type netPacketConn struct{ *UDPConn }

func (c netPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, src, err := c.UDPConn.ReadFrom(p)
	if err != nil {
		return n, nil, err
	}
	if src.IP.IsValid() {
		return n, net.UDPAddrFromAddrPort(netip.AddrPortFrom(src.IP, src.Port)), nil
	}
	return n, src, nil
}

func (c netPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	dst, ok := addr.(netx.Addr)
	if !ok {
		if dst = netx.AddrFromNetAddr(addr); !dst.IP.IsValid() && dst.Name == "" {
			return 0, ErrInvalidAddr
		}
	}
	return c.UDPConn.WriteTo(p, dst)
}
