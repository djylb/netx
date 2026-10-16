package socks5

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/djylb/netx"
)

// ContextDialer dials connections. *net.Dialer implements it.
type ContextDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Dialer dials TCP connections through a SOCKS5, SOCKS4 or SOCKS4a proxy
// with the CONNECT command. Host names are sent to the proxy, which resolves
// them, unless Resolver is set.
//
// For SOCKS over TLS, set Forward to a dialer that returns TLS connections,
// such as a *tls.Dialer or a tlsconn.Dialer.
type Dialer struct {
	// ProxyAddr is the proxy's host:port.
	ProxyAddr string
	// SOCKS4 speaks SOCKS4, or SOCKS4a for host names, instead of SOCKS5.
	// IPv6 targets cannot be reached with it.
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
	Forward ContextDialer
}

// Dial is DialContext with a background context, for code that expects a
// dialer without a context.
func (d *Dialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

// DialContext connects to address through the proxy. ctx bounds the whole
// dial, including name resolution, and the returned connection has no
// deadline set. A non-success reply is returned as a *ReplyError, and networks
// other than tcp, tcp4 and tcp6 as an error matching errors.ErrUnsupported.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("socks5: network %q: %w", network, errors.ErrUnsupported)
	}
	dst, err := ParseAddr(address)
	if err != nil {
		return nil, fmt.Errorf("socks5: invalid target %q: %w", address, err)
	}
	if dst, err = d.resolve(ctx, network, dst); err != nil {
		return nil, err
	}
	if d.SOCKS4 && dst.IP.Unmap().Is6() {
		return nil, fmt.Errorf("%w: SOCKS4 cannot carry IPv6 address %v", ErrAddrType, dst.IP)
	}
	var forward ContextDialer = &net.Dialer{}
	if d.Forward != nil {
		forward = d.Forward
	}
	c, err := forward.DialContext(ctx, "tcp", d.ProxyAddr)
	if err != nil {
		return nil, err
	}
	if err := handshake(ctx, c, func() error { return d.connect(c, dst) }); err != nil {
		return nil, err
	}
	return c, nil
}

// resolve looks dst's name up with d.Resolver, if set, in the address family
// of network.
func (d *Dialer) resolve(ctx context.Context, network string, dst Addr) (Addr, error) {
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
	ips, err := d.Resolver.LookupNetIP(ctx, family, dst.Name)
	if err != nil {
		return Addr{}, err
	}
	if len(ips) == 0 {
		return Addr{}, &net.DNSError{Err: "no suitable address", Name: dst.Name, IsNotFound: true}
	}
	return Addr{IP: ips[0].Unmap(), Port: dst.Port}, nil
}

func (d *Dialer) connect(c net.Conn, dst Addr) error {
	if d.SOCKS4 {
		if err := WriteRequest4(c, CmdConnect, dst, d.Username); err != nil {
			return err
		}
		_, err := ReadReply4(c)
		return err
	}
	methods := []Method{MethodNoAuth}
	if d.Username != "" {
		methods = append(methods, MethodUserPass)
	}
	if err := WriteMethods(c, methods...); err != nil {
		return err
	}
	method, err := ReadMethod(c)
	if err != nil {
		return err
	}
	switch {
	case method == MethodNoAuth:
	case method == MethodUserPass && d.Username != "":
		if err := WriteUserPass(c, d.Username, d.Password); err != nil {
			return err
		}
		if err := ReadUserPassStatus(c); err != nil {
			return err
		}
	default:
		return fmt.Errorf("socks5: server selected unoffered %v", method)
	}
	if err := WriteRequest(c, CmdConnect, dst); err != nil {
		return err
	}
	_, err = ReadReply(c)
	return err
}

// handshake runs fn on c with ctx's deadline as the connection deadline and
// interrupts its I/O when ctx is canceled. On success it clears the deadline;
// on failure it closes c and reports ctx's error when ctx ended the handshake.
func handshake(ctx context.Context, c net.Conn, fn func() error) error {
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() {
		// A connection without deadline support is closed instead.
		if c.SetDeadline(time.Unix(1, 0)) != nil {
			_ = c.Close()
		}
	})
	err := fn()
	if !stop() && err == nil {
		// ctx ended after fn returned and has already poisoned the deadline.
		err = ctx.Err()
	}
	if err == nil {
		// Connections without deadline support, such as SSH channels, fail
		// here although they have no deadline to clear.
		_ = c.SetDeadline(time.Time{})
		return nil
	}
	if ctx.Err() != nil || netx.IsTimeout(err) {
		closeBeneathTLS(c)
	}
	_ = c.Close()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	// The connection deadline equals ctx's, so it can expire just before ctx
	// reports it.
	if _, ok := ctx.Deadline(); ok && errors.Is(err, os.ErrDeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return err
}
