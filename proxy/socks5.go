package proxy

import (
	"context"
	"fmt"
	"net"

	"github.com/djylb/netx/socks5"
)

// SOCKS5Dialer dials through a SOCKS5 proxy with the CONNECT command. Host
// names are sent to the proxy, which resolves them.
type SOCKS5Dialer struct {
	// ProxyAddr is the proxy's host:port.
	ProxyAddr string
	// Username and Password are offered with username/password
	// authentication (RFC 1929) when Username is not empty; no
	// authentication is offered as well.
	Username string
	Password string
	// Forward dials the proxy; nil means a zero net.Dialer.
	Forward ContextDialer
}

// Dial is DialContext with a background context, matching the Dialer
// interface of golang.org/x/net/proxy.
func (d *SOCKS5Dialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

// DialContext connects to address through the proxy. ctx bounds the whole
// dial, and the returned connection has no deadline set. A non-success reply
// is returned as a *socks5.ReplyError.
func (d *SOCKS5Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if err := checkNetwork(network); err != nil {
		return nil, err
	}
	dst, err := socks5.ParseAddr(address)
	if err != nil {
		return nil, fmt.Errorf("proxy: invalid target %q: %w", address, err)
	}
	c, err := forwardOf(d.Forward).DialContext(ctx, "tcp", d.ProxyAddr)
	if err != nil {
		return nil, err
	}
	return handshake(ctx, c, func() (net.Conn, error) {
		if err := d.authenticate(c); err != nil {
			return nil, err
		}
		if err := socks5.WriteRequest(c, socks5.CmdConnect, dst); err != nil {
			return nil, err
		}
		if _, err := socks5.ReadReply(c); err != nil {
			return nil, err
		}
		return c, nil
	})
}

func (d *SOCKS5Dialer) authenticate(c net.Conn) error {
	methods := []socks5.Method{socks5.MethodNoAuth}
	if d.Username != "" {
		methods = append(methods, socks5.MethodUserPass)
	}
	if err := socks5.WriteMethods(c, methods...); err != nil {
		return err
	}
	method, err := socks5.ReadMethod(c)
	if err != nil {
		return err
	}
	switch {
	case method == socks5.MethodNoAuth:
		return nil
	case method == socks5.MethodUserPass && d.Username != "":
		if err := socks5.WriteUserPass(c, d.Username, d.Password); err != nil {
			return err
		}
		return socks5.ReadUserPassStatus(c)
	default:
		return fmt.Errorf("proxy: socks5 server selected unoffered %v", method)
	}
}
