package proxy

import (
	"context"
	"fmt"
	"net"
	"net/url"

	"github.com/djylb/netx/socks5"
)

type socks5Dialer struct {
	proxyAddr string
	user      *url.Userinfo
	forward   ContextDialer
}

func newSOCKS5Dialer(u *url.URL, forward ContextDialer) *socks5Dialer {
	return &socks5Dialer{
		proxyAddr: proxyAddress(u, "1080"),
		user:      u.User,
		forward:   forward,
	}
}

func (d *socks5Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if err := checkNetwork(network); err != nil {
		return nil, err
	}
	dst, err := socks5.ParseAddr(address)
	if err != nil {
		return nil, fmt.Errorf("proxy: invalid target %q: %w", address, err)
	}
	c, err := d.forward.DialContext(ctx, "tcp", d.proxyAddr)
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

func (d *socks5Dialer) authenticate(c net.Conn) error {
	methods := []socks5.Method{socks5.MethodNoAuth}
	if d.user != nil {
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
	case method == socks5.MethodUserPass && d.user != nil:
		password, _ := d.user.Password()
		if err := socks5.WriteUserPass(c, d.user.Username(), password); err != nil {
			return err
		}
		return socks5.ReadUserPassStatus(c)
	default:
		return fmt.Errorf("proxy: socks5 server selected unoffered %v", method)
	}
}
