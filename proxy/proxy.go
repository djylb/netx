// Package proxy dials TCP connections through HTTP CONNECT, SOCKS5 and SOCKS4
// proxies, in the clear or over TLS.
//
// FromURL builds a dialer for one proxy URL, and FromEnvironment builds one
// from ALL_PROXY and NO_PROXY:
//
//	forward := &net.Dialer{Timeout: 10 * time.Second}
//	d, err := proxy.FromURL(u, forward)
//	if err != nil {
//		return err
//	}
//	conn, err := d.DialContext(ctx, "tcp", "example.com:443")
//
// The context bounds the whole dial, including the proxy handshake. The
// returned connection has no deadline set.
package proxy

import (
	"cmp"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/textproto"
	"net/url"
	"os"
	"strings"

	"github.com/djylb/netx/socks5"
	"github.com/djylb/netx/tlsconn"
)

// ContextDialer dials connections. *net.Dialer implements it.
type ContextDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// FromURL returns a dialer that connects through the proxy at u:
//
//   - http (default port 80) and https (default port 443, with TLS to the
//     proxy) give an *HTTPDialer, which sends user information as Basic
//     Proxy-Authorization.
//   - socks5 and socks5h give a *socks5.Dialer that lets the proxy resolve
//     host names, socks4a one that speaks SOCKS4a, and socks4 one that
//     resolves names locally, since SOCKS4 cannot carry them. The default
//     port is 1080, and user information becomes the SOCKS5 username and
//     password or the SOCKS4 user ID.
//   - socks5+tls, socks5h+tls, socks4+tls and socks4a+tls reach the SOCKS
//     proxy over TLS, verified against the proxy's host name, through a
//     tlsconn.Dialer as the socks5.Dialer's Forward.
//
// Schemes are case-insensitive. forward dials the proxy; nil means a zero
// net.Dialer.
func FromURL(u *url.URL, forward ContextDialer) (ContextDialer, error) {
	if u == nil {
		return nil, errors.New("proxy: nil URL")
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("proxy: missing host in %s", u.Redacted())
	}
	port := u.Port()
	scheme := strings.ToLower(u.Scheme)
	base, overTLS := strings.CutSuffix(scheme, "+tls")
	switch base {
	case "http", "https":
		if overTLS {
			break
		}
		d := &HTTPDialer{Forward: forward}
		if base == "https" {
			d.TLSConfig = &tls.Config{ServerName: host}
			port = cmp.Or(port, "443")
		}
		d.ProxyAddr = net.JoinHostPort(host, cmp.Or(port, "80"))
		if u.User != nil {
			password, _ := u.User.Password()
			credentials := base64.StdEncoding.EncodeToString([]byte(u.User.Username() + ":" + password))
			d.Header = textproto.MIMEHeader{"Proxy-Authorization": {"Basic " + credentials}}
		}
		return d, nil
	case "socks5", "socks5h", "socks4", "socks4a":
		d := &socks5.Dialer{
			ProxyAddr: net.JoinHostPort(host, cmp.Or(port, "1080")),
			SOCKS4:    base == "socks4" || base == "socks4a",
			Forward:   forward,
		}
		if base == "socks4" {
			d.Resolver = net.DefaultResolver
		}
		if overTLS {
			d.Forward = &tlsconn.Dialer{Config: &tls.Config{ServerName: host}, Forward: forward}
		}
		if u.User != nil {
			d.Username = u.User.Username()
			d.Password, _ = u.User.Password()
		}
		return d, nil
	}
	return nil, fmt.Errorf("proxy: unsupported scheme %q", u.Scheme)
}

// FromEnvironment returns a dialer for the proxy URL in ALL_PROXY (or
// all_proxy) that dials directly through forward, or a zero net.Dialer if
// forward is nil, for the targets matched by NO_PROXY (or no_proxy). It
// returns the direct dialer when ALL_PROXY is unset.
//
// NO_PROXY uses the syntax of ParseNoProxy.
func FromEnvironment(forward ContextDialer) (ContextDialer, error) {
	if forward == nil {
		forward = &net.Dialer{}
	}
	raw := getenv("ALL_PROXY", "all_proxy")
	if raw == "" {
		return forward, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("proxy: parse ALL_PROXY: %w", err)
	}
	proxied, err := FromURL(u, forward)
	if err != nil {
		return nil, err
	}
	bypass := ParseNoProxy(getenv("NO_PROXY", "no_proxy"))
	if bypass.empty() {
		return proxied, nil
	}
	return &bypassDialer{proxied: proxied, direct: forward, bypass: bypass}, nil
}

func getenv(names ...string) string {
	for _, name := range names {
		if v := os.Getenv(name); v != "" {
			return v
		}
	}
	return ""
}

type bypassDialer struct {
	proxied ContextDialer
	direct  ContextDialer
	bypass  NoProxy
}

func (d *bypassDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if d.bypass.Match(address) {
		return d.direct.DialContext(ctx, network, address)
	}
	return d.proxied.DialContext(ctx, network, address)
}

func checkNetwork(network string) error {
	switch network {
	case "tcp", "tcp4", "tcp6":
		return nil
	default:
		return fmt.Errorf("proxy: network %q: %w", network, errors.ErrUnsupported)
	}
}

// forwardOf returns forward, or a zero net.Dialer if it is nil.
func forwardOf(forward ContextDialer) ContextDialer {
	if forward == nil {
		return &net.Dialer{}
	}
	return forward
}
