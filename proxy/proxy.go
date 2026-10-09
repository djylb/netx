// Package proxy dials TCP connections through HTTP CONNECT and SOCKS5
// proxies.
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
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
)

// ContextDialer dials connections. *net.Dialer implements it.
type ContextDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

var errNetwork = errors.New("proxy: only tcp, tcp4 and tcp6 are supported")

// FromURL returns a dialer that connects through the proxy at u, using
// forward to reach the proxy, or a zero net.Dialer if forward is nil.
//
// Supported schemes are http (default port 80), https (default port 443,
// with TLS to the proxy) and socks5 or socks5h (default port 1080). User
// information in u is sent as Basic Proxy-Authorization for HTTP and as
// RFC 1929 credentials for SOCKS5. Both SOCKS5 schemes send host names to the
// proxy, which resolves them.
func FromURL(u *url.URL, forward ContextDialer) (ContextDialer, error) {
	if u == nil {
		return nil, errors.New("proxy: nil URL")
	}
	if forward == nil {
		forward = &net.Dialer{}
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("proxy: missing host in %s", u.Redacted())
	}
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "http", "https":
		return newHTTPDialer(u, scheme == "https", forward), nil
	case "socks5", "socks5h":
		return newSOCKS5Dialer(u, forward), nil
	default:
		return nil, fmt.Errorf("proxy: unsupported scheme %q", u.Scheme)
	}
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
		return errNetwork
	}
}

// proxyAddress returns the host:port of the proxy in u.
func proxyAddress(u *url.URL, defaultPort string) string {
	port := u.Port()
	if port == "" {
		port = defaultPort
	}
	return net.JoinHostPort(u.Hostname(), port)
}
