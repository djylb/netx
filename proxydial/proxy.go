// Package proxydial dials TCP connections through HTTP CONNECT, SOCKS5 and SOCKS4
// proxies, in the clear or over TLS.
//
// FromURL builds a dialer for one proxy URL, FromString for one in text, and
// FromEnvironment builds one from ALL_PROXY and NO_PROXY:
//
//	forward := &net.Dialer{Timeout: 10 * time.Second}
//	d, err := proxydial.FromString("socks5h://proxy.example:1080", forward, nil)
//	if err != nil {
//		return err
//	}
//	conn, err := d.DialContext(ctx, "tcp", "example.com:443")
//
// The context bounds the whole dial, including the proxy handshake. The
// returned connection has no deadline set.
//
// The dialers are plain structs that can also be built directly. Both
// HTTPDialer and socks5.Dialer reach a proxy over TLS through a Forward that
// returns TLS connections, such as a tlsconn.Dialer, as FromURL sets up for
// https and the +tls schemes.
package proxydial

import (
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/djylb/netx"
	"github.com/djylb/netx/socks5"
	"github.com/djylb/netx/tlsconn"
)

// FromURL returns a dialer that connects through the proxy at u:
//
//   - http (default port 80) and https (default port 443, with TLS to the
//     proxy) give an *HTTPDialer, with user information as its Username and
//     Password.
//   - socks5 and socks5h give a *socks5.Dialer that lets the proxy resolve
//     host names, socks4a one that speaks SOCKS4a, and socks4 one that
//     resolves names locally, since SOCKS4 cannot carry them. The default
//     port is 1080, and user information becomes the SOCKS5 username and
//     password or the SOCKS4 user ID.
//   - socks5+tls, socks5h+tls, socks4+tls and socks4a+tls reach the SOCKS
//     proxy over TLS.
//
// Schemes are case-insensitive, and others give an error matching
// errors.ErrUnsupported. forward dials the proxy; nil means a zero
// net.Dialer. For https and the +tls schemes the dialer's Forward is a
// *tlsconn.Dialer over forward with tlsConfig, whose handshake the context
// bounds with the rest of the dial (HandshakeTimeout -1): a nil tlsConfig
// verifies the proxy's host name with the system roots, and one without
// ServerName is used with ServerName set to that host.
//
// The result is an *HTTPDialer or a *socks5.Dialer, as the scheme selects;
// type-assert it to adjust the dialer, such as to add CONNECT header fields.
func FromURL(u *url.URL, forward netx.ContextDialer, tlsConfig *tls.Config) (netx.ContextDialer, error) {
	if u == nil {
		return nil, errors.New("proxydial: nil URL")
	}
	if err := checkURL(u); err != nil {
		return nil, err
	}
	base, overTLS := strings.CutSuffix(strings.ToLower(u.Scheme), "+tls")
	defaultPort := "1080"
	switch base {
	case "http", "https":
		if overTLS {
			return nil, unsupportedScheme(u)
		}
		defaultPort = "80"
		if base == "https" {
			overTLS, defaultPort = true, "443"
		}
	case "socks5", "socks5h", "socks4", "socks4a":
	default:
		return nil, unsupportedScheme(u)
	}
	if overTLS {
		// The context bounds the handshake, as it does the rest of the dial.
		forward = &tlsconn.Dialer{Config: tlsConfig, HandshakeTimeout: -1, Forward: forward}
	}
	addr := net.JoinHostPort(u.Hostname(), cmp.Or(u.Port(), defaultPort))
	var user, password string
	if u.User != nil {
		user = u.User.Username()
		password, _ = u.User.Password()
	}
	if base == "http" || base == "https" {
		return &HTTPDialer{ProxyAddr: addr, Username: user, Password: password, Forward: forward}, nil
	}
	d := &socks5.Dialer{
		ProxyAddr: addr,
		SOCKS4:    base == "socks4" || base == "socks4a",
		Username:  user,
		Password:  password,
		Forward:   forward,
	}
	if base == "socks4" {
		d.Resolver = net.DefaultResolver
	}
	return d, nil
}

func unsupportedScheme(u *url.URL) error {
	return fmt.Errorf("proxydial: scheme %q: %w", u.Scheme, errors.ErrUnsupported)
}

// FromString is FromURL for a proxy URL in text, parsed with ParseURL, such
// as "socks5h://user:pass@proxy.example:1080" or "proxy.example:3128".
func FromString(raw string, forward netx.ContextDialer, tlsConfig *tls.Config) (netx.ContextDialer, error) {
	u, err := ParseURL(raw)
	if err != nil {
		return nil, err
	}
	return FromURL(u, forward, tlsConfig)
}

// ParseURL parses a proxy URL leniently: a value without a scheme, such as
// "proxy.example:3128" or "127.0.0.1:1080", is taken as an http proxy URL, as
// curl does. Its errors do not quote the user information, which may hold a
// password.
func ParseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	switch {
	case err == nil && u.Scheme == "" && u.Host != "":
		u.Scheme = "http" // "//host:port"
	case (err != nil || u.Scheme == "" || u.Host == "") && !strings.Contains(raw, "://"):
		//goland:noinspection HttpUrlsUsage
		u, err = url.Parse("http://" + raw)
	}
	if err != nil {
		// The parse error quotes the URL, or parts of it.
		return nil, fmt.Errorf("proxydial: invalid proxy URL %q", redactUserinfo(raw))
	}
	if err := checkURL(u); err != nil {
		return nil, err
	}
	return u, nil
}

// checkURL rejects a proxy URL without a host or with more than a scheme,
// user information and host: a path other than "/", a query or a fragment.
// Such a URL often holds user information that was not parsed as such, as in
// "http:///user:pass@host" or "http://user:12#pass@host", so its errors name
// the scheme only.
func checkURL(u *url.URL) error {
	switch {
	case u.Hostname() == "":
		return fmt.Errorf("proxydial: %q proxy URL without host", u.Scheme)
	case u.Opaque != "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "":
		return fmt.Errorf("proxydial: %q proxy URL with a path, query or fragment", u.Scheme)
	}
	return nil
}

// redactUserinfo replaces everything between the scheme and the last "@" of
// raw, which may hold user information that url.Parse could not separate.
func redactUserinfo(raw string) string {
	at := strings.LastIndex(raw, "@")
	if at < 0 {
		return raw
	}
	start := 0
	if i := strings.Index(raw, "://"); i >= 0 && i < at {
		start = i + len("://")
	}
	return raw[:start] + "xxxxx" + raw[at:]
}

// FromEnvironment returns a dialer for the proxy URL in ALL_PROXY (or
// all_proxy), bypassed for the targets in NO_PROXY (or no_proxy); it does not
// read HTTP_PROXY or HTTPS_PROXY, since a TCP dialer does not know whether
// its target speaks HTTP or HTTPS. HTTP clients can use
// http.ProxyFromEnvironment for those instead.
//
// ALL_PROXY is parsed with ParseURL, and the proxy dialer is built by
// FromURL with forward and tlsConfig. forward, or a zero net.Dialer if it is
// nil, also dials the targets that bypass the proxy. NO_PROXY uses the syntax
// of ParseNoProxy.
//
// The result is forward when ALL_PROXY is unset, a *Bypass over FromURL's
// dialer when NO_PROXY is set, and FromURL's dialer otherwise.
func FromEnvironment(forward netx.ContextDialer, tlsConfig *tls.Config) (netx.ContextDialer, error) {
	if forward == nil {
		forward = &net.Dialer{}
	}
	raw := getenv("ALL_PROXY", "all_proxy")
	if raw == "" {
		return forward, nil
	}
	u, err := ParseURL(raw)
	if err != nil {
		return nil, err
	}
	proxied, err := FromURL(u, forward, tlsConfig)
	if err != nil {
		return nil, err
	}
	noProxy := ParseNoProxy(getenv("NO_PROXY", "no_proxy"))
	if noProxy.empty() {
		return proxied, nil
	}
	return &Bypass{Proxy: proxied, Direct: forward, NoProxy: noProxy}, nil
}

func getenv(names ...string) string {
	for _, name := range names {
		if v := os.Getenv(name); v != "" {
			return v
		}
	}
	return ""
}

// Bypass dials the targets that NoProxy matches with Direct and all others
// with Proxy, such as a dialer from FromURL.
type Bypass struct {
	// Proxy dials the targets that do not bypass the proxy.
	Proxy netx.ContextDialer
	// Direct dials the targets that NoProxy matches; nil means a zero
	// net.Dialer.
	Direct netx.ContextDialer
	// NoProxy selects the targets that bypass Proxy.
	NoProxy NoProxy
}

// errNoProxyDialer reports a Bypass without Proxy.
var errNoProxyDialer = errors.New("proxydial: Bypass without Proxy")

// Dial is DialContext with a background context, for code that expects a
// dialer without a context.
func (b *Bypass) Dial(network, address string) (net.Conn, error) {
	return b.DialContext(context.Background(), network, address)
}

// DialContext dials address with Direct if NoProxy matches it and with Proxy
// otherwise.
func (b *Bypass) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if b.NoProxy.Match(address) {
		return forwardOf(b.Direct).DialContext(ctx, network, address)
	}
	if b.Proxy == nil {
		return nil, errNoProxyDialer
	}
	return b.Proxy.DialContext(ctx, network, address)
}

func checkNetwork(network string) error {
	switch network {
	case "tcp", "tcp4", "tcp6":
		return nil
	default:
		return fmt.Errorf("proxydial: network %q: %w", network, errors.ErrUnsupported)
	}
}

// forwardOf returns forward, or a zero net.Dialer if it is nil.
func forwardOf(forward netx.ContextDialer) netx.ContextDialer {
	if forward == nil {
		return &net.Dialer{}
	}
	return forward
}
