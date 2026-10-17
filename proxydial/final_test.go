package proxydial

import (
	"context"
	"crypto/tls"
	"net"
	"net/textproto"
	"strings"
	"testing"
)

// A malformed ALL_PROXY does not put its password into the error.
func TestFromEnvironmentErrorHidesPassword(t *testing.T) {
	for raw, secret := range map[string]string{
		"socks5://alice:topsecret@proxy:bad": "topsecret",
		"socks5://u:pa/ss@h:1":               "pa",
		"socks5://u:p%zzw@h:1":               "%zz",
	} {
		t.Setenv("all_proxy", "")
		t.Setenv("ALL_PROXY", raw)
		_, err := FromEnvironment(nil, nil)
		if err == nil {
			t.Fatalf("FromEnvironment(%q) succeeded", raw)
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error %q contains part of the password", err)
		}
	}
}

// The CONNECT request has exactly one Host line, whatever the case of the
// key the caller used, and one even when the caller's Host has no value.
func TestHTTPDialerRequestHost(t *testing.T) {
	for _, tt := range []struct {
		name   string
		header textproto.MIMEHeader
		want   string
	}{
		{"none", nil, "Host: example.com:443"},
		{"empty", textproto.MIMEHeader{"Host": {}}, "Host: example.com:443"},
		{"lower case", textproto.MIMEHeader{"host": {"front.example"}}, "host: front.example"},
	} {
		req, err := (&HTTPDialer{Header: tt.header}).request("example.com:443")
		if err != nil {
			t.Fatal(err)
		}
		if n := strings.Count(strings.ToLower(string(req)), "\r\nhost:"); n != 1 || !strings.Contains(string(req), tt.want) {
			t.Fatalf("%s: request %q has %d Host lines, want one %q", tt.name, req, n, tt.want)
		}
	}
}

// An https proxy reached without a port, such as over a Unix socket that a
// custom Forward dials, is verified against the whole address, as
// tlsconn.Dialer does.
func TestHTTPDialerServerNameWithoutPort(t *testing.T) {
	d := &HTTPDialer{ProxyAddr: "proxy.internal", TLSConfig: &tls.Config{}}
	if got := d.tlsConfig().ServerName; got != "proxy.internal" {
		t.Fatalf("ServerName = %q, want the whole proxy address", got)
	}
}

// The status text of a refused CONNECT is chosen by the proxy, so it must
// not put control characters into the error, and from there into logs.
func TestHTTPConnectErrorQuotesStatus(t *testing.T) {
	addr := serveOnce(t, func(c net.Conn) {
		_, _ = c.Read(make([]byte, 1024))
		_, _ = c.Write([]byte("HTTP/1.1 403 \x1b]0;pwned\x07\x1b[2J\r\n\r\n"))
	})
	_, err := (&HTTPDialer{ProxyAddr: addr}).DialContext(context.Background(), "tcp", "example.com:80")
	if err == nil {
		t.Fatal("DialContext() succeeded")
	}
	if strings.ContainsAny(err.Error(), "\x1b\x07") {
		t.Fatalf("error %q holds the proxy's control characters", err)
	}
}

// NO_PROXY prefixes written in IPv4-mapped form match the IPv4 targets they
// cover, as IPv4-mapped addresses do.
func TestNoProxyMappedPrefixes(t *testing.T) {
	for _, tt := range []struct {
		entry, target string
		want          bool
	}{
		{"::ffff:10.0.0.0/104", "10.1.2.3:80", true},
		{"::ffff:10.0.0.0/104", "[::ffff:10.1.2.3]:80", true},
		{"::ffff:10.0.0.0/104", "11.1.2.3:80", false},
		{"::/0", "192.0.2.1:80", true},
		{"::/0", "[2001:db8::1]:80", true},
		{"2001:db8::/32", "192.0.2.1:80", false},
		{"::ffff:0:0/96", "198.51.100.7:443", true},
	} {
		if got := ParseNoProxy(tt.entry).Match(tt.target); got != tt.want {
			t.Errorf("NO_PROXY %q matches %q = %v, want %v", tt.entry, tt.target, got, tt.want)
		}
	}
}
