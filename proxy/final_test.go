package proxy

import (
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
		_, err := FromEnvironment(nil)
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
