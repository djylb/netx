package safedial

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/djylb/netx"
)

func TestParseLegacyIPv4(t *testing.T) {
	for host, want := range map[string]string{
		"127.1":               "127.0.0.1",
		"2130706433":          "127.0.0.1",
		"0x7f.0.0.1":          "127.0.0.1",
		"0x7F.1":              "127.0.0.1",
		"0177.0.0.1":          "127.0.0.1",
		"0x7F000001":          "127.0.0.1",
		"127.0.1":             "127.0.0.1",
		"10.1":                "10.0.0.1",
		"192.168.257":         "192.168.1.1",
		"0":                   "0.0.0.0",
		"0x":                  "0.0.0.0",
		"1.2.3.4":             "1.2.3.4",
		"4294967295":          "255.255.255.255",
		"1.16777215":          "1.255.255.255",
		"1.2.65535":           "1.2.255.255",
		"017700000001":        "127.0.0.1",
		"0xa9.0xfe.0xa9.0xfe": "169.254.169.254",
	} {
		if ip, ok := ParseLegacyIPv4(host); !ok || ip != netip.MustParseAddr(want) {
			t.Errorf("ParseLegacyIPv4(%q) = %v, %v; want %s", host, ip, ok, want)
		}
	}
	for _, host := range []string{
		"", "1.2.3.4.5", "08", "0x1g", "256.1.1.1", "1.2.3.256", "4294967296",
		"1.16777216", "1.2.65536", "a.1", "1..2", "1.", ".1", "example.com",
		"10.example", "1.2.3.4 ", "0x100000000", "-1",
	} {
		if ip, ok := ParseLegacyIPv4(host); ok {
			t.Errorf("ParseLegacyIPv4(%q) = %v", host, ip)
		}
	}
}

func TestParseTarget(t *testing.T) {
	tests := []struct {
		address, addr, name, zone string
		port                      uint16
	}{
		{address: "1.2.3.4:80", addr: "1.2.3.4", port: 80},
		{address: "[::ffff:127.0.0.1]:80", addr: "127.0.0.1", port: 80},
		{address: "[fe80::1%eth0]:443", addr: "fe80::1", zone: "eth0", port: 443},
		{address: "[2001:db8::1]:0", addr: "2001:db8::1"},
		{address: "127.0.0.1.:80", addr: "127.0.0.1", port: 80},
		{address: "127.1:80", addr: "127.0.0.1", port: 80},
		{address: "127.1.:80", addr: "127.0.0.1", port: 80},
		{address: "2130706433:80", addr: "127.0.0.1", port: 80},
		{address: "0x7f.0.0.1:80", addr: "127.0.0.1", port: 80},
		{address: "0X7F.1:80", addr: "127.0.0.1", port: 80},
		{address: "Example.COM:443", name: "example.com", port: 443},
		{address: "example.com.:443", name: "example.com.", port: 443},
		{address: "1e100.net:80", name: "1e100.net", port: 80},
		{address: "_srv.a-b.example:1", name: "_srv.a-b.example", port: 1},
		{address: "localhost:65535", name: "localhost", port: 65535},
		{address: "0xdead.beef:80", name: "0xdead.beef", port: 80},
	}
	for _, tt := range tests {
		got, err := ParseTarget("tcp", tt.address)
		if err != nil {
			t.Errorf("ParseTarget(%q): %v", tt.address, err)
			continue
		}
		var want Target
		if tt.addr != "" {
			want.Addr = netip.MustParseAddr(tt.addr)
		}
		want.Network, want.Name, want.Zone, want.Port = "tcp", tt.name, tt.zone, tt.port
		if got != want {
			t.Errorf("ParseTarget(%q) = %+v; want %+v", tt.address, got, want)
		}
	}
	for _, address := range []string{
		":80", "example.com", "example.com:x", "example.com:65536", "a..b:80",
		"a b:80", "127.0.0.1 x:80", "1.2.3.256:80", "08:80", "example.1:80",
		"1.2.3.4.5:80", "ex%41.com:80", "münchen.example:80", "ẞ.example:80", "İ:80",
		"1.2.3.4%eth0:80", "[]:80", strings.Repeat("a", 64) + ".example:80",
		strings.Repeat("a.", 127) + "ab:80", ".example:80",
	} {
		if got, err := ParseTarget("tcp", address); !errors.Is(err, netx.ErrInvalidAddr) {
			t.Errorf("ParseTarget(%q) = %+v, %v; want ErrInvalidAddr", address, got, err)
		}
	}
	var unknown net.UnknownNetworkError
	if _, err := ParseTarget("ip", "1.2.3.4:80"); !errors.As(err, &unknown) {
		t.Errorf("ParseTarget(ip): %v", err)
	}
}

func TestTargetString(t *testing.T) {
	for _, tt := range []struct {
		target Target
		want   string
	}{
		{Target{Name: "example.com", Port: 80}, "example.com:80"},
		{Target{Addr: netip.MustParseAddr("1.2.3.4"), Port: 80}, "1.2.3.4:80"},
		{Target{Addr: netip.MustParseAddr("fe80::1"), Zone: "eth0", Port: 80}, "[fe80::1%eth0]:80"},
		{Target{Addr: netip.MustParseAddr("::1"), Name: "localhost", Port: 80}, "localhost:80 (::1)"},
	} {
		if got := tt.target.String(); got != tt.want {
			t.Errorf("%+v.String() = %q; want %q", tt.target, got, tt.want)
		}
	}
}
