//go:build freebsd || darwin

package transparent

import (
	"net/netip"
	"testing"
)

func TestIsLocalAddr(t *testing.T) {
	for _, tt := range []struct {
		addr  string
		local bool
	}{
		{"127.0.0.1", true},
		{"::ffff:127.0.0.1", true},
		{"192.0.2.1", false},
		{"2001:db8::1", false},
	} {
		got, err := isLocalAddr(nil, netip.MustParseAddr(tt.addr))
		if err != nil || got != tt.local {
			t.Errorf("isLocalAddr(%s) = %v, %v; want %v", tt.addr, got, err, tt.local)
		}
	}
}
