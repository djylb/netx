//go:build darwin || freebsd

package transparent

import (
	"net"
	"syscall"
	"testing"
)

func TestNatlookAddr(t *testing.T) {
	var addr [16]byte
	copy(addr[:], net.ParseIP("2001:db8::1"))
	if got, err := natlookAddr(syscall.AF_INET6, &addr, 443); err != nil || got.String() != "[2001:db8::1]:443" {
		t.Fatalf("IPv6 = %v, %v", got, err)
	}
	copy(addr[:], net.IPv4(192, 0, 2, 1).To4())
	if got, err := natlookAddr(syscall.AF_INET, &addr, 80); err != nil || got.String() != "192.0.2.1:80" {
		t.Fatalf("IPv4 = %v, %v", got, err)
	}
	if _, err := natlookAddr(99, &addr, 80); err == nil {
		t.Fatal("unknown family accepted")
	}
}
