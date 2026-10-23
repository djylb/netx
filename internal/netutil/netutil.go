// Package netutil holds the small helpers that the packages of this module
// share: address normalisation, the splice decision and the ContextDialer
// interface. It depends on the standard library alone, so that the leaf
// packages can use it.
package netutil

import (
	"context"
	"net"
	"net/netip"
	"reflect"
	"runtime"
)

// ContextDialer dials connections. *net.Dialer implements it.
type ContextDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// IsNilPointer reports whether v is a nil pointer in a non-nil interface,
// such as a nil *net.TCPConn passed as a net.Conn, whose methods, such as
// *tls.Conn's NetConn, may not accept it.
func IsNilPointer(v any) bool {
	rv := reflect.ValueOf(v)
	return rv.Kind() == reflect.Pointer && rv.IsNil()
}

// UnmapAddrPort returns ap with an IPv4-mapped IPv6 address as IPv4, as
// which a dual-stack socket reports IPv4 peers, so that a peer has one form.
// A zone is kept.
func UnmapAddrPort(ap netip.AddrPort) netip.AddrPort {
	if ap.Addr().Is4In6() {
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	return ap
}

// PeerAddrPort returns the IP address and port of addr, unmapped and
// without a zone: of a *net.TCPAddr or *net.UDPAddr, or of another address
// whose String is "ip:port" or a bare IP address, which gets port 0. It
// returns the zero AddrPort for nil, a nil pointer and other addresses.
func PeerAddrPort(addr net.Addr) netip.AddrPort {
	var ap netip.AddrPort
	switch a := addr.(type) {
	case nil:
	case *net.TCPAddr:
		if a != nil {
			ap = a.AddrPort()
		}
	case *net.UDPAddr:
		if a != nil {
			ap = a.AddrPort()
		}
	default:
		if IsNilPointer(addr) {
			break
		}
		s := addr.String()
		if parsed, err := netip.ParseAddrPort(s); err == nil {
			ap = parsed
		} else if ip, err := netip.ParseAddr(s); err == nil {
			ap = netip.AddrPortFrom(ip, 0)
		}
	}
	if !ap.Addr().IsValid() {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(ap.Addr().Unmap().WithZone(""), ap.Port())
}

// UnmappedPrefixes returns the prefixes that hold, among unmapped addresses
// (IPv4 as IPv4), what p holds: an IPv4-mapped prefix as the IPv4 prefix it
// maps, and an IPv6 prefix that holds all IPv4-mapped addresses, such as
// ::/0, also as 0.0.0.0/0. p is masked first; an invalid p gives none.
func UnmappedPrefixes(p netip.Prefix) []netip.Prefix {
	if p = p.Masked(); !p.IsValid() {
		return nil
	}
	// The IPv4-mapped part of the IPv6 address space.
	v4InV6 := netip.PrefixFrom(netip.AddrFrom16([16]byte{10: 0xff, 11: 0xff}), 96)
	switch {
	case p.Addr().Is4In6() && p.Bits() >= v4InV6.Bits():
		return []netip.Prefix{netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-v4InV6.Bits())}
	case p.Addr().Is6() && p.Bits() < v4InV6.Bits() && p.Contains(v4InV6.Addr()):
		return []netip.Prefix{p, netip.PrefixFrom(netip.IPv4Unspecified(), 0)}
	}
	return []netip.Prefix{p}
}

// SpliceOS reports whether *net.TCPConn moves data with splice(2).
const SpliceOS = runtime.GOOS == "linux" || runtime.GOOS == "android"

// Splices reports whether io.Copy(dst, src) moves the data with splice: from
// a TCP or Unix stream connection into a TCP connection, or from a TCP
// connection into a Unix stream connection.
func Splices(dst, src any) bool {
	if !SpliceOS {
		return false
	}
	switch d := dst.(type) {
	case *net.TCPConn:
		switch s := src.(type) {
		case *net.TCPConn:
			return true
		case *net.UnixConn:
			return IsStreamUnix(s)
		}
	case *net.UnixConn:
		_, ok := src.(*net.TCPConn)
		return ok && IsStreamUnix(d)
	}
	return false
}

// IsStreamUnix reports whether c is a "unix" stream socket, the only kind of
// Unix connection that splice is used for.
func IsStreamUnix(c *net.UnixConn) bool {
	addr := c.LocalAddr()
	return addr != nil && addr.Network() == "unix"
}
