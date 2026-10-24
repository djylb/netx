package safedial

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/djylb/netx"
)

// Target is a destination that a Policy decides on. A Policy sees a host
// name, before it is resolved, with Name set and Addr invalid, and then
// each address that it resolves to, with both set; an IP address that is
// dialed as such comes with Name empty.
type Target struct {
	// Addr is the IP address, unmapped (IPv4-mapped IPv6 addresses as
	// IPv4) and without a zone, so that prefixes and scopes match every
	// form of an address; invalid while a name is checked before it is
	// resolved.
	Addr netip.Addr
	// Network is the network dialed or sent on, such as "tcp" or "udp4".
	Network string
	// Name is the host name, in lower case and with a trailing dot kept, as
	// requested; empty for an IP address, also one in a legacy IPv4 form
	// such as "127.1".
	Name string
	// Zone is the IPv6 zone that the address is dialed with, such as
	// "eth0", which selects an interface for a link-local address.
	Zone string
	// Port is the port.
	Port uint16
}

// String returns the target as "host:port", the name followed by the
// address in parentheses when it has both.
func (t Target) String() string {
	port := strconv.Itoa(int(t.Port))
	switch {
	case !t.Addr.IsValid():
		return net.JoinHostPort(t.Name, port)
	case t.Name == "":
		return netip.AddrPortFrom(t.Addr.WithZone(t.Zone), t.Port).String()
	}
	return net.JoinHostPort(t.Name, port) + " (" + t.Addr.WithZone(t.Zone).String() + ")"
}

// AddrPort returns the address and port that the target is dialed at, with
// its zone.
func (t Target) AddrPort() netip.AddrPort {
	return netip.AddrPortFrom(t.Addr.WithZone(t.Zone), t.Port)
}

// ParseTarget parses address, "host:port", for network, one of "tcp",
// "tcp4", "tcp6", "udp", "udp4" and "udp6", as Dialer does before it checks
// the target. An IP literal, also in brackets, with a zone or with a
// trailing dot, becomes Addr, as does a host in a legacy IPv4 form that
// ParseLegacyIPv4 reads, such as "127.1" or "0x7f.0.0.1", which system
// resolvers may connect to as that address. Any other host becomes Name,
// in lower case, and must be a host name of letters, digits, hyphens and
// underscores in labels of at most 63 bytes, at most 253 bytes long without
// a trailing dot, whose last label is not numeric; others, such as names
// with spaces or other bytes that resolvers handle in their own ways, and
// an empty host, which net.Dial reads as the local system, fail with an
// error matching netx.ErrInvalidAddr. Non-ASCII names must be given in
// their ASCII (punycode) form.
func ParseTarget(network, address string) (Target, error) {
	if !validNetwork(network) {
		return Target{}, net.UnknownNetworkError(network)
	}
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return Target{}, fmt.Errorf("safedial: %w: %q", netx.ErrInvalidAddr, address)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return Target{}, fmt.Errorf("safedial: %w: port of %q", netx.ErrInvalidAddr, address)
	}
	t, err := hostTarget(host)
	if err != nil {
		return Target{}, err
	}
	t.Network, t.Port = network, uint16(port)
	return t, nil
}

// hostTarget returns the Target of host without network and port. It
// allocates only for an error, and for a name in upper case.
func hostTarget(host string) (Target, error) {
	if strings.IndexByte(host, ':') >= 0 {
		// Only IPv6 literals hold a colon, also with one trailing dot.
		ip, err := netip.ParseAddr(host)
		if err != nil {
			ip, err = netip.ParseAddr(strings.TrimSuffix(host, "."))
		}
		if err != nil {
			return Target{}, fmt.Errorf("safedial: %w: host %q", netx.ErrInvalidAddr, host)
		}
		return addrTarget(ip), nil
	}
	return nameTarget(host)
}

// nameTarget returns the Target of host, which holds no colon: an IPv4
// address, also in a legacy form or with one trailing dot, or a name.
func nameTarget(host string) (Target, error) {
	if len(host) > netx.MaxNameLen {
		return Target{}, fmt.Errorf("safedial: %w: host name too long", netx.ErrInvalidAddr)
	}
	trimmed := strings.TrimSuffix(host, ".")
	if ip, ok := ParseLegacyIPv4(trimmed); ok { // dotted decimal among them
		return Target{Addr: ip}, nil
	}
	if !validName(trimmed) {
		return Target{}, fmt.Errorf("safedial: %w: host name %q", netx.ErrInvalidAddr, host)
	}
	return Target{Name: strings.ToLower(host)}, nil // ASCII alone
}

// addrTarget returns the Target of ip, unmapped, its zone kept apart.
func addrTarget(ip netip.Addr) Target {
	if ip.Is4In6() {
		return Target{Addr: ip.Unmap()}
	}
	return Target{Addr: ip.WithZone(""), Zone: ip.Zone()}
}

// validNetwork reports whether network is one that Dialer dials.
func validNetwork(network string) bool {
	switch network {
	case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6":
		return true
	}
	return false
}

// validName reports whether name, without a trailing dot, is a host name as
// ParseTarget describes. It does not allocate.
func validName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	label := 0 // the length of the current label
	for i := range len(name) {
		switch c := name[i]; {
		case c == '.':
			if label == 0 {
				return false
			}
			label = 0
			continue
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
		if label++; label > 63 {
			return false
		}
	}
	return label > 0 && !numericLabel(name[strings.LastIndexByte(name, '.')+1:])
}

// numericLabel reports whether label is a number, decimal or with 0x, as
// no top-level domain is and as resolvers may read a host that ends in one
// as an address.
func numericLabel(label string) bool {
	digits := label
	hex := len(label) >= 2 && label[0] == '0' && (label[1] == 'x' || label[1] == 'X')
	if hex {
		digits = label[2:]
	}
	for i := range len(digits) {
		c := digits[i]
		if c >= '0' && c <= '9' || hex && (c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			continue
		}
		return false
	}
	return true
}

// ParseLegacyIPv4 parses s as inet_aton does, which system resolvers use
// for numeric hosts: one to four parts separated by dots, each decimal,
// octal with a leading 0 or hexadecimal with 0x, the last filling the
// bytes that the others leave, as in "127.1", "2130706433", "0x7f.0.0.1"
// and "0177.0.0.1", and the dotted decimal form. It reports false for
// anything else, also for a number that does not fit. It does not allocate.
func ParseLegacyIPv4(s string) (netip.Addr, bool) {
	if s == "" || s[0] < '0' || s[0] > '9' {
		return netip.Addr{}, false
	}
	var parts [4]uint32
	n := 0
	for part := range strings.SplitSeq(s, ".") {
		if n == len(parts) {
			return netip.Addr{}, false
		}
		v, ok := legacyNumber(part)
		if !ok {
			return netip.Addr{}, false
		}
		parts[n] = v
		n++
	}
	var v uint32
	for i := range n - 1 {
		if parts[i] > 0xff {
			return netip.Addr{}, false
		}
		v |= parts[i] << (24 - 8*i)
	}
	// The last part fills the bytes that the others leave.
	last := parts[n-1]
	if n > 1 && last >= 1<<(32-8*(n-1)) {
		return netip.Addr{}, false
	}
	v |= last
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}), true
}

// legacyNumber parses one part of a legacy IPv4 address, at most 2^32-1.
func legacyNumber(s string) (uint32, bool) {
	base := uint64(10)
	switch {
	case s == "":
		return 0, false
	case len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'):
		s, base = s[2:], 16
		if s == "" {
			return 0, true // inet_aton reads a bare 0x as 0
		}
	case len(s) >= 2 && s[0] == '0':
		s, base = s[1:], 8
	}
	var v uint64
	for i := range len(s) {
		d := uint64(16)
		switch c := s[i]; {
		case c >= '0' && c <= '9':
			d = uint64(c - '0')
		case c >= 'a' && c <= 'f':
			d = uint64(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = uint64(c-'A') + 10
		}
		if d >= base {
			return 0, false
		}
		if v = v*base + d; v > 1<<32-1 {
			return 0, false
		}
	}
	return uint32(v), true
}
