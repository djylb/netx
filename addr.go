package netx

import (
	"errors"
	"net"
	"net/netip"
	"strconv"

	"github.com/djylb/netx/internal/netutil"
)

// ErrInvalidAddr reports an address that cannot be parsed or encoded.
var ErrInvalidAddr = errors.New("netx: invalid address")

// MaxNameLen is the length of the longest host name an Addr holds, as DNS
// and SOCKS bound it.
const MaxNameLen = 255

// Addr is a destination as proxy requests name it: an IP address or a host
// name, and a port. When IP is valid it is used and Name is ignored. The
// zero Addr stands for no address and prints as "0.0.0.0:0".
//
// The constructors of this module put every IP address in IP, in one form:
// an IPv4-mapped IPv6 address as IPv4, without a zone, also when it comes as
// a name that is an IP literal, such as "127.0.0.1" or "::1", or one with a
// trailing dot, such as "127.0.0.1.", which some resolvers connect to as
// that address; and names in lower case, with a trailing dot kept. Names are
// not resolved. A policy on IP addresses that sees an Addr, such as a proxy
// server's Allow hook, must therefore also check the addresses that names
// resolve to, where they are dialed, for example with a net.Dialer Control
// function, since some resolvers turn legacy forms such as "127.1" or
// "0x7f.0.0.1" into addresses. The unspecified addresses 0.0.0.0 and :: reach
// the local host on many systems.
type Addr struct {
	IP   netip.Addr
	Name string
	Port uint16
}

// HostAddr returns the Addr of host, an IP literal or a name, and port,
// normalised as described at Addr. It does not check that a name is valid.
func HostAddr(host string, port uint16) Addr {
	if ip, ok := netutil.HostIP(host); ok {
		return Addr{IP: ip, Port: port}
	}
	return Addr{Name: lowerASCII(host), Port: port}
}

// AddrFromAddrPort returns the Addr of ap, normalised as described at Addr.
func AddrFromAddrPort(ap netip.AddrPort) Addr {
	return Addr{IP: ap.Addr().Unmap().WithZone(""), Port: ap.Port()}
}

// ParseAddr parses "host:port", where host is an IP literal, IPv6 in
// brackets, or a name of at most MaxNameLen bytes, normalised as described
// at Addr.
func ParseAddr(s string) (Addr, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return Addr{}, ErrInvalidAddr
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return Addr{}, ErrInvalidAddr
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return Addr{IP: ip.Unmap().WithZone(""), Port: uint16(port)}, nil
	}
	if host == "" || len(host) > MaxNameLen {
		return Addr{}, ErrInvalidAddr
	}
	return HostAddr(host, uint16(port)), nil
}

// AddrFromNetAddr converts a *net.TCPAddr, a *net.UDPAddr, an Addr, or
// another net.Addr whose String is "host:port". It returns the zero Addr for
// nil, a nil pointer or an address it cannot split.
func AddrFromNetAddr(a net.Addr) Addr {
	switch a := a.(type) {
	case nil:
		return Addr{}
	case Addr:
		return a
	case *net.TCPAddr:
		if a == nil {
			return Addr{}
		}
		return addrFromIP(a.IP, a.Port)
	case *net.UDPAddr:
		if a == nil {
			return Addr{}
		}
		return addrFromIP(a.IP, a.Port)
	}
	if netutil.IsNilPointer(a) {
		return Addr{}
	}
	addr, err := ParseAddr(a.String())
	if err != nil {
		return Addr{}
	}
	return addr
}

func addrFromIP(ip net.IP, port int) Addr {
	addr, _ := netip.AddrFromSlice(ip)
	return Addr{IP: addr.Unmap(), Port: uint16(port)}
}

// IsZero reports whether a is the zero Addr.
func (a Addr) IsZero() bool { return a == Addr{} }

// Host returns the IP address as text, or the name, or "0.0.0.0" for
// neither.
func (a Addr) Host() string {
	switch {
	case a.IP.IsValid():
		return a.IP.Unmap().WithZone("").String()
	case a.Name == "":
		return "0.0.0.0"
	}
	return a.Name
}

// String returns the address as "host:port", with an IPv6 address in
// brackets, for net.Dial.
func (a Addr) String() string {
	return net.JoinHostPort(a.Host(), strconv.Itoa(int(a.Port)))
}

// Network returns "", as an Addr names no network, so that an Addr is also a
// net.Addr, such as for a source that is a name.
func (a Addr) Network() string { return "" }

// lowerASCII returns s with ASCII letters in lower case, s itself when it
// has none in upper case.
func lowerASCII(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if c := b[j]; c >= 'A' && c <= 'Z' {
					b[j] = c + 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}
