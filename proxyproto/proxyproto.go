// Package proxyproto builds and decodes PROXY protocol v1 and v2 headers,
// which carry the original client and destination addresses of a proxied
// connection to the backend, and provides a Conn that reports those
// addresses for a connection whose peer sends one, with a Listener that
// wraps the connections it accepts. Both serve streams and UDP flows whose
// first datagram carries the header.
//
// A header lets its sender choose the reported client address, so accept
// one only from trusted peers, such as with TrustPrefixes:
//
//	ln := &proxyproto.Listener{
//		Listener:  inner,
//		PolicyFor: proxyproto.TrustPrefixes(netip.MustParsePrefix("10.0.0.0/8")),
//	}
//
// To send a header, build it with NewHeader or HeaderFromConn and encode it
// with Header.AppendBinary. HeaderOf finds the header of a Conn beneath
// other wrappers.
//
// Decoding is lenient towards non-standard senders wherever that cannot
// change who a connection is attributed to: version 1 lines may end in a bare
// LF, use runs of spaces, any letter case, UDP4 and UDP6 tokens, address
// families that differ from the token, and padded ports; version 2 headers
// may carry any version nibble. Unknown commands, protocols and families,
// short address blocks and truncated TLVs make the connection's own
// addresses, or the whole TLVs, apply instead of failing. Decoded headers
// drop NOOP padding and keep every other TLV in no more memory than the
// header took. The package depends only on the standard library.
package proxyproto

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
)

// Version selects the PROXY protocol header version.
type Version int

const (
	// V1 is the text header format.
	V1 Version = 1
	// V2 is the binary header format.
	V2 Version = 2
)

// NewHeader returns a header of version v for a connection from src to dst.
//
// Both addresses are *net.TCPAddr, both *net.UDPAddr or, for version 2, both
// *net.UnixAddr of the same kind (stream or "unixgram"), and src must have an
// IP address. A nil dst, or one with an unspecified IP address, stands for an
// unknown destination: it is sent as the zero address of src's family
// (0.0.0.0 or ::), with dst's port if any; a nil Unix dst is unnamed. An
// IPv4 and an IPv6 address are sent as IPv6 with the IPv4 side in its
// IPv4-mapped form (::ffff:a.b.c.d). NewHeader returns an error for other
// pairs, such as a nil src, address types of other packages, or a TCP and a
// UDP address. The header holds copies of the addresses.
//
// When the pair cannot be sent and the backend should still get a header,
// send one without addresses explicitly: Header{Version: v} is PROXY
// UNKNOWN in version 1 and a PROXY command with AF_UNSPEC in version 2, which
// can still carry TLVs, so that the backend uses the connection's own
// addresses. For a proxy's own connections, such as health checks, use
// Header{Version: v, Local: true}, the LOCAL command.
func NewHeader(v Version, src, dst net.Addr) (*Header, error) {
	if v != V1 && v != V2 {
		return nil, fmt.Errorf("proxyproto: unknown version %d", v)
	}
	h := &Header{Version: v}
	switch s := src.(type) {
	case *net.TCPAddr:
		d, ok := dst.(*net.TCPAddr)
		if !ok && dst != nil {
			return nil, mismatched(src, dst)
		}
		if s == nil {
			return nil, errNilAddr
		}
		var dip net.IP
		var dport int
		if d != nil {
			dip, dport = d.IP, d.Port
		}
		h.Source = &net.TCPAddr{IP: cloneIP(s.IP), Port: s.Port, Zone: s.Zone}
		h.Destination = &net.TCPAddr{IP: destinationIP(s.IP, dip), Port: dport}
	case *net.UDPAddr:
		d, ok := dst.(*net.UDPAddr)
		if !ok && dst != nil {
			return nil, mismatched(src, dst)
		}
		if s == nil {
			return nil, errNilAddr
		}
		var dip net.IP
		var dport int
		if d != nil {
			dip, dport = d.IP, d.Port
		}
		h.Source = &net.UDPAddr{IP: cloneIP(s.IP), Port: s.Port, Zone: s.Zone}
		h.Destination = &net.UDPAddr{IP: destinationIP(s.IP, dip), Port: dport}
	case *net.UnixAddr:
		d, ok := dst.(*net.UnixAddr)
		if !ok && dst != nil {
			return nil, mismatched(src, dst)
		}
		if s == nil {
			return nil, errNilAddr
		}
		h.Source = &net.UnixAddr{Name: s.Name, Net: s.Net}
		if d == nil {
			h.Destination = &net.UnixAddr{Net: s.Net}
		} else {
			h.Destination = &net.UnixAddr{Name: d.Name, Net: d.Net}
		}
	case nil:
		return nil, errNilAddr
	default:
		return nil, fmt.Errorf("proxyproto: unsupported source address type %T", src)
	}
	if _, err := h.addrs(); err != nil {
		return nil, err
	}
	return h, nil
}

// HeaderFromConn returns a header of version v for c, from its remote
// address to its local address, as NewHeader does.
func HeaderFromConn(v Version, c net.Conn) (*Header, error) {
	if c == nil {
		return nil, errors.New("proxyproto: nil connection")
	}
	return NewHeader(v, c.RemoteAddr(), c.LocalAddr())
}

var errNilAddr = errors.New("proxyproto: nil address")

func mismatched(src, dst net.Addr) error {
	return fmt.Errorf("proxyproto: source %T and destination %T do not form an address pair", src, dst)
}

func cloneIP(ip net.IP) net.IP {
	return append(net.IP(nil), ip...)
}

// destinationIP returns a copy of dst, or the zero address of src's family
// when dst is unspecified.
func destinationIP(src, dst net.IP) net.IP {
	if len(dst) > 0 && !dst.IsUnspecified() {
		return cloneIP(dst)
	}
	if src.To4() != nil {
		return net.IPv4zero.To4()
	}
	return make(net.IP, net.IPv6len)
}

// ipPair is a pair of IP addresses as a header carries them: both IPv4, or
// both IPv6 with any IPv4 side in its IPv4-mapped form, without zones.
type ipPair struct {
	src, dst netip.AddrPort
	udp      bool
}

func (p ipPair) is4() bool { return p.src.Addr().Is4() }

// newIPPair returns the pair of two TCP or two UDP addresses.
func newIPPair(src, dst net.Addr) (ipPair, bool, error) {
	var s, d netip.AddrPort
	var udp bool
	switch a := src.(type) {
	case *net.TCPAddr:
		b, ok := dst.(*net.TCPAddr)
		if !ok {
			return ipPair{}, false, nil
		}
		if a == nil || b == nil {
			return ipPair{}, true, errNilAddr
		}
		var err error
		if s, err = addrPort(a.IP, a.Port); err == nil {
			d, err = addrPort(b.IP, b.Port)
		}
		if err != nil {
			return ipPair{}, true, err
		}
	case *net.UDPAddr:
		b, ok := dst.(*net.UDPAddr)
		if !ok {
			return ipPair{}, false, nil
		}
		if a == nil || b == nil {
			return ipPair{}, true, errNilAddr
		}
		var err error
		if s, err = addrPort(a.IP, a.Port); err == nil {
			d, err = addrPort(b.IP, b.Port)
		}
		if err != nil {
			return ipPair{}, true, err
		}
		udp = true
	default:
		return ipPair{}, false, nil
	}
	if !s.Addr().Is4() || !d.Addr().Is4() {
		s = netip.AddrPortFrom(netip.AddrFrom16(s.Addr().As16()), s.Port())
		d = netip.AddrPortFrom(netip.AddrFrom16(d.Addr().As16()), d.Port())
	}
	return ipPair{src: s, dst: d, udp: udp}, true, nil
}

// addrPort returns ip and port without a zone, with an IPv4-mapped address
// as IPv4.
func addrPort(ip net.IP, port int) (netip.AddrPort, error) {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.AddrPort{}, errors.New("proxyproto: address without an IP address")
	}
	if port < 0 || port > 0xffff {
		return netip.AddrPort{}, fmt.Errorf("proxyproto: port %d out of range", port)
	}
	return netip.AddrPortFrom(a.Unmap(), uint16(port)), nil
}
