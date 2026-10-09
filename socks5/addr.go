package socks5

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// Address types defined by RFC 1928.
const (
	atypIPv4   = 1
	atypDomain = 3
	atypIPv6   = 4
)

// MaxAddrLen is the length of the longest encoded address: the type byte, a
// length byte, a 255-byte domain name and the port.
const MaxAddrLen = 1 + 1 + 255 + 2

// Addr is a SOCKS address: an IP address or a domain name, and a port.
//
// When IP is valid it is used and Name is ignored. IPv4-mapped IPv6
// addresses are sent as IPv4 and zones are dropped. The zero Addr is sent as
// 0.0.0.0:0, the usual bound address of a failure reply.
type Addr struct {
	IP   netip.Addr
	Name string
	Port uint16
}

// AddrFromNetAddr converts a *net.TCPAddr, a *net.UDPAddr, or another
// net.Addr whose String is "host:port". It returns the zero Addr for nil or
// for an address it cannot split.
func AddrFromNetAddr(a net.Addr) Addr {
	switch a := a.(type) {
	case nil:
		return Addr{}
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

// ParseAddr parses "host:port", where host is an IP literal or a domain name
// of at most 255 bytes.
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
	if host == "" || len(host) > 255 {
		return Addr{}, ErrInvalidAddr
	}
	return Addr{Name: host, Port: uint16(port)}, nil
}

// String returns the address as "host:port".
func (a Addr) String() string {
	host := a.Name
	switch {
	case a.IP.IsValid():
		host = a.IP.Unmap().WithZone("").String()
	case host == "":
		host = "0.0.0.0"
	}
	return net.JoinHostPort(host, strconv.Itoa(int(a.Port)))
}

// AppendBinary appends the encoded address (type, address and port) to b. It
// returns ErrInvalidAddr for a domain name longer than 255 bytes.
func (a Addr) AppendBinary(b []byte) ([]byte, error) {
	switch ip := a.IP.Unmap(); {
	case ip.Is4():
		b = append(b, atypIPv4)
		v4 := ip.As4()
		b = append(b, v4[:]...)
	case ip.Is6():
		b = append(b, atypIPv6)
		v6 := ip.As16()
		b = append(b, v6[:]...)
	case a.Name != "":
		if len(a.Name) > 255 {
			return b, ErrInvalidAddr
		}
		b = append(b, atypDomain, byte(len(a.Name)))
		b = append(b, a.Name...)
	default:
		b = append(b, atypIPv4, 0, 0, 0, 0)
	}
	return binary.BigEndian.AppendUint16(b, a.Port), nil
}

// ReadAddr reads an encoded address, normalized as by DecodeAddr. It returns
// ErrAddrType for an unknown address type and ErrMalformed for an empty
// domain name.
func ReadAddr(r io.Reader) (Addr, error) {
	var buf [MaxAddrLen]byte
	if _, err := io.ReadFull(r, buf[:2]); err != nil {
		return Addr{}, unexpectedEOF(err)
	}
	var n int
	switch buf[0] {
	case atypIPv4:
		n = 1 + 4 + 2
	case atypIPv6:
		n = 1 + 16 + 2
	case atypDomain:
		n = 2 + int(buf[1]) + 2
	default:
		return Addr{}, ErrAddrType
	}
	if _, err := io.ReadFull(r, buf[2:n]); err != nil {
		return Addr{}, unexpectedEOF(err)
	}
	addr, _, err := DecodeAddr(buf[:n])
	return addr, err
}

// DecodeAddr decodes the encoded address at the start of b and returns it
// with its encoded length. It returns ErrAddrType for an unknown address type
// and ErrMalformed for a truncated address or an empty domain name.
//
// Every IP address comes back as IP, in one form: an IPv4-mapped IPv6
// address as IPv4, and a domain name that is an IP literal, such as
// "127.0.0.1" or "::1", also with one trailing dot such as "127.0.0.1.", as
// that address without a zone. Other names are kept unresolved.
func DecodeAddr(b []byte) (Addr, int, error) {
	if len(b) < 1 {
		return Addr{}, 0, ErrMalformed
	}
	var addr Addr
	pos := 1
	switch b[0] {
	case atypIPv4:
		if len(b) < pos+4+2 {
			return Addr{}, 0, ErrMalformed
		}
		addr.IP = netip.AddrFrom4([4]byte(b[pos : pos+4]))
		pos += 4
	case atypIPv6:
		if len(b) < pos+16+2 {
			return Addr{}, 0, ErrMalformed
		}
		addr.IP = netip.AddrFrom16([16]byte(b[pos : pos+16])).Unmap()
		pos += 16
	case atypDomain:
		if len(b) < pos+1 {
			return Addr{}, 0, ErrMalformed
		}
		n := int(b[pos])
		pos++
		if n == 0 || len(b) < pos+n+2 {
			return Addr{}, 0, ErrMalformed
		}
		addr = nameAddr(string(b[pos : pos+n]))
		pos += n
	default:
		return Addr{}, 0, ErrAddrType
	}
	addr.Port = binary.BigEndian.Uint16(b[pos:])
	return addr, pos + 2, nil
}

// nameAddr returns the Addr of a requested host name: its IP address when it
// is an IP literal, also with one trailing dot as in "127.0.0.1.", which some
// resolvers connect to as that address, so that address policies see every
// form of an address.
func nameAddr(name string) Addr {
	if ip, err := netip.ParseAddr(strings.TrimSuffix(name, ".")); err == nil {
		return Addr{IP: ip.Unmap().WithZone("")}
	}
	return Addr{Name: name}
}

// unexpectedEOF turns an EOF inside a message into io.ErrUnexpectedEOF.
func unexpectedEOF(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}
