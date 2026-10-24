package socks5

import (
	"encoding/binary"
	"io"
	"net/netip"

	"github.com/djylb/netx"
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

// AppendAddr appends the encoded address a (type, address and port) to b.
// IPv4-mapped IPv6 addresses are sent as IPv4 and zones are dropped; the
// zero Addr is sent as 0.0.0.0:0, the usual bound address of a failure
// reply. It returns ErrInvalidAddr for a name longer than 255 bytes.
func AppendAddr(b []byte, a netx.Addr) ([]byte, error) {
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
func ReadAddr(r io.Reader) (netx.Addr, error) {
	var buf [MaxAddrLen]byte
	if _, err := io.ReadFull(r, buf[:2]); err != nil {
		return netx.Addr{}, unexpectedEOF(err)
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
		return netx.Addr{}, ErrAddrType
	}
	if _, err := io.ReadFull(r, buf[2:n]); err != nil {
		return netx.Addr{}, unexpectedEOF(err)
	}
	addr, _, err := DecodeAddr(buf[:n])
	return addr, err
}

// DecodeAddr decodes the encoded address at the start of b and returns it
// with its encoded length. It returns ErrAddrType for an unknown address type
// and ErrMalformed for a truncated address or an empty domain name.
//
// The address is normalised as described at netx.Addr: every IP address
// comes back as IP, also a domain name that is an IP literal, and other
// names in lower case, unresolved.
func DecodeAddr(b []byte) (netx.Addr, int, error) {
	if len(b) < 1 {
		return netx.Addr{}, 0, ErrMalformed
	}
	var addr netx.Addr
	pos := 1
	switch b[0] {
	case atypIPv4:
		if len(b) < pos+4+2 {
			return netx.Addr{}, 0, ErrMalformed
		}
		addr.IP = netip.AddrFrom4([4]byte(b[pos : pos+4]))
		pos += 4
	case atypIPv6:
		if len(b) < pos+16+2 {
			return netx.Addr{}, 0, ErrMalformed
		}
		addr.IP = netip.AddrFrom16([16]byte(b[pos : pos+16])).Unmap()
		pos += 16
	case atypDomain:
		if len(b) < pos+1 {
			return netx.Addr{}, 0, ErrMalformed
		}
		n := int(b[pos])
		pos++
		if n == 0 || len(b) < pos+n+2 {
			return netx.Addr{}, 0, ErrMalformed
		}
		addr = nameAddr(string(b[pos : pos+n]))
		pos += n
	default:
		return netx.Addr{}, 0, ErrAddrType
	}
	addr.Port = binary.BigEndian.Uint16(b[pos:])
	return addr, pos + 2, nil
}

// nameAddr returns the Addr of a requested host name, normalised by
// netx.HostAddr, so that address policies see every form of an address.
func nameAddr(name string) netx.Addr { return netx.HostAddr(name, 0) }

// unexpectedEOF turns an EOF inside a message into io.ErrUnexpectedEOF.
func unexpectedEOF(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}
