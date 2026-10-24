package socks5

import "github.com/djylb/netx"

// MaxDatagramHeaderLen is the length of the longest UDP datagram header:
// two reserved bytes, the fragment number and an address.
const MaxDatagramHeaderLen = 3 + MaxAddrLen

// DecodeDatagram decodes the header of a UDP ASSOCIATE datagram and returns
// the address with the header's length; the payload is b[n:].
//
// It returns ErrFragmented for a fragment number other than 0, since
// fragmentation is not supported, and ErrMalformed for a truncated header.
// The reserved field is ignored, which also accepts senders that store the
// payload length there.
func DecodeDatagram(b []byte) (addr netx.Addr, n int, err error) {
	if len(b) < 3 {
		return netx.Addr{}, 0, ErrMalformed
	}
	if b[2] != 0 {
		return netx.Addr{}, 0, ErrFragmented
	}
	addr, n, err = DecodeAddr(b[3:])
	if err != nil {
		return netx.Addr{}, 0, err
	}
	return addr, 3 + n, nil
}

// AppendDatagram appends a UDP ASSOCIATE datagram for addr carrying payload
// to b. It returns ErrInvalidAddr for a domain name longer than 255 bytes.
func AppendDatagram(b []byte, addr netx.Addr, payload []byte) ([]byte, error) {
	out, err := AppendAddr(append(b, 0, 0, 0), addr)
	if err != nil {
		return b, err
	}
	return append(out, payload...), nil
}
