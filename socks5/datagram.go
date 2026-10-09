package socks5

// MaxDatagramHeaderLen is the length of the longest UDP datagram header:
// two reserved bytes, the fragment number and an address.
const MaxDatagramHeaderLen = 3 + MaxAddrLen

// ParseDatagram parses the header of a UDP ASSOCIATE datagram and returns the
// address and the payload, which aliases b.
//
// It returns ErrFragmented for a fragment number other than 0, since
// fragmentation is not supported, and ErrMalformed for a truncated header.
// The reserved field is ignored, which also accepts senders that store the
// payload length there.
func ParseDatagram(b []byte) (Addr, []byte, error) {
	if len(b) < 3 {
		return Addr{}, nil, ErrMalformed
	}
	if b[2] != 0 {
		return Addr{}, nil, ErrFragmented
	}
	addr, n, err := DecodeAddr(b[3:])
	if err != nil {
		return Addr{}, nil, err
	}
	return addr, b[3+n:], nil
}

// AppendDatagram appends a UDP ASSOCIATE datagram for addr carrying payload
// to b. It returns ErrInvalidAddr for a domain name longer than 255 bytes.
func AppendDatagram(b []byte, addr Addr, payload []byte) ([]byte, error) {
	out, err := addr.AppendBinary(append(b, 0, 0, 0))
	if err != nil {
		return b, err
	}
	return append(out, payload...), nil
}
