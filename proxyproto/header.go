package proxyproto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"iter"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
)

const (
	v1Prefix    = "PROXY "
	v2Signature = "\r\n\r\n\x00\r\nQUIT\n"
	v2HeadLen   = 16
	// maxV1Len is the longest version 1 header, CRLF included.
	maxV1Len = 107
	// maxV1Line is the longest version 1 header Decode accepts, leaving
	// room for the padding of non-standard senders.
	maxV1Line = 256
	// unixPathLen is the size of each AF_UNIX address in a version 2 header.
	unixPathLen = 108
)

var (
	// ErrNoHeader is returned by Decode for data that does not start with a
	// PROXY protocol header, and by a Conn whose policy requires one.
	ErrNoHeader = errors.New("proxyproto: no PROXY protocol header")
	// ErrMalformed reports a header that starts with a PROXY protocol
	// signature but cannot be decoded even leniently: a version 1 TCP or UDP
	// line whose addresses do not parse, or one longer than 256 bytes.
	ErrMalformed = errors.New("proxyproto: malformed PROXY protocol header")
)

// TLVType is the type of a version 2 type-length-value field.
type TLVType byte

// TLV types defined by the PROXY protocol specification.
const (
	TLVALPN      TLVType = 0x01 // application protocol, as in TLS ALPN
	TLVAuthority TLVType = 0x02 // host name the client asked for, as in TLS SNI
	TLVCRC32C    TLVType = 0x03 // CRC32c checksum of the header
	TLVNoop      TLVType = 0x04 // padding
	TLVUniqueID  TLVType = 0x05 // opaque connection identifier
	TLVSSL       TLVType = 0x20 // TLS information of the client connection
	TLVNetNS     TLVType = 0x30 // network namespace name
)

// TLV type ranges that the specification leaves to applications: custom
// types for an application's own fields, such as who a connection belongs
// to, and experimental ones. A receiver must accept fields only from peers
// it trusts, as for the addresses; see Listener.PolicyFor and TrustPrefixes.
const (
	TLVCustomMin       TLVType = 0xE0
	TLVCustomMax       TLVType = 0xEF
	TLVExperimentalMin TLVType = 0xF0
	TLVExperimentalMax TLVType = 0xF7
)

// IsCustom reports whether t is in the range for application fields.
func (t TLVType) IsCustom() bool { return t >= TLVCustomMin && t <= TLVCustomMax }

// IsExperimental reports whether t is in the range for experimental fields.
func (t TLVType) IsExperimental() bool { return t >= TLVExperimentalMin && t <= TLVExperimentalMax }

func (t TLVType) String() string {
	switch t {
	case TLVALPN:
		return "ALPN"
	case TLVAuthority:
		return "AUTHORITY"
	case TLVCRC32C:
		return "CRC32C"
	case TLVNoop:
		return "NOOP"
	case TLVUniqueID:
		return "UNIQUE_ID"
	case TLVSSL:
		return "SSL"
	case TLVNetNS:
		return "NETNS"
	default:
		return fmt.Sprintf("0x%02x", byte(t))
	}
}

// TLVs holds version 2 type-length-value fields in their wire encoding: a
// type byte, a 2-byte big-endian length and the value, for each in header
// order. Build them with Append; a decoded header keeps a copy of its fields
// without NOOP padding and ends them at the first truncated one, so it takes
// no more memory than the header did however many fields it has.
type TLVs []byte

// Append appends a field of type t and value v. It fails for a value longer
// than 65535 bytes, leaving the fields unchanged.
func (f TLVs) Append(t TLVType, v []byte) (TLVs, error) {
	if len(v) > 0xffff {
		return f, fmt.Errorf("proxyproto: TLV 0x%02x value of %d bytes", t, len(v))
	}
	out := append(f, byte(t))
	out = binary.BigEndian.AppendUint16(out, uint16(len(v)))
	return append(out, v...), nil
}

// All returns the fields in order, without NOOP padding, until the first
// truncated one. The values share f's memory.
func (f TLVs) All() iter.Seq2[TLVType, []byte] {
	return func(yield func(TLVType, []byte) bool) {
		for rest := f; len(rest) >= 3; {
			n := int(binary.BigEndian.Uint16(rest[1:3]))
			if len(rest) < 3+n {
				return
			}
			t, v := TLVType(rest[0]), rest[3:3+n:3+n]
			rest = rest[3+n:]
			if t != TLVNoop && !yield(t, v) {
				return
			}
		}
	}
}

// Get returns the value of the first field of type t.
func (f TLVs) Get(t TLVType) ([]byte, bool) {
	for typ, v := range f.All() {
		if typ == t {
			return v, true
		}
	}
	return nil, false
}

// wellFormed reports whether f is a sequence of whole fields.
func (f TLVs) wellFormed() bool {
	for rest := f; len(rest) > 0; {
		if len(rest) < 3 {
			return false
		}
		n := 3 + int(binary.BigEndian.Uint16(rest[1:3]))
		if len(rest) < n {
			return false
		}
		rest = rest[n:]
	}
	return true
}

// Header is a PROXY protocol header. Build one to send with NewHeader or
// HeaderFromConn, or as a literal for a Local header.
type Header struct {
	// Version is V1 for the text format and V2 for the binary format.
	Version Version
	// Local marks a version 2 LOCAL command, which a proxy sends for its own
	// connections such as health checks, and a version 1 UNKNOWN header.
	// Unknown version 2 commands and version 1 protocols are decoded as
	// Local. The connection's own addresses apply.
	Local bool
	// Source and Destination are the client and server addresses of the
	// proxied connection: *net.TCPAddr, *net.UDPAddr or *net.UnixAddr. They
	// are nil for a Local header and for unspecified or unknown families, in
	// which case the connection's own addresses apply.
	Source      net.Addr
	Destination net.Addr
	// TLVs holds the version 2 type-length-value fields.
	TLVs TLVs
}

// TLV returns the value of the first field of type t.
func (h *Header) TLV(t TLVType) ([]byte, bool) {
	return h.TLVs.Get(t)
}

// UDPAddrs returns Source and Destination with *net.TCPAddr converted to
// *net.UDPAddr, for a header sent ahead of UDP traffic. Version 1 has no UDP
// token, so UDP senders use TCP4 and TCP6, and some use a version 2 STREAM
// transport. Other addresses are returned unchanged.
func (h *Header) UDPAddrs() (src, dst net.Addr) {
	return udpAddr(h.Source), udpAddr(h.Destination)
}

func udpAddr(a net.Addr) net.Addr {
	if t, ok := a.(*net.TCPAddr); ok && t != nil {
		return &net.UDPAddr{IP: t.IP, Port: t.Port, Zone: t.Zone}
	}
	return a
}

// AppendBinary appends the encoded header to b.
//
// A Local header is encoded without addresses, as "PROXY UNKNOWN" (version
// 1) or a LOCAL command (version 2). Otherwise Source and Destination must be
// as NewHeader returns them, without its rewriting of the destination: both
// *net.TCPAddr or both *net.UDPAddr with IP addresses, or, for version 2,
// both *net.UnixAddr of the same kind with names of at most 108 bytes. Both
// nil, as decoded from a header of an unknown family, is encoded as "PROXY
// UNKNOWN" or a PROXY command of the AF_UNSPEC family. Version 1 has no UDP
// token, so UDP pairs use the TCP4 and TCP6 tokens. AppendBinary fails for
// other addresses, for TLVs in version 1, and in version 2 for TLVs that are
// not a sequence of whole fields or an address and TLV block of more than
// 65535 bytes. On failure b is returned unchanged.
func (h *Header) AppendBinary(b []byte) ([]byte, error) {
	a, err := h.addrs()
	if err != nil {
		return b, err
	}
	switch h.Version {
	case V1:
		if len(h.TLVs) > 0 {
			return b, errors.New("proxyproto: version 1 cannot carry TLVs")
		}
		if a.kind == addrNone {
			return append(b, "PROXY UNKNOWN\r\n"...), nil
		}
		return appendV1(slices.Grow(b, maxV1Len), a.ip), nil
	default:
		return appendV2(b, h, a)
	}
}

// WriteTo writes the encoded header to w with one Write, so that it goes out
// in one segment ahead of the proxied stream or as a datagram of its own. It
// fails as AppendBinary does, without writing, and with io.ErrShortWrite for
// a Write that writes less without an error.
func (h *Header) WriteTo(w io.Writer) (int64, error) {
	bp := headerPool.Get().(*[]byte)
	defer headerPool.Put(bp)
	b, err := h.AppendBinary((*bp)[:0])
	if err != nil {
		return 0, err
	}
	n, err := w.Write(b)
	if err == nil && n < len(b) {
		err = io.ErrShortWrite
	}
	return int64(n), err
}

// headerPool holds the buffers that WriteTo encodes into; a larger header,
// with many TLVs, takes a buffer of its own.
var headerPool = sync.Pool{New: func() any {
	b := make([]byte, 0, 256)
	return &b
}}

// Kinds of address blocks.
const (
	addrNone = iota
	addrIP
	addrUnix
)

// headerAddrs is the address block of an encoded header.
type headerAddrs struct {
	ip               ipPair
	unixSrc, unixDst *net.UnixAddr
	kind             uint8
}

// addrs checks h's version and returns the address block it encodes.
func (h *Header) addrs() (headerAddrs, error) {
	if h.Version != V1 && h.Version != V2 {
		return headerAddrs{}, fmt.Errorf("proxyproto: unknown version %d", h.Version)
	}
	if h.Local || (h.Source == nil && h.Destination == nil) {
		return headerAddrs{}, nil
	}
	if p, ok, err := newIPPair(h.Source, h.Destination); ok || err != nil {
		return headerAddrs{ip: p, kind: addrIP}, err
	}
	s, ok1 := h.Source.(*net.UnixAddr)
	d, ok2 := h.Destination.(*net.UnixAddr)
	switch {
	case !ok1 || !ok2:
		return headerAddrs{}, fmt.Errorf("proxyproto: unsupported address pair %T and %T", h.Source, h.Destination)
	case s == nil || d == nil:
		return headerAddrs{}, errNilAddr
	case h.Version == V1:
		return headerAddrs{}, errors.New("proxyproto: version 1 cannot carry Unix addresses")
	case (s.Net == "unixgram") != (d.Net == "unixgram"):
		return headerAddrs{}, fmt.Errorf("proxyproto: Unix addresses of networks %q and %q", s.Net, d.Net)
	case len(s.Name) > unixPathLen || len(d.Name) > unixPathLen:
		return headerAddrs{}, fmt.Errorf("proxyproto: Unix address name longer than %d bytes", unixPathLen)
	}
	return headerAddrs{unixSrc: s, unixDst: d, kind: addrUnix}, nil
}

func appendV1(b []byte, p ipPair) []byte {
	b = append(b, v1Prefix...)
	if p.is4() {
		b = append(b, "TCP4 "...)
	} else {
		b = append(b, "TCP6 "...)
	}
	b = p.src.Addr().AppendTo(b)
	b = append(b, ' ')
	b = p.dst.Addr().AppendTo(b)
	b = append(b, ' ')
	b = strconv.AppendUint(b, uint64(p.src.Port()), 10)
	b = append(b, ' ')
	b = strconv.AppendUint(b, uint64(p.dst.Port()), 10)
	return append(b, '\r', '\n')
}

func appendV2(b []byte, h *Header, a headerAddrs) ([]byte, error) {
	if !h.TLVs.wellFormed() {
		return b, errors.New("proxyproto: TLVs cut short")
	}
	var cmd, famProto byte = 0x20, 0x00 // LOCAL, AF_UNSPEC
	size := 0
	if !h.Local {
		cmd = 0x21
	}
	switch a.kind {
	case addrIP:
		famProto, size = 0x11, 12
		if !a.ip.is4() {
			famProto, size = 0x21, 36
		}
		if a.ip.udp {
			famProto++
		}
	case addrUnix:
		famProto, size = 0x31, 2*unixPathLen
		if a.unixSrc.Net == "unixgram" {
			famProto = 0x32
		}
	case addrNone:
		// AF_UNSPEC, without addresses.
	}
	n := size + len(h.TLVs)
	if n > 0xffff {
		return b, fmt.Errorf("proxyproto: header of %d bytes", v2HeadLen+n)
	}
	b = slices.Grow(b, v2HeadLen+n)
	b = append(b, v2Signature...)
	b = append(b, cmd, famProto)
	b = binary.BigEndian.AppendUint16(b, uint16(n))
	switch a.kind {
	case addrIP:
		b = appendV2IPs(b, a.ip)
	case addrUnix:
		b = appendUnixPath(b, a.unixSrc.Name)
		b = appendUnixPath(b, a.unixDst.Name)
	case addrNone:
		// No address block.
	}
	return append(b, h.TLVs...), nil
}

func appendV2IPs(b []byte, p ipPair) []byte {
	b = append(b, p.src.Addr().AsSlice()...)
	b = append(b, p.dst.Addr().AsSlice()...)
	b = binary.BigEndian.AppendUint16(b, p.src.Port())
	return binary.BigEndian.AppendUint16(b, p.dst.Port())
}

// appendUnixPath appends name as a sun_path field, with a Linux abstract
// name, which Go spells "@name", starting with a NUL. A lone "@" has no name
// to tell it from an empty field, so it is sent as the path "@".
func appendUnixPath(b []byte, name string) []byte {
	start := len(b)
	b = append(b, name...)
	if len(name) > 1 && strings.HasPrefix(name, "@") {
		b[start] = 0
	}
	var zero [unixPathLen]byte
	return append(b, zero[len(name):]...)
}
