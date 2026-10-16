package proxyproto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"iter"
	"net"
	"strconv"
	"strings"
)

const (
	v1Prefix    = "PROXY "
	v2Signature = "\r\n\r\n\x00\r\nQUIT\n"
	v2HeadLen   = 16
	// maxV1Len is the longest version 1 header, CRLF included.
	maxV1Len = 107
	// maxV1Line is the longest version 1 header the parser accepts, leaving
	// room for the padding of non-standard senders.
	maxV1Line = 256
	// unixPathLen is the size of each AF_UNIX address in a version 2 header.
	unixPathLen = 108
)

var (
	// ErrNoHeader is returned by Parse and Read for data that does not start
	// with a PROXY protocol header.
	ErrNoHeader = errors.New("proxyproto: no PROXY protocol header")
	// ErrMalformed reports a header that starts with a PROXY protocol
	// signature but cannot be parsed even leniently: a version 1 TCP or UDP
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
// order. Build them with Append; a parsed header keeps a copy of its fields
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

// Header is a PROXY protocol header.
type Header struct {
	// Version is V1 for the text format and V2 for the binary format.
	Version Version
	// Local marks a version 2 LOCAL command, which a proxy sends for its own
	// connections such as health checks, and a version 1 UNKNOWN header.
	// Unknown version 2 commands and version 1 protocols are parsed as Local.
	// The connection's own addresses apply.
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
// Source and Destination must be both *net.TCPAddr, both *net.UDPAddr or,
// for version 2, both *net.UnixAddr; other pairs and Local are encoded as
// "PROXY UNKNOWN" (version 1) or a LOCAL command (version 2). Version 1 cannot
// carry UDP or TLVs: UDP pairs use the TCP4 and TCP6 tokens, and TLVs are an
// error. Version 2 also fails when TLVs is not a sequence of whole fields or
// the address and TLV block exceeds 65535 bytes. The address rules otherwise
// match V1Header and V2Header.
func (h *Header) AppendBinary(b []byte) ([]byte, error) {
	switch h.Version {
	case V1:
		if len(h.TLVs) > 0 {
			return b, fmt.Errorf("proxyproto: version 1 cannot carry TLVs")
		}
		if h.Local {
			return append(b, "PROXY UNKNOWN\r\n"...), nil
		}
		return appendV1(b, h.Source, h.Destination), nil
	case V2:
		return appendV2(b, h)
	default:
		return b, fmt.Errorf("proxyproto: unknown version %d", h.Version)
	}
}

func appendV1(b []byte, src, dst net.Addr) []byte {
	meta, ok := buildProxyAddrMeta(src, dst)
	if !ok {
		return append(b, "PROXY UNKNOWN\r\n"...)
	}
	b = append(b, v1Prefix...)
	b = append(b, meta.v1Protocol...)
	b = append(b, ' ')
	b = appendIPText(b, meta.srcIP)
	b = append(b, ' ')
	b = appendIPText(b, meta.dstIP)
	b = append(b, ' ')
	b = strconv.AppendUint(b, uint64(meta.srcPort), 10)
	b = append(b, ' ')
	b = strconv.AppendUint(b, uint64(meta.dstPort), 10)
	return append(b, '\r', '\n')
}

func appendV2(b []byte, h *Header) ([]byte, error) {
	start := len(b)
	b = append(b, v2Signature...)
	b = append(b, 0x20, 0, 0, 0) // version and command, family, length

	if !h.Local {
		if meta, ok := buildProxyAddrMeta(h.Source, h.Destination); ok {
			b[start+12] = 0x21
			b[start+13] = meta.famProto
			b = appendV2IPs(b, meta)
		} else if src, dst, ok := unixPair(h.Source, h.Destination); ok {
			b[start+12] = 0x21
			b[start+13] = 0x31
			if src.Net == "unixgram" {
				b[start+13] = 0x32
			}
			b = appendUnixPath(b, src.Name)
			b = appendUnixPath(b, dst.Name)
		}
	}
	if !h.TLVs.wellFormed() {
		return b[:start], fmt.Errorf("proxyproto: TLVs cut short")
	}
	b = append(b, h.TLVs...)
	n := len(b) - start - v2HeadLen
	if n > 0xffff {
		return b[:start], fmt.Errorf("proxyproto: header of %d bytes", v2HeadLen+n)
	}
	binary.BigEndian.PutUint16(b[start+14:], uint16(n))
	return b, nil
}

func appendV2IPs(b []byte, meta proxyAddrMeta) []byte {
	b = append(b, meta.srcIP...)
	b = append(b, meta.dstIP...)
	b = binary.BigEndian.AppendUint16(b, meta.srcPort)
	return binary.BigEndian.AppendUint16(b, meta.dstPort)
}

func unixPair(src, dst net.Addr) (*net.UnixAddr, *net.UnixAddr, bool) {
	s, ok1 := src.(*net.UnixAddr)
	d, ok2 := dst.(*net.UnixAddr)
	if !ok1 || !ok2 || s == nil || d == nil || len(s.Name) > unixPathLen || len(d.Name) > unixPathLen {
		return nil, nil, false
	}
	return s, d, true
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
