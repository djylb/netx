package proxyproto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
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

// TLV is a version 2 type-length-value field.
type TLV struct {
	Type  TLVType
	Value []byte
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
	// TLVs holds the version 2 type-length-value fields in header order.
	// Parsing omits NOOP padding and fields past the 64th.
	TLVs []TLV
}

// TLV returns the value of the first field of type t.
func (h *Header) TLV(t TLVType) ([]byte, bool) {
	for _, tlv := range h.TLVs {
		if tlv.Type == t {
			return tlv.Value, true
		}
	}
	return nil, false
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
// error. Version 2 also fails when a TLV value or the header exceeds 65535
// bytes. The address rules otherwise match V1Header and V2Header.
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
	for _, tlv := range h.TLVs {
		if len(tlv.Value) > 0xffff {
			return b[:start], fmt.Errorf("proxyproto: TLV 0x%02x value of %d bytes", tlv.Type, len(tlv.Value))
		}
		b = append(b, byte(tlv.Type))
		b = binary.BigEndian.AppendUint16(b, uint16(len(tlv.Value)))
		b = append(b, tlv.Value...)
	}
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

func appendUnixPath(b []byte, name string) []byte {
	b = append(b, name...)
	var zero [unixPathLen]byte
	return append(b, zero[len(name):]...)
}
