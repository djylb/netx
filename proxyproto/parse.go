package proxyproto

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// Parse parses the PROXY protocol header at the start of b and returns it
// with its length in bytes. TLV values are copied, so the header does not
// alias b.
//
// Parse accepts the deviations of non-standard senders described in the
// package documentation. It returns ErrNoHeader if b does not start with a
// header, io.ErrUnexpectedEOF if b holds only the start of one, so that a
// caller sniffing a stream can read more and try again, and an error wrapping
// ErrMalformed for a header that cannot be parsed.
func Parse(b []byte) (*Header, int, error) {
	h, n, _, err := parse(b)
	if err != nil {
		return nil, 0, err
	}
	return h, n, nil
}

// Read reads a PROXY protocol header from r. Its buffer must hold the whole
// of a version 1 header, at most 107 bytes or, with the padding some senders
// add, 256; the default 4096 does. Version 2 headers of any size are read.
//
// If the stream does not start with a header, Read returns ErrNoHeader and
// consumes nothing, so the bytes can still be read from r. A valid header is
// consumed. After an error wrapping ErrMalformed the stream position is
// unspecified. Read only blocks while the bytes received so far are the start
// of a header.
func Read(r *bufio.Reader) (*Header, error) {
	for need := 1; ; {
		data, err := r.Peek(need)
		if errors.Is(err, bufio.ErrBufferFull) {
			if data[0] != v2Signature[0] {
				return nil, malformed("version 1 header longer than the %d-byte read buffer", r.Size())
			}
			// A version 2 header larger than r's buffer; its length is known.
			buf := make([]byte, need)
			if _, err := io.ReadFull(r, buf); err != nil {
				return nil, unexpectedEOF(err)
			}
			h, _, _, err := parse(buf)
			return h, err
		}
		h, n, more, perr := parse(data)
		switch {
		case perr == nil:
			_, _ = r.Discard(n)
			return h, nil
		case !errors.Is(perr, io.ErrUnexpectedEOF):
			return nil, perr
		case err != nil:
			if len(data) == 0 {
				return nil, err
			}
			return nil, unexpectedEOF(err)
		}
		need = more
	}
}

// parse is Parse that also returns, for an incomplete header, the number of
// bytes needed before it can make progress.
func parse(b []byte) (h *Header, n, need int, err error) {
	if len(b) == 0 {
		return nil, 0, 1, io.ErrUnexpectedEOF
	}
	sig := v1Prefix
	if b[0] == v2Signature[0] {
		sig = v2Signature
	}
	if k := min(len(b), len(sig)); !bytes.Equal(b[:k], []byte(sig[:k])) {
		return nil, 0, 0, ErrNoHeader
	}
	if len(b) < len(sig) {
		return nil, 0, len(b) + 1, io.ErrUnexpectedEOF
	}
	if sig == v2Signature {
		return parseV2(b)
	}
	return parseV1(b)
}

func malformed(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrMalformed}, args...)...)
}

// parseV1 goes beyond the specification for non-standard senders. It accepts
// a line ending in a bare LF, runs of spaces and any letter case. Tokens
// starting with TCP or UDP, such as UDP4 and UDP6, carry addresses, which may
// differ in family from the token, have IPv6 zones and ports with leading
// zeros, and be followed by extra fields. Lines may be up to maxV1Line bytes.
// Other tokens are treated as UNKNOWN.
func parseV1(b []byte) (*Header, int, int, error) {
	end := bytes.IndexByte(b[:min(len(b), maxV1Line)], '\n')
	if end < 0 {
		if len(b) >= maxV1Line {
			return nil, maxV1Line, 0, malformed("version 1 header longer than %d bytes", maxV1Line)
		}
		return nil, 0, len(b) + 1, io.ErrUnexpectedEOF
	}
	n := end + 1
	fields := strings.Fields(string(b[len(v1Prefix):end]))
	h := &Header{Version: V1}
	var udp bool
	if len(fields) > 0 {
		switch proto := strings.ToUpper(fields[0]); {
		case strings.HasPrefix(proto, "TCP"):
		case strings.HasPrefix(proto, "UDP"):
			udp = true
		default:
			fields = nil
		}
	}
	if len(fields) == 0 {
		h.Local = true
		return h, n, 0, nil
	}
	if len(fields) < 5 {
		return nil, n, 0, malformed("version 1 %s header with %d fields", fields[0], len(fields)+1)
	}
	src, ok1 := parseV1Addr(fields[1], fields[3])
	dst, ok2 := parseV1Addr(fields[2], fields[4])
	if !ok1 || !ok2 {
		return nil, n, 0, malformed("version 1 %s address", fields[0])
	}
	if udp {
		h.Source, h.Destination = net.UDPAddrFromAddrPort(src), net.UDPAddrFromAddrPort(dst)
	} else {
		h.Source, h.Destination = net.TCPAddrFromAddrPort(src), net.TCPAddrFromAddrPort(dst)
	}
	return h, n, 0, nil
}

func parseV1Addr(ip, port string) (netip.AddrPort, bool) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return netip.AddrPort{}, false
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(addr, uint16(p)), true
}

// parseV2 ignores the version nibble and, so that the connection's own
// addresses apply, treats commands other than PROXY as LOCAL and leaves the
// addresses unset for unknown families and transports and for an address
// block too short for its family. TLVs end at the first truncated one; NOOP
// padding is dropped and TLVs past maxTLVs are ignored.
func parseV2(b []byte) (*Header, int, int, error) {
	if len(b) < v2HeadLen {
		return nil, 0, v2HeadLen, io.ErrUnexpectedEOF
	}
	n := v2HeadLen + int(binary.BigEndian.Uint16(b[14:16]))
	if len(b) < n {
		return nil, 0, n, io.ErrUnexpectedEOF
	}
	cmd, af, proto := b[12]&0x0f, b[13]>>4, b[13]&0x0f
	h := &Header{Version: V2, Local: cmd != 1}
	payload := b[v2HeadLen:n]
	if af > 3 {
		return h, n, 0, nil // the TLVs cannot be located
	}
	addrLen := [...]int{0, 12, 36, 2 * unixPathLen}[af]
	if len(payload) < addrLen {
		return h, n, 0, nil
	}
	if !h.Local && (proto == 1 || proto == 2) {
		h.Source, h.Destination = v2Addrs(af, proto, payload[:addrLen])
	}
	h.TLVs = parseTLVs(payload[addrLen:])
	return h, n, 0, nil
}

// maxTLVs is the number of version 2 TLVs a parsed header keeps; later ones
// are ignored, so that a header of many tiny TLVs cannot make the parsed
// Header much larger than the bytes it came from.
const maxTLVs = 64

// parseTLVs returns the TLVs in b, up to maxTLVs and without NOOP padding,
// with their values copied into one allocation. They end at the first
// truncated one.
func parseTLVs(b []byte) []TLV {
	count, size := 0, 0
	for rest := b; len(rest) >= 3 && count < maxTLVs; {
		n := int(binary.BigEndian.Uint16(rest[1:3]))
		if len(rest) < 3+n {
			break
		}
		if TLVType(rest[0]) != TLVNoop {
			count++
			size += n
		}
		rest = rest[3+n:]
	}
	if count == 0 {
		return nil
	}
	tlvs := make([]TLV, 0, count)
	values := make([]byte, 0, size)
	for len(tlvs) < count {
		n := int(binary.BigEndian.Uint16(b[1:3]))
		if t := TLVType(b[0]); t != TLVNoop {
			start := len(values)
			values = append(values, b[3:3+n]...)
			tlvs = append(tlvs, TLV{Type: t, Value: values[start:len(values):len(values)]})
		}
		b = b[3+n:]
	}
	return tlvs
}

func v2Addrs(af, proto byte, b []byte) (src, dst net.Addr) {
	switch af {
	case 1, 2:
		size := 4
		if af == 2 {
			size = 16
		}
		srcIP, _ := netip.AddrFromSlice(b[:size])
		dstIP, _ := netip.AddrFromSlice(b[size : 2*size])
		s := netip.AddrPortFrom(srcIP, binary.BigEndian.Uint16(b[2*size:]))
		d := netip.AddrPortFrom(dstIP, binary.BigEndian.Uint16(b[2*size+2:]))
		if proto == 2 {
			return net.UDPAddrFromAddrPort(s), net.UDPAddrFromAddrPort(d)
		}
		return net.TCPAddrFromAddrPort(s), net.TCPAddrFromAddrPort(d)
	case 3:
		network := "unix"
		if proto == 2 {
			network = "unixgram"
		}
		return &net.UnixAddr{Name: unixPath(b[:unixPathLen]), Net: network},
			&net.UnixAddr{Name: unixPath(b[unixPathLen:]), Net: network}
	}
	return nil, nil
}

func unixPath(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

func unexpectedEOF(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}
