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
// It returns ErrNoHeader if b does not start with a header,
// io.ErrUnexpectedEOF if b holds only the start of one, so that a caller
// sniffing a stream can read more and try again, and an error wrapping
// ErrMalformed for an invalid header.
func Parse(b []byte) (*Header, int, error) {
	h, n, _, err := parse(b)
	if err != nil {
		return nil, 0, err
	}
	return h, n, nil
}

// Read reads a PROXY protocol header from r, whose buffer must hold at least
// 107 bytes (the default 4096 does).
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
				return nil, fmt.Errorf("proxyproto: reader buffer of %d bytes is too small", r.Size())
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

func parseV1(b []byte) (*Header, int, int, error) {
	end := bytes.IndexByte(b[:min(len(b), maxV1Len)], '\n')
	if end < 0 {
		if len(b) >= maxV1Len {
			return nil, maxV1Len, 0, malformed("version 1 header longer than %d bytes", maxV1Len)
		}
		return nil, 0, len(b) + 1, io.ErrUnexpectedEOF
	}
	n := end + 1
	if b[end-1] != '\r' {
		return nil, n, 0, malformed("version 1 header not terminated by CRLF")
	}
	fields := strings.Split(string(b[len(v1Prefix):end-1]), " ")
	h := &Header{Version: V1}
	switch fields[0] {
	case "UNKNOWN":
		h.Local = true
		return h, n, 0, nil
	case "TCP4", "TCP6":
	default:
		return nil, n, 0, malformed("version 1 protocol %q", fields[0])
	}
	if len(fields) != 5 {
		return nil, n, 0, malformed("version 1 header with %d fields", len(fields)+1)
	}
	v4 := fields[0] == "TCP4"
	src, ok1 := parseV1Addr(fields[1], fields[3], v4)
	dst, ok2 := parseV1Addr(fields[2], fields[4], v4)
	if !ok1 || !ok2 {
		return nil, n, 0, malformed("version 1 %s address", fields[0])
	}
	h.Source, h.Destination = src, dst
	return h, n, 0, nil
}

func parseV1Addr(ip, port string, v4 bool) (*net.TCPAddr, bool) {
	addr, err := netip.ParseAddr(ip)
	if err != nil || addr.Zone() != "" || addr.Is4() != v4 {
		return nil, false
	}
	// Ports are decimal numbers without sign or leading zeros.
	if port == "" || len(port) > 1 && port[0] == '0' || port[0] == '+' {
		return nil, false
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, false
	}
	return net.TCPAddrFromAddrPort(netip.AddrPortFrom(addr, uint16(p))), true
}

func parseV2(b []byte) (*Header, int, int, error) {
	if len(b) < v2HeadLen {
		return nil, 0, v2HeadLen, io.ErrUnexpectedEOF
	}
	n := v2HeadLen + int(binary.BigEndian.Uint16(b[14:16]))
	verCmd, fam := b[12], b[13]
	if verCmd>>4 != 2 {
		return nil, n, 0, malformed("version 2 header with version %d", verCmd>>4)
	}
	cmd := verCmd & 0x0f
	if cmd > 1 {
		return nil, n, 0, malformed("version 2 command %d", cmd)
	}
	af, proto := fam>>4, fam&0x0f
	if af > 3 || proto > 2 {
		return nil, n, 0, malformed("version 2 family 0x%02x", fam)
	}
	if len(b) < n {
		return nil, 0, n, io.ErrUnexpectedEOF
	}
	payload := b[v2HeadLen:n]
	addrLen := [...]int{0, 12, 36, 2 * unixPathLen}[af]
	if len(payload) < addrLen {
		return nil, n, 0, malformed("version 2 address block shorter than %d bytes", addrLen)
	}
	h := &Header{Version: V2, Local: cmd == 0}
	if cmd == 1 && proto != 0 {
		h.Source, h.Destination = v2Addrs(af, proto, payload[:addrLen])
	}
	if tlvs := payload[addrLen:]; len(tlvs) > 0 {
		tlvs = bytes.Clone(tlvs)
		for len(tlvs) > 0 {
			if len(tlvs) < 3 {
				return nil, n, 0, malformed("version 2 truncated TLV")
			}
			size := int(binary.BigEndian.Uint16(tlvs[1:3]))
			if len(tlvs) < 3+size {
				return nil, n, 0, malformed("version 2 truncated TLV")
			}
			h.TLVs = append(h.TLVs, TLV{Type: TLVType(tlvs[0]), Value: tlvs[3 : 3+size : 3+size]})
			tlvs = tlvs[3+size:]
		}
	}
	return h, n, 0, nil
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
