package httphead

import (
	"encoding/binary"
	"errors"
	"io"
	"slices"
	"strings"
)

// HTTP2Preface is the initial connection preface sent by HTTP/2 clients.
const HTTP2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// ParseHTTP2 returns the first request in a prior-knowledge cleartext
// HTTP/2 connection. It expects the preface, SETTINGS and a complete
// request header block. Use HTTP2Scanner for successive prefixes or to
// configure limits.
func ParseHTTP2(data []byte) (*RoutedRequest, error) {
	var s HTTP2Scanner
	return s.Scan(data)
}

const (
	http2FrameHeaderLen  = 9
	http2PrefixOverLimit = "HTTP/2 prefix over the limit"
	// A client uses the initial frame size until the server advertises a
	// different one.
	http2MaxFrameSize = 16384

	frameHeaders      = 0x1
	frameSettings     = 0x4
	frameContinuation = 0x9

	flagAck        = 0x1
	flagEndHeaders = 0x4
	flagPadded     = 0x8
	flagPriority   = 0x20
)

// HTTP2Scanner incrementally parses the first request of a prior-knowledge
// cleartext HTTP/2 connection, including a fragmented HPACK header block.
// The zero value is ready to use. It can only inspect the first request
// and does not perform any part of the HTTP/2 handshake. A scanner is
// single-owner and requires no cleanup. Reset releases a partial block.
type HTTP2Scanner struct {
	// MaxBytes bounds the encoded prefix, including the preface and frames
	// before the first request. A nonpositive value uses 64 KiB.
	MaxBytes int
	// MaxHeaderListBytes bounds the decoded HPACK header list, counting
	// names, values and 32 bytes per field. A nonpositive value uses 64 KiB.
	MaxHeaderListBytes int

	result *RoutedRequest
	err    error
	block  []byte
	pos    int
	need   int
	stream uint32
}

// Reset prepares the scanner for another connection and preserves its limits.
func (s *HTTP2Scanner) Reset() {
	*s = HTTP2Scanner{MaxBytes: s.MaxBytes, MaxHeaderListBytes: s.MaxHeaderListBytes}
}

// Need returns the minimum length at which Scan can make progress after
// io.ErrUnexpectedEOF.
func (s *HTTP2Scanner) Need() int { return max(1, s.need) }

// Scan parses a buffer containing the bytes seen so far. After
// io.ErrUnexpectedEOF, call Scan again with the previous prefix followed by
// new bytes. Set limits before the first call. Scan retains no reference to
// the input buffer. After success or a terminal error, it returns the same
// result until Reset.
func (s *HTTP2Scanner) Scan(data []byte) (*RoutedRequest, error) {
	if s.result != nil || s.err != nil {
		return s.result, s.err
	}
	limit := maxHeadBytes(s.MaxBytes)
	result, err := s.scan(data[:min(len(data), limit)], limit)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		s.result, s.err = result, err
		s.block = nil
	}
	return result, err
}

func (s *HTTP2Scanner) scan(data []byte, limit int) (*RoutedRequest, error) {
	if s.pos == 0 {
		n := min(len(data), len(HTTP2Preface))
		if string(data[:n]) != HTTP2Preface[:n] {
			return nil, malformed("HTTP/2 connection preface")
		}
		if n < len(HTTP2Preface) {
			return s.needMore(n+1, limit)
		}
		s.pos = len(HTTP2Preface)
	}
	for {
		if limit-s.pos < http2FrameHeaderLen {
			return nil, &headError{kind: ErrTooLarge, msg: http2PrefixOverLimit}
		}
		start := s.pos + http2FrameHeaderLen
		if len(data) < start {
			return s.needMore(start, limit)
		}
		h := data[s.pos:start]
		size := int(h[0])<<16 | int(h[1])<<8 | int(h[2])
		typ, flags := h[3], h[4]
		stream := binary.BigEndian.Uint32(h[5:]) & 0x7fffffff
		if size > http2MaxFrameSize {
			return nil, malformed("HTTP/2 frame exceeds the initial size limit")
		}
		if size > limit-start {
			return nil, &headError{kind: ErrTooLarge, msg: http2PrefixOverLimit}
		}
		end := start + size
		if len(data) < end {
			return s.needMore(end, limit)
		}
		first := s.pos == len(HTTP2Preface)
		s.pos = end
		payload := data[start:end]
		if typ == frameSettings && (stream != 0 || flags&flagAck != 0 && size != 0 || !validSettings(payload)) {
			return nil, malformed("HTTP/2 SETTINGS frame")
		}
		switch {
		case first:
			if typ != frameSettings || flags&flagAck != 0 {
				return nil, malformed("expected first HTTP/2 SETTINGS frame")
			}
		case s.stream != 0:
			if typ != frameContinuation || stream != s.stream {
				return nil, malformed("expected HTTP/2 CONTINUATION frame")
			}
			s.block = append(s.block, payload...)
			if flags&flagEndHeaders != 0 {
				return s.request(s.block)
			}
		case typ == frameHeaders:
			frag, err := headersFragment(stream, flags, payload)
			if err != nil {
				return nil, err
			}
			if flags&flagEndHeaders != 0 {
				return s.request(frag)
			}
			s.stream = stream
			s.block = append(s.block, frag...)
		case !beforeHeaders(typ, stream, payload):
			return nil, malformed("unexpected frame before HTTP/2 HEADERS")
		}
	}
}

func (s *HTTP2Scanner) needMore(n, limit int) (*RoutedRequest, error) {
	if n > limit {
		return nil, &headError{kind: ErrTooLarge, msg: http2PrefixOverLimit}
	}
	s.need = n
	return nil, io.ErrUnexpectedEOF
}

func headersFragment(stream uint32, flags byte, payload []byte) ([]byte, error) {
	if stream%2 == 0 {
		return nil, malformed("expected an odd HTTP/2 request stream")
	}
	if flags&flagPadded != 0 {
		if len(payload) == 0 || int(payload[0]) >= len(payload) {
			return nil, malformed("HTTP/2 HEADERS padding")
		}
		payload = payload[1 : len(payload)-int(payload[0])]
	}
	if flags&flagPriority != 0 {
		if len(payload) < 5 || binary.BigEndian.Uint32(payload)&0x7fffffff == stream {
			return nil, malformed("HTTP/2 HEADERS priority")
		}
		payload = payload[5:]
	}
	return payload, nil
}

func validSettings(payload []byte) bool {
	for len(payload) >= 6 {
		id, v := binary.BigEndian.Uint16(payload), binary.BigEndian.Uint32(payload[2:])
		switch id {
		case 2, 8, 9:
			if v > 1 {
				return false
			}
		case 4:
			if v > 0x7fffffff {
				return false
			}
		case 5:
			if v < 16384 || v > 0xffffff {
				return false
			}
		}
		payload = payload[6:]
	}
	return len(payload) == 0
}

func beforeHeaders(typ byte, stream uint32, payload []byte) bool {
	switch typ {
	case 0, 3, 5, 7, frameContinuation: // DATA, RST_STREAM, PUSH_PROMISE, GOAWAY, CONTINUATION
		return false
	case 2: // PRIORITY
		return stream != 0 && len(payload) == 5 && binary.BigEndian.Uint32(payload)&0x7fffffff != stream
	case 6: // PING
		return stream == 0 && len(payload) == 8
	case 8: // WINDOW_UPDATE
		return stream == 0 && len(payload) == 4 && binary.BigEndian.Uint32(payload)&0x7fffffff != 0
	default:
		return true
	}
}

var pseudoFields = [...]string{pseudoMethod, pseudoPath, pseudoScheme, pseudoAuthority}

func (s *HTTP2Scanner) request(block []byte) (*RoutedRequest, error) {
	r := Request{Proto: "HTTP/2.0"}
	var scheme, authority string
	var seen [len(pseudoFields)]bool
	valid := true
	d := newHPACKDecoder()
	d.maxHeaderList = maxHeadBytes(s.MaxHeaderListBytes)
	err := d.decode(block, func(f hpackField) {
		if !valid {
			return
		}
		if !validHTTP2Field(f) {
			valid = false
			return
		}
		if f.name[0] != ':' {
			r.Header.Add(f.name, f.value)
			return
		}
		i := slices.Index(pseudoFields[:], f.name)
		if len(r.Header) != 0 || i < 0 || seen[i] {
			valid = false
			return
		}
		seen[i] = true
		switch f.name {
		case pseudoMethod:
			r.Method = f.value
		case pseudoPath:
			r.Target = f.value
		case pseudoScheme:
			scheme = f.value
		case pseudoAuthority:
			authority = f.value
		}
	})
	switch {
	case errors.Is(err, ErrTooLarge):
		return nil, err
	case err != nil:
		return nil, malformed("HTTP/2 HPACK block")
	case !valid || !ValidFieldName(r.Method):
		return nil, malformed("HTTP/2 request header fields")
	case r.Method == methodConnect:
		if seen[1] || seen[2] || authority == "" {
			return nil, malformed("HTTP/2 CONNECT pseudo-header fields")
		}
	case !isScheme(scheme) || r.Target != "*" && !strings.HasPrefix(r.Target, "/"):
		return nil, malformed("HTTP/2 request scheme or path")
	}
	return routeRequest(r, authority)
}

func validHTTP2Field(f hpackField) bool {
	name := strings.TrimPrefix(f.name, ":")
	if !ValidFieldName(name) || strings.ContainsAny(name, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") || TrimOWS(f.value) != f.value || !ValidFieldValue(f.value) {
		return false
	}
	switch name {
	case "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade":
		return false
	case "te":
		return strings.EqualFold(f.value, "trailers")
	}
	return true
}
