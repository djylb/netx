package httphead

import (
	"bytes"
	"errors"
	"io"

	"github.com/djylb/netx/internal/httptoken"
)

const defaultMaxHeadBytes = 64 << 10

// ScanRequest parses the first HTTP/1.x request head in data. Trailing body
// or pipelined bytes are ignored. It returns io.ErrUnexpectedEOF for a
// partial head and ErrTooLarge for a head exceeding 64 KiB. Use Scanner to
// set the limit or to process successive prefixes.
func ScanRequest(data []byte) (*RoutedRequest, error) {
	var s Scanner
	return s.Scan(data)
}

const (
	scanMethod uint8 = iota
	scanLeadingLF
	scanTarget
	scanVersion
	scanFields
)

// Scanner incrementally recognises and parses an HTTP/1.x request head for
// routing. The zero value is ready to use. Use one scanner per input stream.
// A scanner is single-owner and requires no cleanup.
type Scanner struct {
	// MaxBytes bounds the head and leading empty lines. A nonpositive value
	// uses 64 KiB. Set it before the first Scan for a request.
	MaxBytes int

	result      *RoutedRequest
	err         error
	pos         int
	headStart   int
	lineStart   int
	targetStart int
	protoStart  int
	phase       uint8
}

// Reset prepares the scanner for a new request and preserves its limit.
func (s *Scanner) Reset() { *s = Scanner{MaxBytes: s.MaxBytes} }

// Need returns the minimum length at which Scan can make progress after
// io.ErrUnexpectedEOF.
func (s *Scanner) Need() int { return s.pos + 1 }

// Scan parses a buffer containing the bytes seen so far. After
// io.ErrUnexpectedEOF, call Scan again with the previous prefix followed by
// new bytes. Scan retains no reference to the input buffer. After success
// or a terminal error, it returns the same result until Reset.
func (s *Scanner) Scan(data []byte) (*RoutedRequest, error) {
	if s.result != nil || s.err != nil {
		return s.result, s.err
	}
	limit := maxHeadBytes(s.MaxBytes)
	result, err := s.scan(data[:min(len(data), limit)])
	if errors.Is(err, io.ErrUnexpectedEOF) {
		if len(data) < limit {
			return nil, err
		}
		err = &headError{kind: ErrTooLarge, msg: "request head over the limit"}
	}
	s.result, s.err = result, err
	return result, err
}

func (s *Scanner) scan(data []byte) (*RoutedRequest, error) {
	for s.pos < len(data) {
		c := data[s.pos]
		switch s.phase {
		case scanMethod:
			switch {
			case s.pos == s.headStart && c == '\r':
				s.phase = scanLeadingLF
			case s.pos == s.headStart && c == '\n':
				s.headStart = s.pos + 1
			case httptoken.Contains(c):
			case c == ' ' && s.pos > s.headStart:
				s.targetStart, s.phase = s.pos+1, scanTarget
			default:
				return nil, malformed("request method")
			}
		case scanLeadingLF:
			if c != '\n' {
				return nil, malformed("CR inside the start line")
			}
			s.headStart, s.phase = s.pos+1, scanMethod
		case scanTarget:
			switch {
			case targetByte(c):
			case c == ' ' && s.pos > s.targetStart:
				s.protoStart, s.phase = s.pos+1, scanVersion
			default:
				return nil, malformed("request target")
			}
		case scanVersion:
			const prefix = "HTTP/1."
			i := s.pos - s.protoStart
			switch {
			case i < len(prefix):
				if c != prefix[i] {
					if i == len("HTTP/") && c >= '2' && c <= '9' {
						return nil, &headError{kind: ErrVersion, msg: "expected HTTP/1.x"}
					}
					return nil, malformed("request version")
				}
			case i == len(prefix):
				if !isDigit(c) {
					return nil, malformed("request version")
				}
			case c == '\n' && (i == len(prefix)+1 || i == len(prefix)+2 && data[s.pos-1] == '\r'):
				s.lineStart, s.phase = s.pos+1, scanFields
			case c != '\r' || i != len(prefix)+1:
				return nil, malformed("request line ending")
			}
		case scanFields:
			nl := bytes.IndexByte(data[s.pos:], '\n')
			if nl < 0 {
				s.pos = len(data)
				return nil, io.ErrUnexpectedEOF
			}
			s.pos += nl
			line := bytes.TrimSuffix(data[s.lineStart:s.pos], []byte{'\r'})
			if len(line) == 0 {
				r, err := ParseRequest(string(data[s.headStart:s.pos+1]), nil)
				if err != nil {
					return nil, err
				}
				return routeRequest(r, "")
			}
			if _, _, err := parseField(line, bytes.IndexByte(line, ':')); err != nil {
				return nil, err
			}
			s.lineStart = s.pos + 1
		}
		s.pos++
	}
	return nil, io.ErrUnexpectedEOF
}

func maxHeadBytes(limit int) int {
	if limit > 0 {
		return limit
	}
	return defaultMaxHeadBytes
}
