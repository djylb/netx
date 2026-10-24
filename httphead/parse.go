package httphead

import (
	"bufio"
	"errors"
	"io"
	"strings"
)

// Read reads a message head, the start line and the header fields up to and
// including the empty line, from r into buf, reusing its storage, and
// returns it; at most limit bytes, counting empty lines before the start
// line, which it skips (RFC 9112, section 2.2). Lines may be longer than
// r's buffer. It returns io.EOF when r ends before any byte of a start
// line, io.ErrUnexpectedEOF when it ends inside a head, and ErrTooLarge for
// a head over limit bytes; what it read so far is returned with the error.
func Read(r *bufio.Reader, buf []byte, limit int) ([]byte, error) {
	buf = buf[:0]
	read := 0
	lineStart := 0
	for {
		frag, err := r.ReadSlice('\n')
		read += len(frag)
		if read > limit {
			return buf, &headError{kind: ErrTooLarge, msg: "over the limit"}
		}
		buf = append(buf, frag...)
		switch {
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case err != nil:
			if err == io.EOF {
				if len(buf) == 0 {
					return buf, io.EOF
				}
				err = io.ErrUnexpectedEOF
			}
			return buf, err
		}
		line := buf[lineStart:]
		if len(line) == 1 || len(line) == 2 && line[0] == '\r' {
			if lineStart == 0 {
				buf = buf[:0] // an empty line before the start line
				continue
			}
			return buf, nil
		}
		lineStart = len(buf)
	}
}

// Request is a parsed request head.
type Request struct {
	// Method is the method as sent; methods are case-sensitive.
	Method string
	// Target is the request-target as sent; see ParseTarget.
	Target string
	// Proto is the version as sent, such as "HTTP/1.1".
	Proto string
	// Minor is the minor version: 0 for HTTP/1.0, 1 for HTTP/1.1 and later
	// minor versions, which are compatible with it (RFC 9110, section 2.5).
	Minor  int
	Header Header
}

// Response is a parsed response head.
type Response struct {
	Proto string
	Minor int
	// Code is the status code, from 100 to 999.
	Code int
	// Reason is the reason phrase as sent, which may be empty.
	Reason string
	Header Header
}

// ParseRequest parses a request head as Read returns it, converted to a
// string. The fields are appended to fields, which may be nil, reusing its
// storage. See ParseHeader for what is accepted. The request line is method,
// target and version separated by single spaces; the target cannot hold
// spaces or control characters.
func ParseRequest(head string, fields Header) (Request, error) {
	first, h, err := split(head, fields)
	if err != nil {
		return Request{}, err
	}
	method, rest, ok1 := strings.Cut(first, " ")
	target, proto, ok2 := strings.Cut(rest, " ")
	if !ok1 || !ok2 || !ValidFieldName(method) || target == "" {
		return Request{}, malformed("request line " + quote(first))
	}
	for i := 0; i < len(target); i++ {
		if c := target[i]; c <= ' ' || c >= 0x7f {
			return Request{}, malformed("request target " + quote(target))
		}
	}
	minor, err := ParseVersion(proto)
	if err != nil {
		return Request{}, err
	}
	return Request{Method: method, Target: target, Proto: proto, Minor: minor, Header: h}, nil
}

// ParseResponse parses a response head as Read returns it, converted to a
// string, appending the fields to fields as ParseRequest does. The status
// line is the version, a three-digit code and an optional reason phrase,
// which may hold spaces.
func ParseResponse(head string, fields Header) (Response, error) {
	first, h, err := split(head, fields)
	if err != nil {
		return Response{}, err
	}
	proto, rest, _ := strings.Cut(first, " ")
	codeStr, reason, _ := strings.Cut(rest, " ")
	minor, err := ParseVersion(proto)
	if err != nil {
		return Response{}, err
	}
	if len(codeStr) != 3 {
		return Response{}, malformed("status line " + quote(first))
	}
	code := 0
	for i := 0; i < 3; i++ {
		c := codeStr[i]
		if c < '0' || c > '9' {
			return Response{}, malformed("status line " + quote(first))
		}
		code = code*10 + int(c-'0')
	}
	if code < 100 {
		return Response{}, malformed("status code " + quote(codeStr))
	}
	return Response{Proto: proto, Minor: minor, Code: code, Reason: reason, Header: h}, nil
}

// ParseHeader parses header field lines, such as a trailer section,
// appending them to fields. Lines end in CRLF or in LF alone (RFC 9112,
// section 2.2); an empty line ends the section and must be the last. It
// refuses what would let two readers disagree on the fields: a CR other
// than before LF, a line that starts with whitespace (obsolete line
// folding), whitespace before the colon, a name that is not a token, and
// control characters in a value. Values have their surrounding whitespace
// trimmed.
func ParseHeader(lines string, fields Header) (Header, error) {
	for len(lines) > 0 {
		line, rest, err := nextLine(lines)
		if err != nil {
			return fields, err
		}
		lines = rest
		if line == "" {
			if lines != "" {
				return fields, malformed("data after the empty line")
			}
			break
		}
		f, err := parseField(line)
		if err != nil {
			return fields, err
		}
		fields = append(fields, f)
	}
	return fields, nil
}

// split splits a head into its start line and fields.
func split(head string, fields Header) (string, Header, error) {
	first, rest, err := nextLine(head)
	if err != nil {
		return "", fields, err
	}
	if first == "" {
		return "", fields, malformed("no start line")
	}
	if !ValidFieldValue(first) {
		return "", fields, malformed("start line " + quote(first))
	}
	h, err := ParseHeader(rest, fields)
	return first, h, err
}

// nextLine returns the first line of s, without its ending, and the rest.
func nextLine(s string) (string, string, error) {
	i := strings.IndexByte(s, '\n')
	if i < 0 {
		return "", "", malformed("unterminated line")
	}
	line := s[:i]
	if n := len(line); n > 0 && line[n-1] == '\r' {
		line = line[:n-1]
	}
	if strings.IndexByte(line, '\r') >= 0 {
		return "", "", malformed("CR inside a line")
	}
	return line, s[i+1:], nil
}

// parseField parses a field line "name: value".
func parseField(line string) (Field, error) {
	if line[0] == ' ' || line[0] == '\t' {
		return Field{}, malformed("obsolete line folding")
	}
	colon := strings.IndexByte(line, ':')
	if colon <= 0 {
		return Field{}, malformed("header line " + quote(line))
	}
	name := line[:colon]
	if !ValidFieldName(name) {
		return Field{}, malformed("header field name " + quote(name))
	}
	value := TrimOWS(line[colon+1:])
	if !ValidFieldValue(value) {
		return Field{}, malformed("value of header field " + quote(name))
	}
	return Field{Name: name, Value: value}, nil
}

// ParseVersion parses "HTTP/1.x" and returns the minor version, 1 for any x
// from 1. Other versions of the right form, such as "HTTP/2.0", give
// ErrVersion, and anything else ErrMalformed; the version is
// case-sensitive.
func ParseVersion(v string) (int, error) {
	switch {
	case len(v) == 8 && strings.HasPrefix(v, "HTTP/") && v[6] == '.' && isDigit(v[5]) && isDigit(v[7]):
		switch {
		case v[5] == '1' && v[7] == '0':
			return 0, nil
		case v[5] == '1':
			return 1, nil
		case v[5] > '1':
			return 0, &headError{kind: ErrVersion, msg: quote(v)}
		}
	case v == "HTTP/2" || v == "HTTP/3":
		return 0, &headError{kind: ErrVersion, msg: quote(v)}
	}
	return 0, malformed("version " + quote(v))
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
