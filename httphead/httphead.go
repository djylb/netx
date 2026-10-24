// Package httphead reads and parses the heads of HTTP/1.x messages, the
// start line and the header fields, strictly where a lax reading lets two
// parties read one message in two ways, as in request smuggling, and
// leniently where that is safe (RFC 9110, RFC 9112). It also tells how a
// message's body is delimited and splits request targets. It reads
// nothing beyond the empty line that ends a head, so that the body and any
// next message stay in the reader, and it allocates one string per head,
// which the start line parts and the fields are substrings of.
//
// It depends on the standard library alone and has no package
// initialisation beyond a table, so that sniffers and servers can use it at
// a small cost; net/http's parser would add crypto/tls and the HTTP/2
// machinery to a program.
package httphead

import (
	"errors"
	"strings"
)

// Errors of reading and parsing. Parse errors match ErrMalformed, or one of
// the more precise errors, and carry a description.
var (
	// ErrMalformed reports a head that violates the syntax.
	ErrMalformed = errors.New("httphead: malformed message")
	// ErrTooLarge reports a head, line or section over its limit.
	ErrTooLarge = errors.New("httphead: head too large")
	// ErrVersion reports an HTTP version other than 1.x, such as HTTP/2.0,
	// which a server answers with 505 HTTP Version Not Supported.
	ErrVersion = errors.New("httphead: unsupported HTTP version")
	// ErrTransferCoding reports a request transfer coding other than
	// chunked alone, which a server answers with 501 Not Implemented.
	ErrTransferCoding = errors.New("httphead: unsupported transfer coding")
)

// headError is an error of one of the kinds above, with a description.
type headError struct {
	kind error
	msg  string
}

func (e *headError) Error() string { return e.kind.Error() + ": " + e.msg }
func (e *headError) Unwrap() error { return e.kind }

func malformed(msg string) error { return &headError{kind: ErrMalformed, msg: msg} }

// Field is a header field.
type Field struct {
	Name, Value string
}

// Header holds the fields of a head in the order they were sent, with their
// names as sent. Names are matched case-insensitively. The zero Header is
// empty and ready for use. Its methods all take a pointer, as Add, Set and
// Del change its length in place, and so are called on a Header held in a
// variable or a field.
type Header []Field

// Get returns the value of the first field named name, or "".
func (h *Header) Get(name string) string {
	for _, f := range *h {
		if strings.EqualFold(f.Name, name) {
			return f.Value
		}
	}
	return ""
}

// Values returns the values of the fields named name, in order.
func (h *Header) Values(name string) []string {
	var vs []string
	for _, f := range *h {
		if strings.EqualFold(f.Name, name) {
			vs = append(vs, f.Value)
		}
	}
	return vs
}

// Count returns the number of fields named name.
func (h *Header) Count(name string) int {
	n := 0
	for _, f := range *h {
		if strings.EqualFold(f.Name, name) {
			n++
		}
	}
	return n
}

// Has reports whether h has a field named name.
func (h *Header) Has(name string) bool {
	for _, f := range *h {
		if strings.EqualFold(f.Name, name) {
			return true
		}
	}
	return false
}

// HasToken reports whether the comma-separated lists in the fields named
// name hold token, case-insensitively, as for "Connection: keep-alive,
// Upgrade".
func (h *Header) HasToken(name, token string) bool {
	for _, f := range *h {
		if strings.EqualFold(f.Name, name) {
			for t := range Tokens(f.Value) {
				if strings.EqualFold(t, token) {
					return true
				}
			}
		}
	}
	return false
}

// Add appends a field.
func (h *Header) Add(name, value string) {
	*h = append(*h, Field{Name: name, Value: value})
}

// Set replaces the fields named name with one field, in the place of the
// first of them, or appends it.
func (h *Header) Set(name, value string) {
	for i, f := range *h {
		if strings.EqualFold(f.Name, name) {
			(*h)[i].Value = value
			h.del(name, i+1)
			return
		}
	}
	h.Add(name, value)
}

// Del removes the fields named name.
func (h *Header) Del(name string) { h.del(name, 0) }

func (h *Header) del(name string, from int) {
	out := (*h)[:from]
	for _, f := range (*h)[from:] {
		if !strings.EqualFold(f.Name, name) {
			out = append(out, f)
		}
	}
	clear((*h)[len(out):])
	*h = out
}

// AppendTo appends the fields to b as header lines, "Name: value" and CRLF
// each. It returns ErrMalformed, and b as it was, when a name is not a
// token or a value holds a byte a field value cannot, such as CR or LF, so
// that no field can add a line.
func (h *Header) AppendTo(b []byte) ([]byte, error) {
	n := len(b)
	for _, f := range *h {
		if !ValidFieldName(f.Name) || !ValidFieldValue(f.Value) {
			return b[:n], malformed("invalid header field " + quote(f.Name))
		}
		b = append(b, f.Name...)
		b = append(b, ": "...)
		b = append(b, f.Value...)
		b = append(b, "\r\n"...)
	}
	return b, nil
}

// tokenChars marks the bytes of a token (RFC 9110, section 5.6.2).
var tokenChars = func() (t [256]bool) {
	for c := '0'; c <= '9'; c++ {
		t[c] = true
	}
	for c := 'a'; c <= 'z'; c++ {
		t[c] = true
		t[c-'a'+'A'] = true
	}
	for _, c := range "!#$%&'*+-.^_`|~" {
		t[c] = true
	}
	return t
}()

// ValidFieldName reports whether s is a token, as a field name or a method
// must be (RFC 9110, section 5.6.2).
func ValidFieldName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !tokenChars[s[i]] {
			return false
		}
	}
	return true
}

// ValidFieldValue reports whether s may be a field value: visible ASCII,
// spaces, tabs and bytes from 0x80, without other control characters
// (RFC 9110, section 5.5).
func ValidFieldValue(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < ' ' && c != '\t' || c == 0x7f {
			return false
		}
	}
	return true
}

// TrimOWS returns s without leading and trailing spaces and tabs.
func TrimOWS(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

// Tokens returns the elements of the comma-separated list s, with
// whitespace trimmed and empty elements skipped (RFC 9110, section 5.6.1).
func Tokens(s string) func(yield func(string) bool) {
	return func(yield func(string) bool) {
		for s != "" {
			var t string
			t, s, _ = strings.Cut(s, ",")
			if t = TrimOWS(t); t != "" && !yield(t) {
				return
			}
		}
	}
}

// quote quotes s for an error message, bounded.
func quote(s string) string {
	const limit = 64
	if len(s) > limit {
		s = s[:limit] + "..."
	}
	b := make([]byte, 0, len(s)+2)
	b = append(b, '"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"' || c == '\\':
			b = append(b, '\\', c)
		case c < ' ' || c >= 0x7f:
			b = append(b, '\\', 'x', "0123456789abcdef"[c>>4], "0123456789abcdef"[c&15])
		default:
			b = append(b, c)
		}
	}
	return string(append(b, '"'))
}
