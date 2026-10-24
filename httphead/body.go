package httphead

import "strings"

// Framing is how the body of a message is delimited (RFC 9112, section 6).
type Framing uint8

const (
	// NoBody means the message has no body.
	NoBody Framing = iota
	// Length means the body is as long as Content-Length says.
	Length
	// Chunked means the body is in chunks, its last transfer coding.
	Chunked
	// UntilClose means the body of a response ends when the connection does.
	UntilClose
)

func (f Framing) String() string {
	switch f {
	case NoBody:
		return "no body"
	case Length:
		return "length"
	case Chunked:
		return "chunked"
	case UntilClose:
		return "until close"
	}
	return "unknown"
}

// RequestBody returns how the body of a request with header h and minor
// version minor is delimited, and the length for Length. It refuses what a
// recipient could read in two ways: Transfer-Encoding with Content-Length,
// Transfer-Encoding in HTTP/1.0 (RFC 9112, section 6.1), and invalid or
// differing Content-Length values, of which equal ones in a list or in
// several fields are taken as one (section 6.3). A transfer coding other
// than chunked alone gives ErrTransferCoding. A Content-Length of 0 is
// NoBody.
func RequestBody(h Header, minor int) (Framing, int64, error) {
	te, length, hasLength, err := framingFields(h)
	switch {
	case err != nil:
		return 0, 0, err
	case te == "" && hasLength && length > 0:
		return Length, length, nil
	case te == "":
		return NoBody, 0, nil
	case hasLength:
		return 0, 0, malformed("both Transfer-Encoding and Content-Length")
	case minor == 0:
		return 0, 0, malformed("Transfer-Encoding in an HTTP/1.0 request")
	case !strings.EqualFold(te, "chunked"):
		return 0, 0, &headError{kind: ErrTransferCoding, msg: quote(te)}
	}
	return Chunked, 0, nil
}

// ResponseBody returns how the body of a response with code code and
// header h to a request with method method is delimited, the length for
// Length, and, for Chunked and UntilClose, the transfer codings other than
// chunked as sent, such as "gzip", which the body is still encoded with. A
// response to HEAD and one with a 1xx, 204 or 304 code has no body, whatever
// its fields say. Transfer-Encoding overrides Content-Length (RFC 9112,
// section 6.3); a list that does not end in chunked is read until close,
// and one that holds chunked before its end is an error, as are invalid or
// differing Content-Length values. A response with neither is read until
// close.
func ResponseBody(method string, code int, h Header) (Framing, int64, string, error) {
	if method == "HEAD" || code < 200 || code == 204 || code == 304 {
		return NoBody, 0, "", nil
	}
	te, length, hasLength, err := framingFields(h)
	switch {
	case err != nil && te == "":
		return 0, 0, "", err
	case te != "":
		codings, last := "", te
		if i := strings.LastIndexByte(te, ','); i >= 0 {
			codings, last = TrimOWS(te[:i]), TrimOWS(te[i+1:])
		}
		for t := range Tokens(codings) {
			if strings.EqualFold(t, "chunked") {
				return 0, 0, "", malformed("chunked before the last transfer coding")
			}
		}
		if strings.EqualFold(last, "chunked") {
			return Chunked, 0, codings, nil
		}
		return UntilClose, 0, te, nil
	case hasLength && length > 0:
		return Length, length, "", nil
	case hasLength:
		return NoBody, 0, "", nil
	}
	return UntilClose, 0, "", nil
}

// framingFields returns the transfer codings, all Transfer-Encoding fields
// joined, and the Content-Length.
func framingFields(h Header) (te string, length int64, hasLength bool, err error) {
	length = -1
	for _, f := range h {
		switch {
		case strings.EqualFold(f.Name, "Transfer-Encoding"):
			v := f.Value
			if v == "" {
				err = malformed("empty Transfer-Encoding")
				continue
			}
			if te != "" {
				te += ", "
			}
			te += v
		case strings.EqualFold(f.Name, "Content-Length"):
			empty := true
			for t := range Tokens(f.Value) {
				empty = false
				n, ok := parseLength(t)
				if !ok || hasLength && n != length {
					err = malformed("Content-Length " + quote(f.Value))
					break
				}
				length, hasLength = n, true
			}
			if empty {
				err = malformed("empty Content-Length")
			}
		}
	}
	return te, length, hasLength, err
}

// parseLength parses a Content-Length value, decimal digits only.
func parseLength(s string) (int64, bool) {
	if s == "" || len(s) > 18 { // longer might not fit an int64
		return 0, false
	}
	var n int64
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return 0, false
		}
		n = n*10 + int64(s[i]-'0')
	}
	return n, true
}

// ParseChunkSize parses the chunk-size line of a chunked body, without its
// line ending: hexadecimal digits, then nothing or chunk extensions after a
// semicolon, which are checked for control characters and otherwise
// ignored (RFC 9112, section 7.1.1).
func ParseChunkSize(line []byte) (int64, error) {
	var size int64
	i := 0
	for ; i < len(line); i++ {
		c := line[i]
		var d byte
		switch {
		case isDigit(c):
			d = c - '0'
		case c|0x20 >= 'a' && c|0x20 <= 'f':
			d = c | 0x20 - 'a' + 10
		default:
			goto ext
		}
		if size > (1<<63-1)>>4 {
			return 0, &headError{kind: ErrTooLarge, msg: "chunk size"}
		}
		size = size<<4 | int64(d)
	}
ext:
	if i == 0 {
		return 0, malformed("chunk size " + quote(string(line)))
	}
	rest := line[i:]
	for len(rest) > 0 && (rest[0] == ' ' || rest[0] == '\t') {
		rest = rest[1:]
	}
	if len(rest) > 0 && rest[0] != ';' {
		return 0, malformed("chunk extension")
	}
	for _, c := range rest {
		if c < ' ' && c != '\t' || c == 0x7f {
			return 0, malformed("chunk extension")
		}
	}
	return size, nil
}
