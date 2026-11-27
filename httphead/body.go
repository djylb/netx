package httphead

import (
	"strconv"
	"strings"

	"github.com/djylb/netx/internal/httptoken"
)

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
	te, _, err := transferEncoding(h, false)
	if err != nil {
		return 0, 0, err
	}
	length, hasLength, err := ContentLength(h)
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

// ResponseBody determines response framing from the request method, response
// status code and header. It returns the body length for Length. For Chunked
// and UntilClose, it returns the other transfer codings still applied to the
// body, such as "gzip". Responses to HEAD, successful CONNECT responses, and
// responses with a 1xx, 204 or 304 status have no body regardless of their
// headers. Transfer-Encoding overrides Content-Length (RFC 9112,
// section 6.3); a list that does not end in chunked is read until close,
// and one that holds chunked before its end is an error, as are invalid or
// differing Content-Length values. A response with neither is read until
// close.
func ResponseBody(method string, code int, h Header) (Framing, int64, string, error) {
	if method == "HEAD" || code < 200 || code == 204 || code == 304 || method == methodConnect && code/100 == 2 {
		return NoBody, 0, "", nil
	}
	te, final, err := transferEncoding(h, true)
	switch {
	case err != nil:
		return 0, 0, "", err
	case te != "":
		if strings.EqualFold(te[final:], "chunked") {
			codings := ""
			if final > 0 {
				codings = te[:final-2]
			}
			return Chunked, 0, codings, nil
		}
		return UntilClose, 0, te, nil
	}
	length, hasLength, err := ContentLength(h)
	switch {
	case err != nil:
		return 0, 0, "", err
	case hasLength && length > 0:
		return Length, length, "", nil
	case hasLength:
		return NoBody, 0, "", nil
	}
	return UntilClose, 0, "", nil
}

// transferEncoding joins coding elements and records the start of the last one.
// Commas inside quoted parameters belong to the value, including after an escape.
func transferEncoding(h Header, response bool) (string, int, error) {
	var enc strings.Builder
	var final int
	var chunked bool
	for _, f := range h {
		if !strings.EqualFold(f.Name, "Transfer-Encoding") {
			continue
		}
		value := f.Value
		for {
			coding, rest, ok := cutCoding(value)
			if !ok {
				return "", 0, malformed("invalid Transfer-Encoding")
			}
			if response && chunked {
				return "", 0, malformed("chunked before the last transfer coding")
			}
			if enc.Len() > 0 {
				enc.WriteString(", ")
			}
			final = enc.Len()
			enc.WriteString(coding)
			chunked = strings.EqualFold(coding, "chunked")
			if rest == "" {
				break
			}
			value = rest[1:]
		}
	}
	return enc.String(), final, nil
}

// cutCoding consumes one transfer coding and its parameters up to the next comma.
func cutCoding(value string) (coding, rest string, ok bool) {
	start := strings.TrimLeft(value, " \t")
	name, rest := cutToken(start)
	if name == "" {
		return "", "", false
	}
	for {
		rest = strings.TrimLeft(rest, " \t")
		if rest == "" || rest[0] == ',' {
			return strings.TrimRight(start[:len(start)-len(rest)], " \t"), rest, true
		}
		if rest[0] != ';' || strings.EqualFold(name, "chunked") {
			return "", "", false
		}
		key, tail := cutToken(strings.TrimLeft(rest[1:], " \t"))
		tail = strings.TrimLeft(tail, " \t")
		if key == "" || tail == "" || tail[0] != '=' {
			return "", "", false
		}
		rest, ok = cutParameterValue(strings.TrimLeft(tail[1:], " \t"))
		if !ok {
			return "", "", false
		}
	}
}

func cutToken(s string) (token, rest string) {
	i := 0
	for i < len(s) && httptoken.Contains(s[i]) {
		i++
	}
	return s[:i], s[i:]
}

func cutParameterValue(s string) (string, bool) {
	if s == "" || s[0] != '"' {
		token, rest := cutToken(s)
		return rest, token != ""
	}
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '"':
			return s[i+1:], true
		case '\\':
			i++
			if i == len(s) {
				return "", false
			}
		}
		if !ValidFieldValue(s[i : i+1]) {
			return "", false
		}
	}
	return "", false
}

// ContentLength returns the validated length and whether the field is present.
func ContentLength(h Header) (length int64, hasLength bool, err error) {
	for _, f := range h {
		if strings.EqualFold(f.Name, "Content-Length") {
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
	return length, hasLength, err
}

// parseLength parses a Content-Length value, decimal digits only.
func parseLength(s string) (int64, bool) {
	n, err := strconv.ParseUint(s, 10, 63)
	return int64(n), err == nil
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
	if !ValidFieldValue(rest) {
		return 0, malformed("chunk extension")
	}
	return size, nil
}
