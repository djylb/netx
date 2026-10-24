// Package httprewrite rewrites the header fields of HTTP requests and
// responses with templates, for reverse proxies and servers: templates
// such as "${scheme}://${host}${request_uri}" in the style of the variables
// of common reverse proxies are compiled once and expanded per request, rule
// lists set, add and delete request and response fields, and redirects in
// Location and Refresh are rewritten from the backend's address to the
// public one.
//
// Variables read a Context: the request as the client sent it, the
// response for response rules, the client as the forwarded package finds
// it, and the caller's own data, which variables the caller defines read,
// so that the package knows nothing of a program's configuration. Unknown
// variables are compile errors. An expansion that would put a control
// character other than tab in a field value, such as CR or LF from a
// decoded path, fails instead, so that no variable can inject a field.
//
// # Variables
//
// Templates may use the caller's Vars and these built-in variables.
// Request variables read Context.Request and are empty without it; below,
// "client" is Context.Client, or the TCP peer when that is unset, and
// "peer" is the TCP peer, from Request.RemoteAddr.
//
//	scheme                     "https" for a request over TLS, else "http"
//	https                      "on" for a request over TLS, else ""
//	host                       the Host without its port, in lower case
//	                           (the URL's host when the Host is empty)
//	request_method             the method
//	request_uri                the target as sent, such as "/a%20b?x=1"
//	uri                        the decoded path, such as "/a b"
//	args, query_string         the query without "?", as sent
//	is_args                    "?" when there is a query, else ""
//	remote_addr, remote_ip     the client's IP address
//	remote_port                the client's port, "" when unknown
//	peer_addr, peer_port       the TCP peer's IP address and port
//	server_addr, server_port   the local address the request came in on
//	forwarded_proto            the client's scheme: Client.Proto, else scheme
//	forwarded_host             the client's Host: Client.Host, else the Host
//	proxy_add_x_forwarded_for  the request's X-Forwarded-For lines joined,
//	                           with the TCP peer's address appended
//	proxy_add_forwarded        the request's Forwarded lines joined, with an
//	                           element for this hop appended: for the TCP
//	                           peer's address, host and proto of the request
//	http_NAME                  the first request field NAME, with "_" for
//	                           "-", such as http_user_agent; http_host is
//	                           the Host
//	cookie_NAME                the value of cookie NAME, as sent
//	arg_NAME                   the value of query parameter NAME, as sent
//	status                     the response status code, such as "302"
//	upstream_http_NAME         the first response field NAME
//	msec                       the Unix time in seconds with milliseconds
//	time_iso8601               the time in RFC 3339, such as
//	                           "2006-01-02T15:04:05+07:00"
//	time_http                  the time as HTTP dates are written
//
// Field names, cookie names and parameter names are as the variable name
// gives them, except for the "-" of field names; field names are matched
// without regard to case, cookie and parameter names exactly. Values are
// not decoded.
//
// # Reverse proxies
//
// Rewriter applies the rules from the Rewrite and ModifyResponse hooks of
// httputil.ReverseProxy. Use Rewrite, not Director: ReverseProxy removes
// the hop-by-hop fields (Connection, Keep-Alive, Proxy-Connection,
// Proxy-Authenticate, Proxy-Authorization, Te, Trailer, Transfer-Encoding,
// Upgrade and the fields that Connection names) after Director runs and
// before Rewrite runs, so rules applied in Director on those fields are
// lost, while rules applied in Rewrite are sent as they are. Before
// Rewrite, ReverseProxy also puts back "Connection: Upgrade" and the
// Upgrade field of an upgrade request such as a WebSocket handshake, and
// deletes the Forwarded and X-Forwarded-* fields that the client sent.
// Variables read the inbound request, which still has all of them, so
// rules such as
//
//	X-Forwarded-For: ${proxy_add_x_forwarded_for}
//	X-Forwarded-Proto: ${scheme}
//
// pass the forwarding fields on with this hop added, and ${http_upgrade}
// and ${http_connection} see what the client sent. A rule that sets
// Connection or Upgrade replaces what ReverseProxy put back: deleting
// Upgrade from an upgrade request makes it an ordinary request, and an
// upgrade that the backend then accepts with a different protocol is
// refused by ReverseProxy. "Connection: close" makes the transport close
// the backend connection after the response. Content-Length,
// Transfer-Encoding and Trailer of a request are written from its body
// framing, so rules on them have no effect.
//
// ModifyResponse sees a response without its hop-by-hop fields, except a
// 101 Switching Protocols response, which keeps its Connection and
// Upgrade; response rules must leave those as they are, as ReverseProxy
// checks that the backend switched to the protocol the client asked for. A
// "Connection: close" set on a response makes the server close the client
// connection after it.
package httprewrite

import (
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/djylb/netx/forwarded"
)

// Errors of compiling and expanding. They match one of these and carry a
// description.
var (
	// ErrSyntax reports a template or rule that does not parse, such as an
	// unclosed "${".
	ErrSyntax = errors.New("httprewrite: syntax error")
	// ErrUnknownVariable reports a variable that is neither built in nor
	// in the caller's Vars.
	ErrUnknownVariable = errors.New("httprewrite: unknown variable")
	// ErrInvalidValue reports a template literal or an expansion with a
	// character that a field value cannot carry: a control character other
	// than tab.
	ErrInvalidValue = errors.New("httprewrite: invalid field value")
)

type rewriteError struct {
	kind error
	msg  string
}

func (e *rewriteError) Error() string { return e.kind.Error() + ": " + e.msg }
func (e *rewriteError) Unwrap() error { return e.kind }

// Context holds what variables read for one request.
type Context struct {
	// Request is the request as the client sent it: for a reverse proxy,
	// the inbound request, not the outbound one being rewritten.
	Request *http.Request
	// Response is the response for response rules, nil for request rules.
	// Response variables are empty without it.
	Response *http.Response
	// Client is the client of the request, as a forwarded.Resolver finds
	// it. When its Addr is invalid, the client is the TCP peer of Request.
	Client forwarded.Client
	// Time is the time of the time variables, time.Now() when zero.
	Time time.Time
	// Data holds the caller's facts for the variables it defines, such as
	// the configuration of the matched route.
	Data any
}

// Func appends the value of a variable for c to dst. It must not modify c.
type Func func(dst []byte, c *Context) []byte

// Vars maps the names of the caller's variables to their functions. They
// are looked up before the built-in variables, so they may replace one.
type Vars map[string]Func

// Template is a compiled template: text in which ${name} is replaced by
// the value of the variable name, and $$ by $. A $ before anything else is
// itself. A Template is immutable and safe for concurrent use.
type Template struct {
	src  string
	segs []segment
	lit  bool // segs is one literal, or none
}

// segment is a literal (all functions nil) or a variable.
type segment struct {
	lit string
	str func(c *Context, arg string) string
	app func(dst []byte, c *Context, arg string) []byte
	fn  Func
	arg string // the argument of a variable family, such as a header name
}

// Compile compiles a template, resolving its variables in vars and the
// built-in ones. Variable names consist of ASCII letters, digits and
// underscores and are case-sensitive.
func Compile(src string, vars Vars) (*Template, error) {
	t := &Template{src: src}
	var lit strings.Builder
	flush := func() {
		if lit.Len() > 0 {
			t.segs = append(t.segs, segment{lit: lit.String()})
			lit.Reset()
		}
	}
	for i := 0; i < len(src); {
		c := src[i]
		if c < ' ' && c != '\t' || c == 0x7f {
			return nil, &rewriteError{ErrInvalidValue, "control character in template " + quote(src)}
		}
		if c != '$' || i+1 == len(src) {
			lit.WriteByte(c)
			i++
			continue
		}
		switch src[i+1] {
		case '$':
			lit.WriteByte('$')
			i += 2
			continue
		case '{':
		default:
			lit.WriteByte('$')
			i++
			continue
		}
		end := strings.IndexByte(src[i+2:], '}')
		if end < 0 {
			return nil, &rewriteError{ErrSyntax, "unclosed ${ in template " + quote(src)}
		}
		name := src[i+2 : i+2+end]
		if !validName(name) {
			return nil, &rewriteError{ErrSyntax, "invalid variable name " + quote(name) + " in template " + quote(src)}
		}
		seg, ok := lookup(name, vars)
		if !ok {
			return nil, &rewriteError{ErrUnknownVariable, quote(name) + " in template " + quote(src)}
		}
		flush()
		t.segs = append(t.segs, seg)
		i += end + 3
	}
	flush()
	t.lit = len(t.segs) == 0 || len(t.segs) == 1 && t.segs[0].isLit()
	return t, nil
}

// MustCompile is Compile for templates known to be valid, such as
// constants; it panics on an error.
func MustCompile(src string, vars Vars) *Template {
	t, err := Compile(src, vars)
	if err != nil {
		panic(err)
	}
	return t
}

func (s *segment) isLit() bool { return s.str == nil && s.app == nil && s.fn == nil }

func validName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

// String returns the source of the template.
func (t *Template) String() string { return t.src }

// Append appends the expansion of t for c to dst. If a variable's value has
// a character that a field value cannot carry, it returns dst unchanged
// and an error matching ErrInvalidValue. It allocates only to grow dst.
func (t *Template) Append(dst []byte, c *Context) ([]byte, error) {
	n := len(dst)
	for i := range t.segs {
		s := &t.segs[i]
		start := len(dst)
		switch {
		case s.str != nil:
			dst = append(dst, s.str(c, s.arg)...)
		case s.app != nil:
			dst = s.app(dst, c, s.arg)
		case s.fn != nil:
			dst = s.fn(dst, c)
		default:
			dst = append(dst, s.lit...)
			continue
		}
		if !validValue(dst[start:]) {
			return dst[:n], t.invalid()
		}
	}
	return dst, nil
}

// Expand returns the expansion of t for c, or an error as Append does. It
// allocates the string it returns, and nothing for a template without
// variables or one that is a single variable whose value is a string the
// request holds, such as "${http_host}".
func (t *Template) Expand(c *Context) (string, error) {
	switch {
	case t.lit:
		if len(t.segs) == 0 {
			return "", nil
		}
		return t.segs[0].lit, nil
	case len(t.segs) == 1 && t.segs[0].str != nil:
		s := t.segs[0].str(c, t.segs[0].arg)
		if !validValue(s) {
			return "", t.invalid()
		}
		return s, nil
	}
	bp := getBuf()
	defer putBuf(bp)
	b, err := t.Append((*bp)[:0], c)
	*bp = b
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// bufPool holds expansion buffers: a buffer passed to variable functions
// escapes, so a stack buffer would be allocated on every expansion.
var bufPool = sync.Pool{New: func() any { b := make([]byte, 0, 256); return &b }}

func getBuf() *[]byte { return bufPool.Get().(*[]byte) }

func putBuf(b *[]byte) {
	if cap(*b) <= 64<<10 { // do not keep buffers that a huge value grew
		bufPool.Put(b)
	}
}

func (t *Template) invalid() error {
	return &rewriteError{ErrInvalidValue, "control character in the expansion of " + quote(t.src)}
}

// validValue reports whether s has no control character other than tab.
func validValue[T string | []byte](s T) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < ' ' && c != '\t' || c == 0x7f {
			return false
		}
	}
	return true
}

// quote quotes s for an error message without strconv's escapes of
// non-ASCII text, which a template may legitimately hold.
func quote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '"' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c < ' ' || c == 0x7f:
			const hex = "0123456789abcdef"
			b.WriteString(`\x`)
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&15])
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}
