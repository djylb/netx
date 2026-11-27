package httphead

import (
	"net/url"
	"path"
	"strings"
)

// RoutedRequest is a request with a validated authority and a decoded,
// resolved routing path. Header contains the fields as sent, including Host
// if present. Each scanner owns its result and returns the same pointer until
// Reset. Treat a returned request as read-only when sharing it.
type RoutedRequest struct {
	Request
	// Host is the request target's authority, HTTP/2 :authority, or the Host
	// field, possibly with a port. It is empty when none supplied a host.
	Host string
	// Path is the path as returned by CleanPath. It is empty for CONNECT and
	// "*" for a server-wide OPTIONS request.
	Path string
}

// Query returns a new map of the target's query parameters. It returns nil
// for a malformed query in a manually constructed RoutedRequest.
func (r RoutedRequest) Query() url.Values {
	target, _, _ := strings.Cut(r.Target, "#")
	_, query, _ := strings.Cut(target, "?")
	values, err := url.ParseQuery(query)
	if err != nil {
		return nil
	}
	return values
}

// routeRequest derives routing metadata from a parsed head. For HTTP/2,
// authority is the value of :authority and the wire target is :path.
func routeRequest(r Request, authority string) (*RoutedRequest, error) {
	var host string
	seenHost := false
	for value := range r.Header.All("Host") {
		if seenHost {
			return nil, malformed("more than one Host field")
		}
		host, seenHost = value, true
	}
	var hostTarget Target
	var err error
	if host != "" {
		hostTarget, err = routingAuthority(host)
		if err != nil {
			return nil, err
		}
	}
	if authority != "" && host != authority {
		if seenHost && !strings.EqualFold(authority, host) {
			return nil, malformed("Host disagrees with :authority")
		}
		host = authority
		hostTarget, err = routingAuthority(host)
		if err != nil {
			return nil, err
		}
	}
	if r.Target == "" && r.Proto == "HTTP/2.0" && r.Method == methodConnect {
		if hostTarget.Port == 0 {
			return nil, malformed("CONNECT authority requires a port")
		}
		return &RoutedRequest{Request: r, Host: host}, nil
	}
	if _, q, ok := strings.Cut(r.Target, "?"); ok && !validQuery(q) {
		return nil, malformed("request query")
	}
	if !validRequestTarget(r.Target) || strings.ContainsRune(r.Target, '#') {
		return nil, malformed("request target " + quote(r.Target))
	}
	t, err := parseTarget(r.Method, r.Target, r.Method == methodConnect)
	if err != nil {
		return nil, err
	}
	if t.Form == AuthorityForm || t.Form == AbsoluteForm {
		if !validRoutingAuthority(t) {
			return nil, malformed("authority " + quote(t.Authority))
		}
		if host != "" && !sameAuthority(t, hostTarget) {
			return nil, malformed("Host disagrees with the request target")
		}
		host = t.Authority
	}
	switch t.Form {
	case AuthorityForm:
		if t.Port == 0 {
			return nil, malformed("CONNECT authority requires a port")
		}
		return &RoutedRequest{Request: r, Host: host}, nil
	case AsteriskForm:
		if r.Method != "OPTIONS" {
			return nil, malformed("asterisk target requires OPTIONS")
		}
		return &RoutedRequest{Request: r, Host: host, Path: "*"}, nil
	case OriginForm, AbsoluteForm:
	}
	if t.Form == AbsoluteForm && t.Path == "*" {
		// The absolute URI has an empty path. ParseTarget projects it to
		// asterisk-form for forwarding, but its routing path is root.
		t.Path = "/"
	}
	escaped, _, _ := strings.Cut(t.Path, "?")
	p, err := CleanPath(escaped)
	if err != nil {
		return nil, err
	}
	return &RoutedRequest{Request: r, Host: host, Path: p}, nil
}

func routingAuthority(s string) (Target, error) {
	t, err := parseAuthority(s)
	if err != nil {
		return Target{}, err
	}
	if !validRoutingAuthority(t) {
		return Target{}, malformed("authority " + quote(s))
	}
	return t, nil
}

func validRoutingAuthority(t Target) bool {
	if t.Host == "." || strings.HasSuffix(t.Authority, ":") {
		return false
	}
	_, zone, _ := strings.Cut(t.Host, "%")
	for i := range len(zone) {
		c := zone[i]
		if !isAlpha(c) && !isDigit(c) && !strings.ContainsRune("-._~", rune(c)) {
			return false
		}
	}
	return true
}

func sameAuthority(target, host Target) bool {
	a, zoneA, _ := strings.Cut(target.Host, "%")
	b, zoneB, _ := strings.Cut(host.Host, "%")
	return zoneA == zoneB && strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, ".")) &&
		effectivePort(target.Port, target.Scheme) == effectivePort(host.Port, target.Scheme)
}

func effectivePort(port uint16, scheme string) uint16 {
	if port != 0 {
		return port
	}
	switch scheme {
	case "http":
		return 80
	case "https":
		return 443
	default:
		return 0
	}
}

// validQuery checks the errors reported by url.ParseQuery before a request
// can be used for routing, without allocating a parameter map.
func validQuery(q string) bool {
	for i := 0; i < len(q); i++ {
		switch q[i] {
		case ';':
			return false
		case '%':
			if len(q)-i < 3 || !isHex(q[i+1]) || !isHex(q[i+2]) {
				return false
			}
			i += 2
		}
	}
	return true
}

func isHex(b byte) bool { return isDigit(b) || b|0x20 >= 'a' && b|0x20 <= 'f' }

// CleanPath decodes an escaped path, removes dot segments and repeated
// slashes, and preserves a trailing slash. An empty path becomes "/". It
// returns ErrMalformed for an invalid escape, a backslash, decoded control
// bytes, or a path whose dot or parameter segments can resolve differently
// when decoded or split by another reader.
func CleanPath(escaped string) (string, error) {
	if ambiguousPath(escaped) {
		return "", malformed("ambiguous path " + quote(escaped))
	}
	p := escaped
	if strings.ContainsRune(p, '%') {
		var err error
		if p, err = url.PathUnescape(p); err != nil {
			return "", malformed("path escape " + quote(escaped))
		}
	}
	for i := range len(p) {
		if p[i] < ' ' || p[i] == 0x7f {
			return "", malformed("control byte in path")
		}
	}
	return CleanDecodedPath(p), nil
}

// CleanDecodedPath resolves dot segments and repeated slashes, preserving a
// trailing slash. An empty path becomes "/". Use CleanPath when validating
// an escaped request path.
func CleanDecodedPath(p string) string {
	if p == "" {
		return "/"
	}
	if p[0] != '/' {
		p = "/" + p
	}
	clean := path.Clean(p)
	if strings.HasSuffix(p, "/") && clean != "/" {
		if len(clean)+1 == len(p) && p[:len(clean)] == clean {
			return p
		}
		return clean + "/"
	}
	return clean
}

// HasPathPrefix reports whether p is prefix or lies below it by full path
// segments. A semicolon starts parameters on a segment. A prefix ending
// with a slash only matches paths that contain that slash.
func HasPathPrefix(p, prefix string) bool {
	if !strings.HasPrefix(p, prefix) {
		return false
	}
	return len(p) == len(prefix) || strings.HasSuffix(prefix, "/") || p[len(prefix)] == '/' || p[len(prefix)] == ';'
}

func ambiguousPath(escaped string) bool {
	if strings.ContainsRune(escaped, '\\') {
		return true
	}
	rest, more := escaped, true
	for more {
		var segment string
		segment, rest, more = strings.Cut(rest, "/")
		if segment == "." || segment == ".." || !strings.ContainsAny(segment, "%;") {
			continue
		}
		decoded, err := url.PathUnescape(segment)
		if err != nil || strings.ContainsRune(decoded, '\\') {
			return true
		}
		remaining, hasNext := decoded, true
		for hasNext {
			var piece string
			piece, remaining, hasNext = strings.Cut(remaining, "/")
			name, _, params := strings.Cut(piece, ";")
			if name == "." || name == ".." || params && name == "" && (hasNext || more) {
				return true
			}
		}
	}
	return false
}
