package httphead

import (
	"net/netip"
	"strings"
)

// Form is the form of a request-target (RFC 9112, section 3.2).
type Form uint8

const (
	// OriginForm is a path with an optional query, such as "/a?b".
	OriginForm Form = iota
	// AbsoluteForm is an absolute URI, such as "http://example.com/a",
	// which requests to proxies carry.
	AbsoluteForm
	// AuthorityForm is the host and port of a CONNECT request.
	AuthorityForm
	// AsteriskForm is the "*" of a server-wide OPTIONS request.
	AsteriskForm
)

// Target is a parsed request-target.
type Target struct {
	// Scheme is the scheme of an absolute URI, in lower case.
	Scheme string
	// Authority is the host and port of an absolute URI or of the authority
	// form, as sent, which a forwarded request's Host field carries.
	Authority string
	// Host is the host of Authority: a name as sent, an IPv4 address, or an
	// IPv6 address without brackets, with a zone decoded from "%25" (RFC
	// 6874).
	Host string
	// Path is the origin-form of the target, which a request sent to the
	// origin carries: the target itself for the origin and asterisk forms,
	// and for an absolute URI its path and query without the fragment, "/"
	// for an empty path, or "*" for an empty path of an OPTIONS request
	// (section 3.2.4). It is empty for the authority form.
	Path string
	// Port is the port of Authority, or 0 when it has none or an empty one;
	// port 0 itself is refused.
	Port uint16
	// Form is the form the target was sent in.
	Form Form
}

// ParseTarget parses the request-target of a request with method method:
// the authority form for CONNECT, compared case-insensitively, and the
// other forms for other methods. An absolute URI must have a host and no
// user information, which is deprecated and would let the host differ from
// the one a reader expects (RFC 9110, section 4.2.4). A host is an IP
// literal, IPv6 in brackets, or a name of letters, digits, hyphens,
// underscores and dots, of at most 255 bytes. With an error it returns the
// zero Target.
func ParseTarget(method, target string) (Target, error) {
	switch {
	case strings.EqualFold(method, "CONNECT"):
		t, err := parseAuthority(target)
		if err != nil {
			return Target{}, err
		}
		t.Form = AuthorityForm
		return t, nil
	case target == "*":
		return Target{Form: AsteriskForm, Path: target}, nil
	case strings.HasPrefix(target, "/"):
		return Target{Form: OriginForm, Path: target}, nil
	}
	scheme, rest, ok := strings.Cut(target, "://")
	if !ok || !isScheme(scheme) {
		return Target{}, malformed("request target " + quote(target))
	}
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}
	t, err := parseAuthority(rest[:end])
	if err != nil {
		return Target{}, err
	}
	path := rest[end:]
	if i := strings.IndexByte(path, '#'); i >= 0 {
		path = path[:i] // a fragment is not sent (RFC 9110, section 4.2.5)
	}
	switch {
	case path == "" && method == "OPTIONS":
		path = "*"
	case path == "" || path[0] == '?':
		path = "/" + path
	}
	t.Form, t.Scheme, t.Path = AbsoluteForm, strings.ToLower(scheme), path
	return t, nil
}

func isScheme(s string) bool {
	if s == "" || !isAlpha(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		if c := s[i]; !isAlpha(c) && !isDigit(c) && c != '+' && c != '-' && c != '.' {
			return false
		}
	}
	return true
}

func isAlpha(c byte) bool { return c|0x20 >= 'a' && c|0x20 <= 'z' }

// parseAuthority parses host[:port].
func parseAuthority(s string) (Target, error) {
	if strings.IndexByte(s, '@') >= 0 {
		return Target{}, malformed("user information in the request target")
	}
	t := Target{Authority: s}
	host, portStr := s, ""
	if strings.HasPrefix(s, "[") {
		end := strings.IndexByte(s, ']')
		if end < 0 {
			return Target{}, malformed("host " + quote(s))
		}
		host = s[1:end]
		switch rest := s[end+1:]; {
		case rest == "":
		case rest[0] == ':':
			portStr = rest[1:]
		default:
			return Target{}, malformed("host " + quote(s))
		}
		if i := strings.Index(host, "%25"); i >= 0 {
			host = host[:i] + "%" + host[i+3:]
		}
		if ip, err := netip.ParseAddr(host); err != nil || !ip.Is6() {
			return Target{}, malformed("host " + quote(s))
		}
	} else {
		if i := strings.LastIndexByte(s, ':'); i >= 0 {
			host, portStr = s[:i], s[i+1:]
		}
		if !validName(host) {
			return Target{}, malformed("host " + quote(s))
		}
	}
	port, ok := parsePort(portStr)
	if !ok {
		return Target{}, malformed("port " + quote(s))
	}
	t.Host, t.Port = host, port
	return t, nil
}

func validName(s string) bool {
	if s == "" || len(s) > 255 {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case isAlpha(c), isDigit(c), c == '-', c == '.', c == '_':
		default:
			return false
		}
	}
	return true
}

func parsePort(s string) (uint16, bool) {
	if s == "" {
		return 0, true
	}
	if len(s) > 5 {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return 0, false
		}
		n = n*10 + int(s[i]-'0')
	}
	return uint16(n), n > 0 && n <= 65535
}
