package forwarded

import (
	"net/netip"
	"strings"
)

// ParseNode parses an address as forwarding fields record it: an entry of
// X-Forwarded-For or X-Real-IP, or the unquoted value of a Forwarded for or
// by parameter. It takes an IPv4 address, an IPv6 address in brackets or
// bare, either with an optional ":port" after it (after the brackets for
// IPv6), where an obfuscated port such as ":_a1" (RFC 7239) counts as no
// port. It returns the address IPv4 for IPv4-mapped addresses and without
// a zone, and false for anything else, such as "unknown", an obfuscated
// identifier or a host name. It does not allocate.
func ParseNode(s string) (netip.AddrPort, bool) {
	host, port, hasPort := s, "", false
	switch {
	case strings.HasPrefix(s, "["):
		end := strings.IndexByte(s, ']')
		if end < 0 {
			return netip.AddrPort{}, false
		}
		host, port = s[1:end], s[end+1:]
		if port != "" {
			if port[0] != ':' {
				return netip.AddrPort{}, false
			}
			port, hasPort = port[1:], true
		}
		if strings.IndexByte(host, ':') < 0 {
			return netip.AddrPort{}, false // IPv4 in brackets
		}
	case strings.Count(s, ":") == 1:
		i := strings.IndexByte(s, ':')
		host, port, hasPort = s[:i], s[i+1:], true
	}
	if i := strings.IndexByte(host, '%'); i >= 0 {
		if strings.IndexByte(host[:i], ':') < 0 {
			return netip.AddrPort{}, false // a zone on IPv4
		}
		host = host[:i]
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.AddrPort{}, false
	}
	p, ok := parsePort(port, hasPort)
	if !ok {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(a.Unmap(), p), true
}

// parsePort parses the port of a node, if it has one: 1 to 5 digits up to
// 65535, or an obfuscated port, which is 0.
func parsePort(s string, hasPort bool) (uint16, bool) {
	if !hasPort {
		return 0, true
	}
	if s == "" {
		return 0, false
	}
	if s[0] == '_' {
		return 0, obfChars(s[1:])
	}
	if len(s) > 5 {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	if n > 0xffff {
		return 0, false
	}
	return uint16(n), true
}

// obfChars reports whether s is the nonempty rest of an obfuscated
// identifier: ALPHA, DIGIT, ".", "_" or "-".
func obfChars(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !isAlnum(c) && c != '.' && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

// element is the part of a Forwarded element that a Resolver reads.
type element struct {
	forValue    string // the for value, unquoted but with its escapes
	proto, host string // "" when absent or escaped
	raw         string // the element text, for a malformed one
	forEscaped  bool   // forValue holds quoted-pairs
	hasFor      bool
	empty       bool // the element is empty, as list syntax allows
}

// forNode parses the for value.
func (e *element) forNode() (netip.AddrPort, bool) {
	if !e.forEscaped {
		return ParseNode(e.forValue)
	}
	// A node never needs escapes; undo them for lenience. Nodes are short.
	var buf [64]byte
	n := 0
	for i := 0; i < len(e.forValue); i++ {
		c := e.forValue[i]
		if c == '\\' {
			i++
			c = e.forValue[i]
		}
		if n == len(buf) {
			return netip.AddrPort{}, false
		}
		buf[n] = c
		n++
	}
	return ParseNode(string(buf[:n]))
}

// lastElement parses the last element of the Forwarded field line s,
// returning it, the line before the comma that precedes it, and whether
// there is such a comma. It parses from the right so that the elements that
// the nearest proxies appended are read whatever a client put before them.
// Parameter names are matched without regard to case, values are tokens or
// quoted strings, and spaces are allowed around the separators.
func lastElement(s string) (e element, rest string, more, ok bool) {
	i := trimOWSRight(s)
	end := i
	fail := func() (element, string, bool, bool) {
		start := strings.LastIndexByte(s[:end], ',') + 1
		return element{raw: trimOWS(s[start:end])}, "", false, false
	}
	if i == 0 || s[i-1] == ',' {
		e.empty = true
		if i == 0 {
			return e, "", false, true
		}
		return e, s[:i-1], true, true
	}
	for {
		var val string
		escaped := false
		if s[i-1] == '"' {
			if backslashes(s[:i-1])%2 != 0 {
				return fail() // the closing quote is escaped
			}
			j := i - 2
			for ; j >= 0; j-- {
				if s[j] == '"' {
					if backslashes(s[:j])%2 == 0 {
						break
					}
					escaped = true
				} else if s[j] == '\\' {
					escaped = true
				} else if s[j] < ' ' && s[j] != '\t' || s[j] == 0x7f {
					return fail()
				}
			}
			if j < 0 {
				return fail()
			}
			val, i = s[j+1:i-1], j
		} else {
			j := i
			for j > 0 && valueChar(s[j-1]) {
				j--
			}
			if j == i {
				return fail()
			}
			val, i = s[j:i], j
		}
		if i == 0 || s[i-1] != '=' {
			return fail()
		}
		i--
		j := i
		for j > 0 && isTchar(s[j-1]) {
			j--
		}
		if j == i {
			return fail()
		}
		name := s[j:i]
		i = j
		switch {
		case strings.EqualFold(name, "for"):
			if e.hasFor {
				return fail()
			}
			e.hasFor, e.forValue, e.forEscaped = true, val, escaped
		case strings.EqualFold(name, "proto"):
			if e.proto != "" {
				return fail()
			}
			if !escaped {
				e.proto = val
			}
		case strings.EqualFold(name, "host"):
			if e.host != "" {
				return fail()
			}
			if !escaped {
				e.host = val
			}
		}
		i = trimOWSRight(s[:i])
		if i == 0 {
			return e, "", false, true
		}
		switch s[i-1] {
		case ';':
			i = trimOWSRight(s[:i-1])
			if i == 0 {
				return fail()
			}
		case ',':
			return e, s[:i-1], true, true
		default:
			return fail()
		}
	}
}

// backslashes returns the number of backslashes that s ends with.
func backslashes(s string) int {
	n := 0
	for n < len(s) && s[len(s)-1-n] == '\\' {
		n++
	}
	return n
}

// valueChar reports whether c may be in an unquoted parameter value. It
// takes the tchar of a token and, leniently, the characters of an address
// such as ":" and brackets, but no separator of the element syntax.
func valueChar(c byte) bool {
	return c > ' ' && c < 0x7f && c != '"' && c != ',' && c != ';' && c != '=' && c != '\\'
}

// isTchar reports whether c is a token character (RFC 9110).
func isTchar(c byte) bool {
	return c < 0x80 && tchar[c>>6]&(1<<(c&63)) != 0
}

var tchar = func() (m [2]uint64) {
	for c := byte('!'); c <= '~'; c++ {
		if isAlnum(c) || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0 {
			m[c>>6] |= 1 << (c & 63)
		}
	}
	return m
}()

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// validProto reports whether s is a URI scheme (RFC 3986).
func validProto(s string) bool {
	if s == "" || !isAlpha(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		if c := s[i]; !isAlnum(c) && c != '+' && c != '-' && c != '.' {
			return false
		}
	}
	return true
}

func isAlpha(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

// validHost reports whether s is a URI host with an optional port
// (RFC 3986 authority without userinfo): unreserved characters,
// sub-delimiters, percent signs, colons and brackets.
func validHost(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !isAlnum(c) && strings.IndexByte("-._~!$&'()*+,;=%:[]", c) < 0 {
			return false
		}
	}
	return true
}

// trimOWS trims spaces and tabs.
func trimOWS(s string) string {
	for s != "" && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	return s[:trimOWSRight(s)]
}

// trimOWSRight returns the length of s without trailing spaces and tabs.
func trimOWSRight(s string) int {
	i := len(s)
	for i > 0 && (s[i-1] == ' ' || s[i-1] == '\t') {
		i--
	}
	return i
}
