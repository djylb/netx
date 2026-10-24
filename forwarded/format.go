package forwarded

import (
	"net/netip"
	"strconv"
)

// AppendXForwardedFor appends to dst the X-Forwarded-For value that a proxy
// sends on: the field lines it received, prior, joined with ", " into one,
// then a, the address it received the request from, IPv4 for IPv4-mapped
// addresses and without a zone. Empty lines are skipped. An invalid a is
// written as "unknown".
func AppendXForwardedFor(dst []byte, prior []string, a netip.Addr) []byte {
	dst = appendPrior(dst, prior)
	if !a.IsValid() {
		return append(dst, "unknown"...)
	}
	return a.Unmap().WithZone("").AppendTo(dst)
}

// Element is a Forwarded element (RFC 7239) as a proxy adds it.
type Element struct {
	// For is the address the proxy received the request from, written
	// with its port when that is not 0, or "unknown" when it is invalid.
	For netip.AddrPort
	// By is the address the proxy received the request on, left out when
	// invalid.
	By netip.AddrPort
	// Host is the Host of the request as received, left out when "".
	Host string
	// Proto is the scheme of the request as received, such as "https",
	// left out when "".
	Proto string
}

// AppendElement appends e to dst in the syntax of RFC 7239, such as
// for="[2001:db8::1]:4711";proto=https, quoting values that are not tokens.
func AppendElement(dst []byte, e Element) []byte {
	dst = append(dst, "for="...)
	dst = appendNode(dst, e.For)
	if e.By.Addr().IsValid() {
		dst = append(dst, ";by="...)
		dst = appendNode(dst, e.By)
	}
	if e.Host != "" {
		dst = append(dst, ";host="...)
		dst = appendValue(dst, e.Host)
	}
	if e.Proto != "" {
		dst = append(dst, ";proto="...)
		dst = appendValue(dst, e.Proto)
	}
	return dst
}

// AppendForwarded appends to dst the Forwarded value that a proxy sends on:
// the field lines it received, prior, joined with ", " into one, then e.
// Empty lines are skipped.
func AppendForwarded(dst []byte, prior []string, e Element) []byte {
	return AppendElement(appendPrior(dst, prior), e)
}

func appendPrior(dst []byte, prior []string) []byte {
	for _, p := range prior {
		if p = trimOWS(p); p != "" {
			dst = append(append(dst, p...), ", "...)
		}
	}
	return dst
}

// appendNode appends a node: an IPv4 address alone as a token, anything
// else quoted.
func appendNode(dst []byte, ap netip.AddrPort) []byte {
	a := ap.Addr().Unmap().WithZone("")
	switch {
	case !a.IsValid():
		return append(dst, "unknown"...)
	case a.Is4() && ap.Port() == 0:
		return a.AppendTo(dst)
	}
	dst = append(dst, '"')
	if a.Is6() {
		dst = append(dst, '[')
		dst = a.AppendTo(dst)
		dst = append(dst, ']')
	} else {
		dst = a.AppendTo(dst)
	}
	if ap.Port() != 0 {
		dst = append(dst, ':')
		dst = strconv.AppendUint(dst, uint64(ap.Port()), 10)
	}
	return append(dst, '"')
}

// appendValue appends v as a token, or as a quoted string when it is not
// one, escaping quotes and backslashes and dropping control characters
// other than tab, which a field value cannot carry.
func appendValue(dst []byte, v string) []byte {
	token := true
	for i := 0; i < len(v); i++ {
		if !isTchar(v[i]) {
			token = false
			break
		}
	}
	if token {
		return append(dst, v...)
	}
	dst = append(dst, '"')
	for i := 0; i < len(v); i++ {
		switch c := v[i]; {
		case c == '"' || c == '\\':
			dst = append(dst, '\\', c)
		case c < ' ' && c != '\t' || c == 0x7f:
		default:
			dst = append(dst, c)
		}
	}
	return append(dst, '"')
}
