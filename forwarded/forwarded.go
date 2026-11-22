// Package forwarded finds the address of the client of an HTTP request that
// came through proxies, from the X-Forwarded-For, X-Real-IP or Forwarded
// (RFC 7239) header fields that the proxies add, and formats those fields
// for a proxy to pass on.
//
// A client can send any of these fields itself, so they are only believed
// as far as the proxies that wrote them are trusted. A Resolver walks the
// hops from the nearest: it starts at the TCP peer and, while the hop it is
// at is in its set of trusted proxies, steps to the address that hop
// recorded, the next entry from the right. The client is the first hop that
// is not trusted, so that entries a client prepends are never read, or the
// farthest hop when all are. A Resolver reads one configured address
// header. Scheme and host are each trusted only when explicitly enabled.
//
// The package parses without allocating on the common path and returns
// netip values; the trusted proxies are a PrefixSet built once. It depends
// on the standard library alone and not on net/http: a header is the map
// that http.Header is, so an http.Header can be passed as it is.
package forwarded

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// Header names the header field that a Resolver reads.
type Header uint8

// Header fields.
const (
	// HeaderXForwardedFor is X-Forwarded-For, a comma-separated list of
	// addresses to which each proxy appends the address it received the
	// request from, in any number of field lines.
	HeaderXForwardedFor Header = iota
	// HeaderForwarded is Forwarded (RFC 7239), a list of elements such as
	// for=192.0.2.60;proto=https;host=example.com, one per proxy.
	HeaderForwarded
	// HeaderXRealIP is X-Real-IP, the one address of the client that the
	// nearest proxy sets; only the TCP peer needs to be trusted, and the
	// last field line is read.
	HeaderXRealIP
)

// String returns the field name of h.
func (h Header) String() string {
	switch h {
	case HeaderXForwardedFor:
		return "X-Forwarded-For"
	case HeaderForwarded:
		return "Forwarded"
	case HeaderXRealIP:
		return "X-Real-IP"
	}
	return "Header(" + strconv.Itoa(int(h)) + ")"
}

// key returns the canonical form of the field name, as http.Header keys.
func (h Header) key() string {
	if h == HeaderXRealIP {
		return "X-Real-Ip"
	}
	return h.String()
}

// Metadata is a set of optional forwarding fields a Resolver may trust.
type Metadata uint8

const (
	// TrustProto allows the scheme to populate Client.Proto.
	TrustProto Metadata = 1 << iota
	// TrustHost allows the host to populate Client.Host.
	TrustHost
)

// Resolver finds the client of a request. Its fields must not change while
// it is in use; a Resolver is then safe for concurrent use. A nil *Resolver,
// or one with no trusted proxies, takes every TCP peer for the client.
type Resolver struct {
	// Trusted holds the proxies whose address records are believed. Metadata
	// additionally controls which scheme and host fields are believed.
	Trusted *PrefixSet
	// Name, if set, is the field read in place of the one Header names,
	// with the syntax Header gives, such as "Cf-Connecting-Ip" with
	// HeaderXRealIP. It must be in canonical form, as http.Header keys
	// are, since the header map is indexed with it.
	Name string
	// Header selects the address syntax and the source of enabled metadata.
	Header Header
	// Metadata independently enables TrustProto and TrustHost. The zero
	// value reads only addresses. With HeaderForwarded, enable a parameter
	// only if trusted proxies write it in their own Forwarded elements.
	// With HeaderXForwardedFor or HeaderXRealIP, enable a field only if the
	// trusted TCP peer removes any client-supplied value or writes its own
	// as the last value of X-Forwarded-Proto or X-Forwarded-Host, respectively.
	Metadata Metadata
}

// Client is the client of a request as a Resolver finds it.
type Client struct {
	// Addr is the address of the client, IPv4 for IPv4-mapped addresses and
	// without a zone. Its port is 0 when the hop that recorded it gave none,
	// as X-Forwarded-For entries usually do. It is the TCP peer when that
	// is not trusted, or when it is and recorded no client.
	Addr netip.AddrPort
	// Proto and Host are the enabled scheme and host, or "" when disabled,
	// absent or invalid. With HeaderForwarded they come from the same
	// element as Addr, and are empty if the walk stops at an opaque hop.
	// With HeaderXForwardedFor or HeaderXRealIP they come from the last
	// entry of the last line of X-Forwarded-Proto and X-Forwarded-Host,
	// respectively, when the TCP peer is trusted. They describe the request
	// as received by the nearest trusted proxy and may differ from the
	// scheme and host the client used at the first proxy.
	Proto, Host string
	// Opaque is set when the walk stopped at a hop that a trusted proxy
	// recorded without a usable address: an obfuscated identifier such as
	// "_hidden", "unknown", an entry that does not parse, or "unknown" for
	// a Forwarded element without for. Addr is then the trusted proxy that
	// recorded it, the nearest knowledge of the client.
	Opaque string
	// Hops is the number of trusted proxies between the client and the
	// server, counting the TCP peer: 0 when Addr is the TCP peer.
	Hops int
}

// Resolve returns the client of a request that the TCP peer sent with
// header, an http.Header or a map of the same form. It does not allocate.
func (r *Resolver) Resolve(peer netip.AddrPort, header map[string][]string) Client {
	peer = normAddrPort(peer)
	c := Client{Addr: peer}
	if r == nil || !r.Trusted.Contains(peer.Addr()) {
		return c
	}
	name := r.Name
	if name == "" {
		name = r.Header.key()
	}
	lines := header[name]
	switch r.Header {
	case HeaderForwarded:
		r.walkForwarded(&c, lines)
		return c
	case HeaderXRealIP:
		if n := len(lines); n > 0 {
			if v := trimOWS(lines[n-1]); v != "" {
				if ap, ok := ParseNode(v); ok {
					c.Addr, c.Hops = ap, 1
				} else {
					c.Opaque = v
				}
			}
		}
	default:
		r.walkList(&c, lines)
	}
	if r.Metadata&TrustProto != 0 {
		if p := lastItem(header["X-Forwarded-Proto"]); validProto(p) {
			c.Proto = p
		}
	}
	if r.Metadata&TrustHost != 0 {
		if h := lastItem(header["X-Forwarded-Host"]); validHost(h) {
			c.Host = h
		}
	}
	return c
}

// walkList walks X-Forwarded-For entries from the right, c holding the
// trusted peer.
func (r *Resolver) walkList(c *Client, lines []string) {
	for _, line := range slices.Backward(lines) {
		for end := len(line); end >= 0; {
			comma := strings.LastIndexByte(line[:end], ',')
			entry := trimOWS(line[comma+1 : end])
			end = comma
			if entry == "" {
				continue
			}
			ap, ok := ParseNode(entry)
			if !ok {
				c.Opaque = entry
				return
			}
			c.Addr = ap
			c.Hops++
			if !r.Trusted.Contains(ap.Addr()) {
				return
			}
		}
	}
}

// walkForwarded walks Forwarded elements from the right, c holding the
// trusted peer.
func (r *Resolver) walkForwarded(c *Client, lines []string) {
	for _, rest := range slices.Backward(lines) {
		for more := true; more; {
			var e element
			var ok bool
			e, rest, more, ok = lastElement(rest)
			if !ok {
				c.Opaque = e.raw
				c.Proto, c.Host = "", ""
				return
			}
			if e.empty {
				continue
			}
			c.Proto, c.Host = "", ""
			if !e.hasFor {
				c.Opaque = "unknown"
				return
			}
			ap, ok := e.forNode()
			if !ok {
				c.Opaque = e.forValue
				return
			}
			c.Addr = ap
			c.Hops++
			if r.Metadata&TrustProto != 0 && validProto(e.proto) {
				c.Proto = e.proto
			}
			if r.Metadata&TrustHost != 0 && validHost(e.host) {
				c.Host = e.host
			}
			if !r.Trusted.Contains(ap.Addr()) {
				return
			}
		}
	}
}

func normAddrPort(ap netip.AddrPort) netip.AddrPort {
	a := ap.Addr()
	if a.Is4In6() || a.Zone() != "" {
		return netip.AddrPortFrom(a.Unmap().WithZone(""), ap.Port())
	}
	return ap
}

// lastItem returns the last entry of the last field line, trimmed.
func lastItem(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	line := lines[len(lines)-1]
	return trimOWS(line[strings.LastIndexByte(line, ',')+1:])
}
