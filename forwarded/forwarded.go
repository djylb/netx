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
// farthest hop when all are. Only the one header field that the trusted
// proxies set may be read: a proxy passes the other ones on as the client
// sent them.
//
// The package parses without allocating on the common path and returns
// netip values; the trusted proxies are a PrefixSet built once. It depends
// on the standard library alone and not on net/http: a header is the map
// that http.Header is, so an http.Header can be passed as it is.
package forwarded

import (
	"net/netip"
	"strconv"
	"strings"
)

// Header names the header field that a Resolver reads.
type Header uint8

// Header fields.
const (
	// HeaderXForwardedFor is X-Forwarded-For, a comma-separated list of
	// addresses to which each proxy appends the address it received the
	// request from, in any number of field lines. X-Forwarded-Proto and
	// X-Forwarded-Host give Client.Proto and Client.Host.
	HeaderXForwardedFor Header = iota
	// HeaderForwarded is Forwarded (RFC 7239), a list of elements such as
	// for=192.0.2.60;proto=https;host=example.com, one per proxy. The
	// element that names the client gives Client.Proto and Client.Host.
	HeaderForwarded
	// HeaderXRealIP is X-Real-IP, the one address of the client that the
	// nearest proxy sets; only the TCP peer needs to be trusted, and the
	// last field line is read. X-Forwarded-Proto and X-Forwarded-Host give
	// Client.Proto and Client.Host.
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

// Resolver finds the client of a request. Its fields must not change while
// it is in use; a Resolver is then safe for concurrent use. A nil *Resolver,
// or one with no trusted proxies, takes every TCP peer for the client.
type Resolver struct {
	// Trusted holds the proxies whose header fields are believed.
	Trusted *PrefixSet
	// Header is the field that the trusted proxies set. Fields of the other
	// kinds are ignored, as a client may have sent them.
	Header Header
	// Name, if set, is the field read in place of the one Header names,
	// with the syntax Header gives, such as "Cf-Connecting-Ip" with
	// HeaderXRealIP. It must be in canonical form, as http.Header keys
	// are, since the header map is indexed with it.
	Name string
}

// Client is the client of a request as a Resolver finds it.
type Client struct {
	// Addr is the address of the client, IPv4 for IPv4-mapped addresses and
	// without a zone. Its port is 0 when the hop that recorded it gave none,
	// as X-Forwarded-For entries usually do. It is the TCP peer when that
	// is not trusted, or when it is and recorded no client.
	Addr netip.AddrPort
	// Hops is the number of trusted proxies between the client and the
	// server, counting the TCP peer: 0 when Addr is the TCP peer.
	Hops int
	// Proto and Host are the scheme and the Host that the request had when
	// a trusted proxy received it, or "" when no trusted proxy recorded
	// them or what it recorded is not a valid scheme or host. For
	// Forwarded, they come from the element that names the client; for
	// X-Forwarded-For and X-Real-IP, from the last entry of the last field
	// line of X-Forwarded-Proto and X-Forwarded-Host when the TCP peer is
	// trusted, which is what the nearest proxy set or passed on, so the
	// trusted proxies must set these fields too.
	Proto, Host string
	// Opaque is set when the walk stopped at a hop that a trusted proxy
	// recorded without a usable address: an obfuscated identifier such as
	// "_hidden", "unknown", an entry that does not parse, or "unknown" for
	// a Forwarded element without for. Addr is then the trusted proxy that
	// recorded it, the nearest knowledge of the client.
	Opaque string
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
	if p := lastItem(header["X-Forwarded-Proto"]); validProto(p) {
		c.Proto = p
	}
	if h := lastItem(header["X-Forwarded-Host"]); validHost(h) {
		c.Host = h
	}
	return c
}

// walkList walks X-Forwarded-For entries from the right, c holding the
// trusted peer.
func (r *Resolver) walkList(c *Client, lines []string) {
	for i := len(lines) - 1; i >= 0; i-- {
		line := lines[i]
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
	for i := len(lines) - 1; i >= 0; i-- {
		rest := lines[i]
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
			if validProto(e.proto) {
				c.Proto = e.proto
			}
			if validHost(e.host) {
				c.Host = e.host
			}
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
