// Package safedial dials, and sends datagrams to, only the destinations
// that a policy allows, for a program that connects on behalf of a party it
// trusts less: a tunnel client that a server tells where to connect, a
// proxy, or a sender of webhooks to URLs that users give.
//
// The check binds to the address actually dialed. Dialer parses the
// destination, treating every form of an IP address, also the legacy IPv4
// forms such as "127.1", "2130706433" or "0x7f.0.0.1" that system resolvers
// read as addresses, as that address; checks a host name by name before
// resolving it; resolves it once; checks every address it resolves to,
// unmapped; and dials only the allowed ones, as IP literals, racing them as
// Happy Eyeballs does. A name therefore cannot reach a refused address by
// resolving differently later, as in DNS rebinding, and CNAME chains do
// not matter, as the addresses they end in are checked. An HTTP client that
// follows redirects dials each new host through the Dialer, so redirects
// are covered; an upstream proxy that resolves names itself is not, so an
// http.Transport that dials with a Dialer must have no Proxy.
//
// A Policy returns nil to allow a Target or the reason to refuse it, which
// comes back in a *DeniedError that matches ErrDenied. DefaultPolicy,
// which a Dialer without a policy uses, allows only globally reachable
// unicast addresses, as netx.ScopeOf classifies them. AllowScopes,
// DenyScopes, AllowPrefixes, DenyPrefixes, AllowPorts, DenyPorts,
// AllowPortRange, DenyPortRange, AllowNames and DenyNames build others,
// and All and Any combine them.
//
// For relays that send datagrams to many destinations, such as SOCKS5 UDP
// associations, WrapPacketConn and WrapAddrPacketConn check the destination
// of every datagram, resolving host names themselves with a bounded cache,
// and deliver replies from any source; Dialer.Check checks one address.
// Checking an IP address does not allocate.
package safedial
