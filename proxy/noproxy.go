package proxy

import (
	"net"
	"net/netip"
	"strings"
)

// NoProxy matches the targets that should bypass a proxy, as listed in a
// NO_PROXY environment variable. The zero NoProxy matches nothing.
type NoProxy struct {
	all      bool
	prefixes []netip.Prefix
	ips      []noProxyIP
	domains  []noProxyDomain
}

type noProxyIP struct {
	ip   netip.Addr
	port string
}

type noProxyDomain struct {
	name    string // lower case, without leading or trailing dots
	subOnly bool   // match subdomains only
	port    string
}

// ParseNoProxy parses a comma-separated NO_PROXY list. "*" matches every
// target. An IP address, bracketed or not, or a CIDR range matches IP
// targets. A domain name
// matches itself and its subdomains, and a leading "." or "*." restricts it to
// subdomains. An entry may end in ":port" to match only that port. Matching
// ignores case and a trailing dot; entries that fit none of these forms are
// ignored.
func ParseNoProxy(s string) NoProxy {
	var np NoProxy
	for entry := range strings.SplitSeq(s, ",") {
		entry = strings.ToLower(strings.TrimSpace(entry))
		if entry == "" {
			continue
		}
		if entry == "*" {
			np.all = true
			continue
		}
		if prefix, err := netip.ParsePrefix(entry); err == nil {
			np.prefixes = append(np.prefixes, prefix.Masked())
			continue
		}
		host, port := entry, ""
		if h, p, err := net.SplitHostPort(entry); err == nil {
			host, port = h, p
		}
		if ip, err := netip.ParseAddr(unbracket(host)); err == nil {
			np.ips = append(np.ips, noProxyIP{ip: ip.Unmap().WithZone(""), port: port})
			continue
		}
		host = strings.TrimPrefix(host, "*")
		domain := noProxyDomain{port: port}
		if strings.HasPrefix(host, ".") {
			domain.subOnly = true
			host = host[1:]
		}
		domain.name = strings.TrimSuffix(host, ".")
		if domain.name != "" {
			np.domains = append(np.domains, domain)
		}
	}
	return np
}

func (np NoProxy) empty() bool {
	return !np.all && len(np.prefixes) == 0 && len(np.ips) == 0 && len(np.domains) == 0
}

// Match reports whether the target address, "host:port" or a bare host,
// bypasses the proxy.
func (np NoProxy) Match(address string) bool {
	if np.all {
		return true
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		host, port = address, ""
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if ip, err := netip.ParseAddr(unbracket(host)); err == nil {
		ip = ip.Unmap().WithZone("")
		for _, prefix := range np.prefixes {
			if prefix.Contains(ip) {
				return true
			}
		}
		for _, entry := range np.ips {
			if entry.ip == ip && (entry.port == "" || entry.port == port) {
				return true
			}
		}
		return false
	}
	for _, entry := range np.domains {
		if entry.port != "" && entry.port != port {
			continue
		}
		if (host == entry.name && !entry.subOnly) || strings.HasSuffix(host, "."+entry.name) {
			return true
		}
	}
	return false
}

// unbracket removes the brackets around an IPv6 literal such as "[::1]".
func unbracket(host string) string {
	if len(host) > 1 && host[0] == '[' && host[len(host)-1] == ']' {
		return host[1 : len(host)-1]
	}
	return host
}
