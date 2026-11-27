// Package addrclass classifies IP addresses and exposes common prefix sets
// for local networks and routing. Its functions and classes are safe for
// concurrent use.
package addrclass

import (
	"net/netip"
	"slices"
)

// Class is a predefined address set. The zero value and unknown values
// describe an empty set.
type Class uint8

const (
	// Loopback covers IPv4 and IPv6 loopback.
	Loopback Class = iota + 1
	// PrivateLAN covers RFC 1918, carrier-grade NAT, IPv6 unique local
	// addresses, loopback and link-local.
	PrivateLAN
	// PrivateRouting covers PrivateLAN plus IPv4's "this network" and
	// reserved high ranges (including limited broadcast), and IPv4 and
	// IPv6 multicast. It is suitable for a private routing category.
	PrivateRouting
)

var classPrefixes = func() (sets [PrivateRouting + 1][]netip.Prefix) {
	add := func(prefix string, scope Scope) {
		if scope == ScopeLoopback {
			sets[Loopback] = append(sets[Loopback], netip.MustParsePrefix(prefix))
		}
		switch {
		case scope == ScopeLoopback, scope == ScopeLinkLocal, scope == ScopeShared,
			scope == ScopePrivate && prefix != localNAT64:
			p := netip.MustParsePrefix(prefix)
			sets[PrivateLAN] = append(sets[PrivateLAN], p)
			sets[PrivateRouting] = append(sets[PrivateRouting], p)
		case scope == ScopeMulticast, prefix == thisNetwork, prefix == reservedIPv4:
			sets[PrivateRouting] = append(sets[PrivateRouting], netip.MustParsePrefix(prefix))
		}
	}
	for _, e := range scopeTable4 {
		add(e.prefix, e.scope)
	}
	for _, e := range scopeTable6 {
		add(e.prefix, e.scope)
	}
	return sets
}()

// Contains reports whether c includes a. An IPv4-mapped address is treated
// as IPv4, and an IPv6 zone is ignored.
func (c Class) Contains(a netip.Addr) bool { return Contains(c.prefixes(), a) }

// Prefixes returns an independent copy of the prefixes in c. The caller
// may append to or modify the copy. Prefix order is unspecified.
func (c Class) Prefixes() []netip.Prefix { return slices.Clone(c.prefixes()) }

func (c Class) prefixes() []netip.Prefix {
	if c <= PrivateRouting {
		return classPrefixes[c]
	}
	return nil
}

// Contains reports whether any prefix contains a after unmapping IPv4 and
// removing the zone. Use native IPv4 prefixes to match unmapped addresses.
func Contains(prefixes []netip.Prefix, a netip.Addr) bool {
	a = a.Unmap().WithZone("")
	return slices.ContainsFunc(prefixes, func(p netip.Prefix) bool { return p.Contains(a) })
}
