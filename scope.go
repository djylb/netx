package netx

import (
	"encoding/binary"
	"net/netip"
	"strconv"
)

// Scope is the reachability class of an IP address, as the IANA IPv4 and
// IPv6 Special-Purpose Address Registries (RFC 6890 and its updates) and the
// address architectures (RFC 791, RFC 4291) assign it. ScopeOf returns it.
type Scope uint8

// Scopes, from the narrowest to the widest reach.
const (
	// ScopeInvalid is the scope of the zero netip.Addr.
	ScopeInvalid Scope = iota
	// ScopeUnspecified is 0.0.0.0 and ::, which name no host but reach the
	// local host on many systems when dialed.
	ScopeUnspecified
	// ScopeLoopback is 127.0.0.0/8 and ::1.
	ScopeLoopback
	// ScopeLinkLocal is 169.254.0.0/16 and fe80::/10.
	ScopeLinkLocal
	// ScopePrivate is the space of private networks: 10.0.0.0/8,
	// 172.16.0.0/12, 192.168.0.0/16 (RFC 1918), the unique local addresses
	// fc00::/7 (RFC 4193) and the local-use translation prefix
	// 64:ff9b:1::/48 (RFC 8215).
	ScopePrivate
	// ScopeShared is 100.64.0.0/10, the shared address space of carrier-grade
	// NAT (RFC 6598).
	ScopeShared
	// ScopeMulticast is 224.0.0.0/4 and ff00::/8, of any multicast scope.
	ScopeMulticast
	// ScopeBroadcast is the limited broadcast address 255.255.255.255.
	ScopeBroadcast
	// ScopeDocumentation is 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
	// (RFC 5737), 2001:db8::/32 (RFC 3849) and 3fff::/20 (RFC 9637).
	ScopeDocumentation
	// ScopeBenchmarking is 198.18.0.0/15 (RFC 2544) and 2001:2::/48
	// (RFC 5180).
	ScopeBenchmarking
	// ScopeReserved is unicast space that is not globally reachable and
	// has none of the uses above: "this network" 0.0.0.0/8, the IETF
	// protocol assignments 192.0.0.0/24 and 2001::/23 apart from their
	// globally reachable entries, the former 6to4 relay anycast
	// 192.88.99.0/24 (RFC 7526), 240.0.0.0/4, the discard and dummy
	// prefixes 100::/64 and 100:0:0:1::/64, the deprecated ORCHID
	// 2001:10::/28, the segment routing SIDs 5f00::/16, IPv6 outside
	// 2000::/3 that no entry names (such as the deprecated site-local
	// fec0::/10 and the IPv4-compatible ::/96), and translation addresses
	// that embed an IPv4 address that is not global (see ScopeOf).
	ScopeReserved
	// ScopeGlobal is globally reachable unicast.
	ScopeGlobal
)

var scopeNames = [...]string{
	ScopeInvalid:       "invalid",
	ScopeUnspecified:   "unspecified",
	ScopeLoopback:      "loopback",
	ScopeLinkLocal:     "link-local",
	ScopePrivate:       "private",
	ScopeShared:        "shared",
	ScopeMulticast:     "multicast",
	ScopeBroadcast:     "broadcast",
	ScopeDocumentation: "documentation",
	ScopeBenchmarking:  "benchmarking",
	ScopeReserved:      "reserved",
	ScopeGlobal:        "global",
}

// String returns the name of s, such as "private", or "scope(N)" for a
// value that is not one of the constants.
func (s Scope) String() string {
	if int(s) < len(scopeNames) {
		return scopeNames[s]
	}
	return "scope(" + strconv.Itoa(int(s)) + ")"
}

// Scopes of the table entries that depend on an embedded IPv4 address.
const (
	scopeNAT64  = ScopeGlobal + 1 + iota // 64:ff9b::/96, IPv4 in the last 32 bits
	scope6to4                            // 2002::/16, IPv4 in bits 16 to 47
	scopeTeredo                          // 2001::/32, server IPv4 in bits 32 to 63, client inverted in the last 32
)

// scopeEntry4 is an IPv4 registry entry. prefix is its text, which the
// tests check addr and bits against.
type scopeEntry4 struct {
	prefix string
	addr   uint32
	bits   uint8
	scope  Scope
}

// scopeTable4 lists the IPv4 entries, a more specific one before those that
// contain it; the first that matches decides. Addresses that none matches
// are global, among them the globally reachable registry entries
// 192.31.196.0/24 (AS112), 192.52.193.0/24 (AMT) and 192.175.48.0/24 (AS112
// direct delegation).
var scopeTable4 = [...]scopeEntry4{
	{"0.0.0.0/32", 0x00000000, 32, ScopeUnspecified},
	{"0.0.0.0/8", 0x00000000, 8, ScopeReserved},
	{"10.0.0.0/8", 0x0a000000, 8, ScopePrivate},
	{"100.64.0.0/10", 0x64400000, 10, ScopeShared},
	{"127.0.0.0/8", 0x7f000000, 8, ScopeLoopback},
	{"169.254.0.0/16", 0xa9fe0000, 16, ScopeLinkLocal},
	{"172.16.0.0/12", 0xac100000, 12, ScopePrivate},
	{"192.0.0.9/32", 0xc0000009, 32, ScopeGlobal},  // PCP anycast
	{"192.0.0.10/32", 0xc000000a, 32, ScopeGlobal}, // TURN anycast
	{"192.0.0.0/24", 0xc0000000, 24, ScopeReserved},
	{"192.0.2.0/24", 0xc0000200, 24, ScopeDocumentation},
	{"192.88.99.0/24", 0xc0586300, 24, ScopeReserved},
	{"192.168.0.0/16", 0xc0a80000, 16, ScopePrivate},
	{"198.18.0.0/15", 0xc6120000, 15, ScopeBenchmarking},
	{"198.51.100.0/24", 0xc6336400, 24, ScopeDocumentation},
	{"203.0.113.0/24", 0xcb007100, 24, ScopeDocumentation},
	{"224.0.0.0/4", 0xe0000000, 4, ScopeMulticast},
	{"255.255.255.255/32", 0xffffffff, 32, ScopeBroadcast},
	{"240.0.0.0/4", 0xf0000000, 4, ScopeReserved},
}

// scopeFirst4 indexes scopeTable4 by the first byte of an address: an
// entry below scopeScan is the scope of every address with that byte, and
// scopeScan|i makes the lookup scan the table from entry i.
var scopeFirst4 = func() (idx [256]uint8) {
	for b := range idx {
		idx[b] = firstIndex(b, len(scopeTable4), func(i int) (uint32, uint8, Scope) {
			e := &scopeTable4[i]
			return e.addr >> 24, e.bits, e.scope
		})
	}
	return idx
}()

// scopeScan marks a scopeFirst4 or scopeFirst6 entry that needs a scan.
const scopeScan = 0x80

// firstIndex returns the index entry of first byte b for a table of n
// entries, entry(i) giving the first byte, the prefix length and the scope
// of entry i. A byte whose first covering entry is at most 8 bits long has
// that entry's scope, unless an embedded-address entry or a longer entry
// for the byte comes before it.
func firstIndex(b, n int, entry func(i int) (first uint32, bits uint8, scope Scope)) uint8 {
	for i := range n {
		first, bits, scope := entry(i)
		mask := uint32(0xff)
		if bits < 8 {
			mask = 0xff << (8 - bits) & 0xff
		}
		if uint32(b)&mask != first {
			continue
		}
		if bits <= 8 && scope <= ScopeGlobal {
			return uint8(scope)
		}
		return scopeScan | uint8(i)
	}
	return uint8(ScopeGlobal)
}

// scopeEntry6 is an IPv6 registry entry, the address as two big-endian
// halves.
type scopeEntry6 struct {
	prefix string
	hi, lo uint64
	bits   uint8
	scope  Scope
}

// scopeTable6 lists the IPv6 entries in the order of scopeTable4. The last
// one makes the space outside 2000::/3 that no other entry names reserved.
var scopeTable6 = [...]scopeEntry6{
	{"::/128", 0, 0, 128, ScopeUnspecified},
	{"::1/128", 0, 1, 128, ScopeLoopback},
	{"64:ff9b::/96", 0x0064ff9b00000000, 0, 96, scopeNAT64},
	{"64:ff9b:1::/48", 0x0064ff9b00010000, 0, 48, ScopePrivate},
	{"100::/64", 0x0100000000000000, 0, 64, ScopeReserved},
	{"100:0:0:1::/64", 0x0100000000000001, 0, 64, ScopeReserved},
	{"2001:1::1/128", 0x2001000100000000, 1, 128, ScopeGlobal}, // PCP anycast
	{"2001:1::2/128", 0x2001000100000000, 2, 128, ScopeGlobal}, // TURN anycast
	{"2001:1::3/128", 0x2001000100000000, 3, 128, ScopeGlobal}, // DNS-SD SRP anycast
	{"2001:2::/48", 0x2001000200000000, 0, 48, ScopeBenchmarking},
	{"2001:3::/32", 0x2001000300000000, 0, 32, ScopeGlobal},     // AMT
	{"2001:4:112::/48", 0x2001000401120000, 0, 48, ScopeGlobal}, // AS112-v6
	{"2001:20::/28", 0x2001002000000000, 0, 28, ScopeGlobal},    // ORCHIDv2
	{"2001:30::/28", 0x2001003000000000, 0, 28, ScopeGlobal},    // drone remote ID tags
	{"2001::/32", 0x2001000000000000, 0, 32, scopeTeredo},       // Teredo
	{"2001::/23", 0x2001000000000000, 0, 23, ScopeReserved},     // IETF protocol assignments
	{"2001:db8::/32", 0x20010db800000000, 0, 32, ScopeDocumentation},
	{"2002::/16", 0x2002000000000000, 0, 16, scope6to4},
	{"3fff::/20", 0x3fff000000000000, 0, 20, ScopeDocumentation},
	{"2000::/3", 0x2000000000000000, 0, 3, ScopeGlobal},
	{"5f00::/16", 0x5f00000000000000, 0, 16, ScopeReserved},
	{"fc00::/7", 0xfc00000000000000, 0, 7, ScopePrivate},
	{"fe80::/10", 0xfe80000000000000, 0, 10, ScopeLinkLocal},
	{"ff00::/8", 0xff00000000000000, 0, 8, ScopeMulticast},
	{"::/0", 0, 0, 0, ScopeReserved},
}

// scopeFirst6 indexes scopeTable6 by the first byte of an address, as
// scopeFirst4 does scopeTable4.
var scopeFirst6 = func() (idx [256]uint8) {
	for b := range idx {
		idx[b] = firstIndex(b, len(scopeTable6), func(i int) (uint32, uint8, Scope) {
			e := &scopeTable6[i]
			return uint32(e.hi >> 56), e.bits, e.scope
		})
	}
	return idx
}()

// ScopeOf returns the scope of a, ignoring its zone. An IPv4-mapped IPv6
// address has the scope of its IPv4 address.
//
// The registries leave the reachability of 6to4 (2002::/16) and Teredo
// (2001::/32) addresses to the IPv4 addresses they embed, so such an
// address is ScopeGlobal when its embedded IPv4 addresses are (for Teredo,
// the server's and the client's) and ScopeReserved otherwise. The NAT64
// well-known prefix 64:ff9b::/96 is globally reachable in the registry, and
// RFC 6052 forbids it to embed an IPv4 address that is not global, so its
// addresses are classified in the same way, which agrees with the registry
// for every valid one. The RFC 8215 local-use prefix 64:ff9b:1::/48 is
// ScopePrivate whatever it embeds.
//
// Registry entries that are globally reachable inside larger reserved
// blocks, such as the PCP and TURN anycast addresses 192.0.0.9, 192.0.0.10,
// 2001:1::1 and 2001:1::2, are ScopeGlobal. Multicast addresses are
// ScopeMulticast whatever their multicast scope. ScopeOf does not allocate.
func ScopeOf(a netip.Addr) Scope {
	if a.Is4In6() {
		a = a.Unmap()
	}
	switch {
	case a.Is4():
		b := a.As4()
		return scope4(binary.BigEndian.Uint32(b[:]))
	case a.Is6():
		b := a.As16()
		return scope6(binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:]))
	}
	return ScopeInvalid
}

// IsGlobal reports whether a is globally reachable unicast, ScopeOf(a) ==
// ScopeGlobal: not private, shared, loopback, link-local, multicast,
// documentation, benchmarking, reserved or unspecified.
func IsGlobal(a netip.Addr) bool { return ScopeOf(a) == ScopeGlobal }

func scope4(v uint32) Scope {
	x := scopeFirst4[v>>24]
	if x < scopeScan {
		return Scope(x)
	}
	for i := int(x &^ scopeScan); i < len(scopeTable4); i++ {
		e := &scopeTable4[i]
		if (v^e.addr)&^(0xffffffff>>e.bits) == 0 {
			return e.scope
		}
	}
	return ScopeGlobal
}

func scope6(hi, lo uint64) Scope {
	x := scopeFirst6[hi>>56]
	if x < scopeScan {
		return Scope(x)
	}
	for i := int(x &^ scopeScan); i < len(scopeTable6); i++ {
		e := &scopeTable6[i]
		if !match6(hi, lo, e.hi, e.lo, e.bits) {
			continue
		}
		switch e.scope {
		case scopeNAT64:
			return embedded(uint32(lo))
		case scope6to4:
			return embedded(uint32(hi >> 16))
		case scopeTeredo:
			if scope4(uint32(hi)) != ScopeGlobal {
				return ScopeReserved
			}
			return embedded(^uint32(lo))
		}
		return e.scope
	}
	return ScopeReserved
}

// embedded returns the scope of a translation address that embeds v.
func embedded(v uint32) Scope {
	if scope4(v) == ScopeGlobal {
		return ScopeGlobal
	}
	return ScopeReserved
}

// match6 reports whether hi:lo is in the prefix ehi:elo/bits.
func match6(hi, lo, ehi, elo uint64, bits uint8) bool {
	switch {
	case bits == 0:
		return true
	case bits <= 64:
		return (hi^ehi)&^(^uint64(0)>>bits) == 0
	}
	return hi == ehi && (lo^elo)&^(^uint64(0)>>(bits-64)) == 0
}
