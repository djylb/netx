package forwarded

import (
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// ErrInvalidPrefix reports an entry of ParsePrefixSet that is neither an IP
// prefix nor an IP address.
var ErrInvalidPrefix = errors.New("forwarded: invalid prefix")

// PrefixSet is an immutable set of IP prefixes, such as the addresses of
// trusted proxies, built once and looked up without allocating in a time
// logarithmic in the number of prefixes. The zero PrefixSet and a nil
// *PrefixSet are empty. It is safe for concurrent use.
//
// IPv4 and IPv6 are separate: an IPv4 address is matched against the IPv4
// prefixes alone, also when it comes IPv4-mapped (::ffff:192.0.2.1), and a
// prefix inside ::ffff:0:0/96 is taken as the IPv4 prefix it maps, so that
// ::ffff:10.0.0.0/104 is 10.0.0.0/8. Zones are ignored.
type PrefixSet struct {
	ranges []addrRange // sorted, disjoint and not adjacent
	count  int
}

type addrRange struct {
	lo, hi netip.Addr
}

// NewPrefixSet builds a set from prefixes. Invalid prefixes are ignored.
func NewPrefixSet(prefixes ...netip.Prefix) *PrefixSet {
	ps := &PrefixSet{}
	ranges := make([]addrRange, 0, len(prefixes))
	for _, p := range prefixes {
		if p.IsValid() {
			p = NormalizePrefix(p)
			ranges = append(ranges, addrRange{lo: p.Addr(), hi: lastAddr(p)})
		}
	}
	ps.count = len(ranges)
	if len(ranges) == 0 {
		return ps
	}
	slices.SortFunc(ranges, func(a, b addrRange) int { return a.lo.Compare(b.lo) })
	merged := ranges[:1]
	for _, r := range ranges[1:] {
		last := &merged[len(merged)-1]
		if next := last.hi.Next(); next.IsValid() && r.lo.Compare(next) <= 0 && r.lo.BitLen() == last.hi.BitLen() {
			if r.hi.Compare(last.hi) > 0 {
				last.hi = r.hi
			}
			continue
		}
		if r.hi.Compare(last.hi) <= 0 && r.lo.BitLen() == last.hi.BitLen() {
			continue // inside the last range, which ends at the family's top
		}
		merged = append(merged, r)
	}
	// A copy, so that the ranges before merging are not kept.
	ps.ranges = slices.Clone(merged)
	return ps
}

// NormalizeAddr returns a as a PrefixSet compares it: without a zone, and an
// IPv4-mapped IPv6 address as IPv4.
func NormalizeAddr(a netip.Addr) netip.Addr {
	return a.Unmap().WithZone("")
}

// NormalizePrefix returns p as a PrefixSet keeps it: masked, and an IPv4-mapped
// IPv6 prefix of at least 96 bits as IPv4. Shorter IPv4-mapped prefixes,
// which hold more than IPv4 addresses, stay IPv6.
func NormalizePrefix(p netip.Prefix) netip.Prefix {
	addr, bits := p.Addr(), p.Bits()
	if addr.Is4In6() && bits >= 96 {
		addr, bits = addr.Unmap(), bits-96
	}
	return netip.PrefixFrom(addr, bits).Masked()
}

// Len returns the number of valid prefixes the set was built from.
func (ps *PrefixSet) Len() int {
	if ps == nil {
		return 0
	}
	return ps.count
}

// Contains reports whether a is inside one of the prefixes.
func (ps *PrefixSet) Contains(a netip.Addr) bool {
	a = NormalizeAddr(a)
	if ps == nil {
		return false
	}
	i, _ := slices.BinarySearchFunc(ps.ranges, a, func(r addrRange, a netip.Addr) int {
		if r.lo.Compare(a) > 0 {
			return 1
		}
		return -1
	})
	return i > 0 && a.Compare(ps.ranges[i-1].hi) <= 0
}

// lastAddr returns the highest address of a masked prefix.
func lastAddr(p netip.Prefix) netip.Addr {
	if p.Addr().Is4() {
		b := p.Addr().As4()
		setHostBits(b[:], p.Bits())
		return netip.AddrFrom4(b)
	}
	b := p.Addr().As16()
	setHostBits(b[:], p.Bits())
	return netip.AddrFrom16(b)
}

func setHostBits(b []byte, bits int) {
	for i := bits; i < len(b)*8; i++ {
		b[i/8] |= 1 << (7 - i%8)
	}
}

// Prefixes returns an independent slice of the fewest prefixes covering the set,
// in increasing address order. Len counts valid inputs, including duplicates.
func (ps *PrefixSet) Prefixes() []netip.Prefix {
	if ps == nil {
		return nil
	}
	var out []netip.Prefix
	for _, r := range ps.ranges {
		out = appendRangePrefixes(out, r.lo, r.hi)
	}
	return out
}

// appendRangePrefixes appends the fewest prefixes that cover lo to hi.
func appendRangePrefixes(dst []netip.Prefix, lo, hi netip.Addr) []netip.Prefix {
	for {
		// The shortest prefix that starts at lo and ends no later than hi.
		bits := lo.BitLen()
		for bits > 0 {
			wider := netip.PrefixFrom(lo, bits-1)
			if wider.Masked().Addr() != lo || lastAddr(wider).Compare(hi) > 0 {
				break
			}
			bits--
		}
		p := netip.PrefixFrom(lo, bits)
		dst = append(dst, p)
		end := lastAddr(p)
		if end.Compare(hi) >= 0 {
			return dst
		}
		lo = end.Next()
	}
}

// IsEmpty reports whether the set holds no address.
func (ps *PrefixSet) IsEmpty() bool { return ps.Len() == 0 }

// ParsePrefixSet returns the set of the given entries, each an IP prefix
// such as "10.0.0.0/8" or "2001:db8::/32" or an IP address such as
// "192.0.2.1" for itself alone, with spaces around it ignored and empty
// entries skipped. Every address is "0.0.0.0/0" and "::/0".
func ParsePrefixSet(entries ...string) (*PrefixSet, error) {
	prefixes := make([]netip.Prefix, 0, len(entries))
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if strings.IndexByte(e, '/') >= 0 {
			p, err := netip.ParsePrefix(e)
			if err != nil {
				return nil, &prefixError{e}
			}
			prefixes = append(prefixes, p)
			continue
		}
		a, err := netip.ParseAddr(e)
		if err != nil || a.Zone() != "" {
			return nil, &prefixError{e}
		}
		prefixes = append(prefixes, netip.PrefixFrom(a, a.BitLen()))
	}
	return NewPrefixSet(prefixes...), nil
}

type prefixError struct{ entry string }

func (e *prefixError) Error() string { return ErrInvalidPrefix.Error() + " " + strconv.Quote(e.entry) }
func (e *prefixError) Unwrap() error { return ErrInvalidPrefix }
