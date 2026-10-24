package forwarded

import (
	"cmp"
	"encoding/binary"
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
	v4 []span4 // sorted, disjoint and not adjacent
	v6 []span6
}

type span4 struct{ first, last uint32 }

type u128 struct{ hi, lo uint64 }

func (a u128) less(b u128) bool { return a.hi < b.hi || a.hi == b.hi && a.lo < b.lo }

type span6 struct{ first, last u128 }

// NewPrefixSet returns the set of the given prefixes. Invalid prefixes,
// such as the zero netip.Prefix, are left out; host bits are ignored, so
// 192.0.2.1/24 is 192.0.2.0/24.
func NewPrefixSet(prefixes ...netip.Prefix) *PrefixSet {
	s := &PrefixSet{}
	for _, p := range prefixes {
		if !p.IsValid() {
			continue
		}
		a, bits := p.Addr().WithZone(""), p.Bits()
		if a.Is4In6() && bits >= 96 {
			a, bits = a.Unmap(), bits-96
		}
		if a.Is4() {
			b := a.As4()
			v := binary.BigEndian.Uint32(b[:])
			host := uint32(0xffffffff) >> bits // a shift by 32 gives 0
			s.v4 = append(s.v4, span4{v &^ host, v | host})
			continue
		}
		b := a.As16()
		v := u128{binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:])}
		var host u128
		switch {
		case bits < 64:
			host = u128{^uint64(0) >> bits, ^uint64(0)}
		default:
			host = u128{0, ^uint64(0) >> (bits - 64)}
		}
		s.v6 = append(s.v6, span6{u128{v.hi &^ host.hi, v.lo &^ host.lo}, u128{v.hi | host.hi, v.lo | host.lo}})
	}
	s.v4 = merge4(s.v4)
	s.v6 = merge6(s.v6)
	return s
}

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

// Contains reports whether a is in the set.
func (s *PrefixSet) Contains(a netip.Addr) bool {
	if s == nil {
		return false
	}
	if a.Is4In6() {
		a = a.Unmap()
	}
	if a.Is4() {
		b := a.As4()
		v := binary.BigEndian.Uint32(b[:])
		lo, hi := 0, len(s.v4)
		for lo < hi { // the first span that ends at or after v
			m := int(uint(lo+hi) >> 1)
			if s.v4[m].last < v {
				lo = m + 1
			} else {
				hi = m
			}
		}
		return lo < len(s.v4) && s.v4[lo].first <= v
	}
	if !a.Is6() {
		return false
	}
	b := a.As16()
	v := u128{binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:])}
	lo, hi := 0, len(s.v6)
	for lo < hi {
		m := int(uint(lo+hi) >> 1)
		if s.v6[m].last.less(v) {
			lo = m + 1
		} else {
			hi = m
		}
	}
	return lo < len(s.v6) && !v.less(s.v6[lo].first)
}

// IsEmpty reports whether the set holds no address.
func (s *PrefixSet) IsEmpty() bool { return s == nil || len(s.v4) == 0 && len(s.v6) == 0 }

func merge4(spans []span4) []span4 {
	slices.SortFunc(spans, func(a, b span4) int { return cmp.Compare(a.first, b.first) })
	out := spans[:0]
	for _, sp := range spans {
		if n := len(out); n > 0 && (out[n-1].last == 0xffffffff || sp.first <= out[n-1].last+1) {
			out[n-1].last = max(out[n-1].last, sp.last)
			continue
		}
		out = append(out, sp)
	}
	return slices.Clip(out)
}

func merge6(spans []span6) []span6 {
	slices.SortFunc(spans, func(a, b span6) int {
		switch {
		case a.first.less(b.first):
			return -1
		case b.first.less(a.first):
			return 1
		}
		return 0
	})
	out := spans[:0]
	for _, sp := range spans {
		if n := len(out); n > 0 {
			last := out[n-1].last
			next := u128{last.hi, last.lo + 1}
			if next.lo == 0 {
				next.hi++
			}
			full := last.hi == ^uint64(0) && last.lo == ^uint64(0)
			if full || !next.less(sp.first) {
				if last.less(sp.last) {
					out[n-1].last = sp.last
				}
				continue
			}
		}
		out = append(out, sp)
	}
	return slices.Clip(out)
}
