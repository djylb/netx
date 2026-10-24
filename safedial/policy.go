package safedial

import (
	"cmp"
	"errors"
	"net/netip"
	"slices"
	"strings"

	"github.com/djylb/netx"
	"github.com/djylb/netx/internal/netutil"
)

// Policy decides which targets may be reached. Check returns nil to allow
// t, or the reason to refuse it, which Dialer and the packet wrappers
// return in a *DeniedError. It is called for a host name before the name
// is resolved, with t.Addr invalid, so that names can be refused without a
// lookup, and for each address dialed or sent to; a policy on addresses
// returns nil for a name, and one on names, for an IP address dialed as
// such, decides by the empty Name. A Policy must be safe for concurrent use
// and should not allocate when it allows, so that the per-datagram checks
// of the packet wrappers do not.
type Policy interface {
	Check(t Target) error
}

// PolicyFunc is a Policy as a function.
type PolicyFunc func(t Target) error

// Check returns f(t).
func (f PolicyFunc) Check(t Target) error { return f(t) }

// Reasons that the policies of this package refuse a target with. The
// reasons of scope policies name the scope and match ErrScope.
var (
	// ErrScope refuses an address of a scope that the policy does not allow.
	ErrScope = errors.New("safedial: address scope not allowed")
	// ErrPrefix refuses an address outside the allowed prefixes or in a
	// denied one.
	ErrPrefix = errors.New("safedial: address range not allowed")
	// ErrPort refuses a port.
	ErrPort = errors.New("safedial: port not allowed")
	// ErrName refuses a host name, or an IP address where only names are
	// allowed.
	ErrName = errors.New("safedial: host name not allowed")
	// errNoPolicy is the reason of Any without policies.
	errNoPolicy = errors.New("safedial: no policy allows the target")
)

// scopeError is the reason that a scope policy refuses a scope with.
type scopeError struct{ scope netx.Scope }

func (e *scopeError) Error() string { return "safedial: " + e.scope.String() + " address not allowed" }
func (e *scopeError) Unwrap() error { return ErrScope }

// scopeErrors holds the reason of each scope, so that a refusal does not
// allocate.
var scopeErrors = func() (errs [netx.ScopeGlobal + 1]error) {
	for s := range errs {
		errs[s] = &scopeError{netx.Scope(s)}
	}
	return errs
}()

// scopePolicy allows the scopes in its bit set.
type scopePolicy uint32

func (p scopePolicy) Check(t Target) error {
	if !t.Addr.IsValid() && t.Name != "" {
		return nil // a name, decided by its addresses
	}
	s := netx.ScopeOf(t.Addr) // ScopeInvalid for a target of neither
	if p&(1<<s) != 0 {
		return nil
	}
	return scopeErrors[s]
}

// defaultPolicy allows global unicast addresses alone.
const defaultPolicy = scopePolicy(1 << netx.ScopeGlobal)

// DefaultPolicy returns the policy of a Dialer without one: it allows
// every host name and port, and only globally reachable unicast addresses,
// AllowScopes(netx.ScopeGlobal). It refuses loopback, private, link-local,
// shared (carrier-grade NAT), unspecified, multicast, broadcast,
// documentation, benchmarking and reserved addresses, and translation
// addresses (NAT64, 6to4, Teredo) that embed such an IPv4 address, as
// netx.ScopeOf classifies them.
func DefaultPolicy() Policy { return defaultPolicy }

// AllowScopes returns a policy that allows only the addresses of scopes, as
// netx.ScopeOf classifies them, and every name. A target with neither an
// address nor a name, of ScopeInvalid, is refused whatever scopes holds.
func AllowScopes(scopes ...netx.Scope) Policy {
	var p scopePolicy
	for _, s := range scopes {
		if s <= netx.ScopeGlobal {
			p |= 1 << s
		}
	}
	return p &^ (1 << netx.ScopeInvalid)
}

// DenyScopes returns a policy that refuses the addresses of scopes, as
// netx.ScopeOf classifies them, and a target with neither an address nor a
// name, and allows every name.
func DenyScopes(scopes ...netx.Scope) Policy {
	p := scopePolicy(1<<(netx.ScopeGlobal+1) - 1)
	for _, s := range scopes {
		if s <= netx.ScopeGlobal {
			p &^= 1 << s
		}
	}
	return p &^ (1 << netx.ScopeInvalid)
}

// prefixPolicy matches addresses against disjoint prefixes sorted by
// address, so that a lookup is a binary search.
type prefixPolicy struct {
	prefixes []netip.Prefix
	allow    bool // allow the addresses in prefixes, or refuse them
	invalid  bool // an invalid prefix was given: refuse every address
}

func newPrefixPolicy(prefixes []netip.Prefix, allow bool) *prefixPolicy {
	p := &prefixPolicy{allow: allow}
	var all []netip.Prefix
	for _, prefix := range prefixes {
		unmapped := netutil.UnmappedPrefixes(prefix)
		if len(unmapped) == 0 {
			p.invalid = true
		}
		all = append(all, unmapped...)
	}
	slices.SortFunc(all, func(a, b netip.Prefix) int {
		return cmp.Or(a.Addr().Compare(b.Addr()), cmp.Compare(a.Bits(), b.Bits()))
	})
	// A prefix sorts after the one that holds it: keep the holders alone.
	for _, prefix := range all {
		if n := len(p.prefixes); n > 0 && p.prefixes[n-1].Contains(prefix.Addr()) {
			continue
		}
		p.prefixes = append(p.prefixes, prefix)
	}
	return p
}

// contains reports whether a is in one of p's prefixes. It does not
// allocate.
func (p *prefixPolicy) contains(a netip.Addr) bool {
	i, _ := slices.BinarySearchFunc(p.prefixes, a, func(prefix netip.Prefix, a netip.Addr) int {
		if prefix.Addr().Compare(a) <= 0 {
			return -1
		}
		return 1
	})
	// i is the first prefix that starts after a.
	return i > 0 && p.prefixes[i-1].Contains(a)
}

func (p *prefixPolicy) Check(t Target) error {
	if !t.Addr.IsValid() {
		if t.Name != "" {
			return nil // a name, decided by its addresses
		}
		return ErrPrefix // neither an address nor a name
	}
	// Targets come unmapped and without a zone; one made otherwise is
	// matched as one that comes so.
	if p.invalid || p.contains(t.Addr.Unmap().WithZone("")) != p.allow {
		return ErrPrefix
	}
	return nil
}

// AllowPrefixes returns a policy that allows only the addresses in
// prefixes, and every name. Prefixes are matched against the address as
// dialed, unmapped, so an IPv4-mapped prefix such as ::ffff:10.0.0.0/104
// stands for its IPv4 prefix; an address that embeds another, as NAT64 and
// 6to4 addresses do, matches by its own form alone. An invalid prefix, such
// as the zero netip.Prefix, makes the policy refuse every address, failing
// closed. Lookups are binary searches that do not allocate.
func AllowPrefixes(prefixes ...netip.Prefix) Policy { return newPrefixPolicy(prefixes, true) }

// DenyPrefixes returns a policy that refuses the addresses in prefixes,
// matched as AllowPrefixes matches them, and allows every name. An invalid
// prefix makes it refuse every address.
func DenyPrefixes(prefixes ...netip.Prefix) Policy { return newPrefixPolicy(prefixes, false) }

// portPolicy holds a bit for each port.
type portPolicy struct {
	set   [1 << 16 / 64]uint64
	allow bool
}

func (p *portPolicy) add(from, to uint16) {
	for port := int(from); port <= int(to); port++ {
		p.set[port/64] |= 1 << (port % 64)
	}
}

func (p *portPolicy) Check(t Target) error {
	if (p.set[t.Port/64]&(1<<(t.Port%64)) != 0) != p.allow {
		return ErrPort
	}
	return nil
}

// AllowPorts returns a policy that allows only ports, for names and
// addresses alike.
func AllowPorts(ports ...uint16) Policy { return newPortPolicy(ports, true) }

// DenyPorts returns a policy that refuses ports.
func DenyPorts(ports ...uint16) Policy { return newPortPolicy(ports, false) }

// AllowPortRange returns a policy that allows only the ports from from to
// to, inclusive; none if to is below from.
func AllowPortRange(from, to uint16) Policy {
	p := &portPolicy{allow: true}
	p.add(from, to)
	return p
}

// DenyPortRange returns a policy that refuses the ports from from to to,
// inclusive.
func DenyPortRange(from, to uint16) Policy {
	p := &portPolicy{}
	p.add(from, to)
	return p
}

func newPortPolicy(ports []uint16, allow bool) *portPolicy {
	p := &portPolicy{allow: allow}
	for _, port := range ports {
		p.add(port, port)
	}
	return p
}

// namePolicy matches names against patterns, looking up each suffix of a
// name that starts at a label in maps, so that a check takes as many map
// lookups as the name has labels.
type namePolicy struct {
	domains map[string]struct{} // match the name and the names under it
	subs    map[string]struct{} // match the names under it
	allow   bool
	invalid bool // a pattern was no host name
}

func (p *namePolicy) match(name string) bool {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return false
	}
	if _, ok := p.domains[name]; ok {
		return true
	}
	for i := range len(name) {
		if name[i] != '.' {
			continue
		}
		suffix := name[i+1:]
		if _, ok := p.domains[suffix]; ok {
			return true
		}
		if _, ok := p.subs[suffix]; ok {
			return true
		}
	}
	return false
}

func (p *namePolicy) Check(t Target) error {
	if p.invalid && !p.allow && t.Name != "" {
		return ErrName // an invalid pattern refuses every name
	}
	if p.match(t.Name) != p.allow {
		return ErrName
	}
	return nil
}

func newNamePolicy(patterns []string, allow bool) *namePolicy {
	p := &namePolicy{domains: make(map[string]struct{}), subs: make(map[string]struct{}), allow: allow}
	for _, pattern := range patterns {
		pattern = strings.TrimSuffix(strings.TrimSpace(pattern), ".")
		set := p.domains
		if rest, ok := strings.CutPrefix(pattern, "*."); ok {
			pattern, set = rest, p.subs
		} else if rest, ok := strings.CutPrefix(pattern, "."); ok {
			pattern, set = rest, p.subs
		}
		if pattern == "" {
			continue
		}
		// Names are matched in their ASCII form, as they are dialed.
		ascii, ok := netutil.ToASCII(pattern)
		if !ok || !validName(ascii) {
			p.invalid = true
			continue
		}
		set[ascii] = struct{}{}
	}
	return p
}

// AllowNames returns a policy that allows only the host names that match
// patterns, refusing IP addresses that are dialed as such, and allows every
// address that an allowed name resolves to. A pattern matches the name
// itself and every name under it, so that "example.com" matches
// "example.com" and "www.example.com"; one that starts with "*." or "."
// matches only the names under it. Matching ignores case and a trailing
// dot, and an internationalised pattern matches in its ASCII (punycode)
// form, as names are dialed; a pattern that is no host name, such as one
// with spaces or an IP address, matches nothing.
//
// An allowed name may resolve to any address, also loopback, link-local
// (such as a cloud metadata service at 169.254.169.254), unspecified or
// multicast ones, by whoever controls its DNS. Combined with Any, restrict
// the scopes that such names may reach:
//
//	// Names under intranet.example may resolve to private addresses; other
//	// names and IP addresses must be global.
//	safedial.Any(
//		safedial.All(safedial.AllowNames("intranet.example"), safedial.AllowScopes(netx.ScopePrivate, netx.ScopeGlobal)),
//		safedial.DefaultPolicy(),
//	)
func AllowNames(patterns ...string) Policy { return newNamePolicy(patterns, true) }

// DenyNames returns a policy that refuses the host names that match
// patterns, matched as AllowNames matches them, before they are resolved.
// It allows IP addresses dialed as such. A pattern that is no host name
// makes it refuse every name, failing closed. Name rules decide on names
// alone: another name, or an IP address, that reaches the same host is not
// refused by them, so pair them with address rules to keep a host out.
func DenyNames(patterns ...string) Policy { return newNamePolicy(patterns, false) }

type allPolicy []Policy

func (ps allPolicy) Check(t Target) error {
	for _, p := range ps {
		if err := p.Check(t); err != nil {
			return err
		}
	}
	return nil
}

type anyPolicy []Policy

func (ps anyPolicy) Check(t Target) error {
	err := errNoPolicy
	for _, p := range ps {
		if err = p.Check(t); err == nil {
			return nil
		}
	}
	return err
}

// All returns a policy that allows a target that every one of policies
// allows, and otherwise returns the reason of the first that refuses it.
// Nil policies are skipped; without policies, it allows every target.
func All(policies ...Policy) Policy { return allPolicy(nonNil(policies)) }

// Any returns a policy that allows a target that one of policies allows,
// and otherwise returns the reason of the last. Nil policies are skipped;
// without policies, it refuses every target.
func Any(policies ...Policy) Policy { return anyPolicy(nonNil(policies)) }

func nonNil(policies []Policy) []Policy {
	out := make([]Policy, 0, len(policies))
	for _, p := range policies {
		if p != nil {
			out = append(out, p)
		}
	}
	return out
}
