package tlsconn

import (
	"crypto/x509"
	"errors"
	"net/netip"
	"slices"
	"strings"

	"github.com/djylb/netx/internal/netutil"
)

var (
	// ErrInvalidName is the error of a name that is not a DNS name, as
	// CanonicalName takes it.
	ErrInvalidName = errors.New("tlsconn: invalid DNS name")
	// ErrNotCovered is the error of VerifyDomain for a certificate that
	// covers no name at or under the domain.
	ErrNotCovered = errors.New("tlsconn: certificate covers no name under the domain")
	// ErrOnlySubdomains is the error of VerifyDomain for a certificate that
	// covers some names under the domain but not the domain itself.
	ErrOnlySubdomains = errors.New("tlsconn: certificate covers only some subdomains, not the domain")
)

// maxNameLen is the longest DNS name in text form without its trailing
// dot, and maxLabelLen the longest label: the limits of the DNS encoding.
const (
	maxNameLen  = 253
	maxLabelLen = 63
)

// CanonicalName returns name in the form in which this package compares DNS
// names: lowercase, international labels in their ASCII (A-label, "xn--")
// form, and without a trailing dot. Two names are the same name exactly
// when their canonical forms are equal.
//
// A label holding non-ASCII characters is lowercased and Punycode-encoded,
// without the further mapping of UTS #46 (such as of full-width characters
// or dots), so pass the A-label form for names that need it; a name that
// maps differently only fails to match. It fails with ErrInvalidName for a
// name that is not a DNS host name: empty labels, labels other than letters,
// digits, hyphens and underscores, a hyphen at the start or end of a label,
// labels over 63 bytes or a name over 253, a wildcard, an IP address, or a
// last label of digits only, which URL parsers read as an IPv4 address.
func CanonicalName(name string) (string, error) {
	n := strings.TrimSuffix(name, ".")
	if !netutil.IsASCII(n) {
		var ok bool
		if n, ok = netutil.ToASCII(n); !ok {
			return "", ErrInvalidName
		}
	} else {
		n = strings.ToLower(n)
	}
	if _, ok := checkName(n); !ok {
		return "", ErrInvalidName
	}
	return n, nil
}

// Covers reports whether cert covers name: a DNS name, matched by RFC 6125
// and RFC 9525 against the certificate's DNS subject alternative names, or
// an IP address, matched against its IP address names only. See Names for
// the rules; Covers is CertNames(cert).Covers(name) without building the
// Names.
func Covers(cert *x509.Certificate, name string) bool {
	if cert == nil {
		return false
	}
	if ip, ok := parseIP(name); ok {
		for _, raw := range cert.IPAddresses {
			if a, ok := netip.AddrFromSlice(raw); ok && a.Unmap() == ip {
				return true
			}
		}
		return false
	}
	n, err := CanonicalName(name)
	if err != nil {
		return false
	}
	// n is valid, so a name equal to it is too, and a wildcard base equal
	// to its parent only needs two labels; this skips checking the others.
	parent := parentOf(n)
	wildcards := strings.IndexByte(parent, '.') > 0
	for _, san := range cert.DNSNames {
		s := strings.TrimSuffix(san, ".")
		if base, found := strings.CutPrefix(s, "*."); found {
			if wildcards && equalLower(base, parent) {
				return true
			}
		} else if equalLower(s, n) {
			return true
		}
	}
	return false
}

// equalLower reports whether s, lowercased in ASCII only, is lower.
func equalLower(s, lower string) bool {
	if len(s) != len(lower) {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != lower[i] {
			return false
		}
	}
	return true
}

// Names are the names a certificate covers, as CertNames returns them, in
// canonical form (see CanonicalName), sorted and without duplicates.
//
// The rules are those of RFC 6125 and RFC 9525 and the CA/Browser Forum's:
//
//   - Only subject alternative names count. The subject's common name is
//     never used, also when there are no alternative names, as crypto/x509
//     and browsers do.
//   - A DNS name covers exactly that name.
//   - A wildcard covers the names one label below its base, the rest of it:
//     *.example.com covers a.example.com, but neither example.com nor
//     a.b.example.com. The wildcard must be the whole leftmost label, and
//     its base must have at least two labels, so *.com, f*.example.com,
//     *a.example.com and a.*.example.com cover nothing. A suffix list is not
//     consulted: a certificate issued by a public authority has no wildcard
//     directly under a public suffix such as *.co.uk, but one that a
//     private root signs may.
//   - IP address names cover their addresses, and are matched apart from DNS
//     names: a wildcard never covers an address, and a DNS name that is an
//     address covers nothing.
//   - A name that CanonicalName rejects covers nothing; it is listed in
//     Invalid.
//
// No name covers its subdomains: a certificate only covers each name it
// lists, and each name one label below each wildcard.
type Names struct {
	// DNS are the exact DNS names.
	DNS []string
	// Wildcards are the wildcard patterns, such as *.example.com.
	Wildcards []string
	// IPs are the IP addresses, IPv4 ones in their 4-byte form.
	IPs []netip.Addr
	// Invalid are the DNS names that cover nothing, as the certificate has
	// them.
	Invalid []string
}

// CertNames returns the names cert covers.
func CertNames(cert *x509.Certificate) Names {
	var n Names
	if cert == nil {
		return n
	}
	for _, san := range cert.DNSNames {
		base, wildcard, ok := sanName(san)
		switch {
		case !ok:
			n.Invalid = append(n.Invalid, san)
		case wildcard:
			n.Wildcards = append(n.Wildcards, "*."+base)
		default:
			n.DNS = append(n.DNS, base)
		}
	}
	for _, raw := range cert.IPAddresses {
		if a, ok := netip.AddrFromSlice(raw); ok {
			n.IPs = append(n.IPs, a.Unmap())
		}
	}
	slices.Sort(n.DNS)
	n.DNS = slices.Compact(n.DNS)
	slices.Sort(n.Wildcards)
	n.Wildcards = slices.Compact(n.Wildcards)
	slices.SortFunc(n.IPs, netip.Addr.Compare)
	n.IPs = slices.Compact(n.IPs)
	return n
}

// Covers reports whether n covers name, a DNS name or an IP address, by the
// rules of Names. It takes time logarithmic in the number of names.
func (n Names) Covers(name string) bool {
	if ip, ok := parseIP(name); ok {
		_, found := slices.BinarySearchFunc(n.IPs, ip, netip.Addr.Compare)
		return found
	}
	c, err := CanonicalName(name)
	if err != nil {
		return false
	}
	if _, found := slices.BinarySearch(n.DNS, c); found {
		return true
	}
	return n.coversByWildcard(c)
}

// coversByWildcard reports whether a wildcard of n covers the canonical name.
func (n Names) coversByWildcard(name string) bool {
	parent := parentOf(name)
	if parent == "" {
		return false
	}
	// Every pattern starts with "*.", so they sort as their bases do.
	_, found := slices.BinarySearchFunc(n.Wildcards, parent, func(p, base string) int {
		return strings.Compare(p[2:], base)
	})
	return found
}

// DomainCoverage is what a certificate covers at and under a domain, as
// Names.Under and VerifyDomain return it.
//
// It lists names, not a subtree: no certificate covers every name under a
// domain, since a wildcard covers one label and other names only
// themselves, so coverage of a domain is never authority over its
// descendants. A certificate for *.example.com covers a.example.com but
// neither example.com (Apex is false) nor a.b.example.com; one for
// example.com covers example.com alone. Ask Covers for each name.
type DomainCoverage struct {
	// Domain is the domain asked about, in canonical form.
	Domain string
	// Subdomains are the exact names strictly under Domain.
	Subdomains []string
	// Wildcards are the patterns *.x for x Domain or a name under it; each
	// covers the names one label below x, and not x.
	Wildcards []string
	// Apex reports whether Domain itself is covered.
	Apex bool
	// ApexByWildcard reports whether Domain is covered only by a wildcard
	// for its parent, not by its exact name.
	ApexByWildcard bool
}

// Under returns what n covers at and under domain, or ErrInvalidName if
// CanonicalName rejects domain.
func (n Names) Under(domain string) (DomainCoverage, error) {
	d, err := CanonicalName(domain)
	if err != nil {
		return DomainCoverage{}, err
	}
	c := DomainCoverage{Domain: d}
	if _, found := slices.BinarySearch(n.DNS, d); found {
		c.Apex = true
	} else if n.coversByWildcard(d) {
		c.Apex, c.ApexByWildcard = true, true
	}
	for _, name := range n.DNS {
		if name != d && isUnder(name, d) {
			c.Subdomains = append(c.Subdomains, name)
		}
	}
	for _, p := range n.Wildcards {
		if isUnder(p[2:], d) {
			c.Wildcards = append(c.Wildcards, p)
		}
	}
	return c, nil
}

// Empty reports whether c covers no name.
func (c DomainCoverage) Empty() bool {
	return !c.Apex && len(c.Subdomains) == 0 && len(c.Wildcards) == 0
}

// Covers reports whether c covers name, which must be Domain or under it:
// Domain itself if Apex, an exact name of Subdomains, or a name one label
// below the base of one of Wildcards.
func (c DomainCoverage) Covers(name string) bool {
	n, err := CanonicalName(name)
	if err != nil || c.Domain == "" || !isUnder(n, c.Domain) {
		return false
	}
	if n == c.Domain {
		return c.Apex
	}
	if _, found := slices.BinarySearch(c.Subdomains, n); found {
		return true
	}
	return Names{Wildcards: c.Wildcards}.coversByWildcard(n)
}

// VerifyDomain verifies chain with VerifyChain and checks that its leaf
// covers domain itself, exactly or by a wildcard for its parent, returning
// what it covers at and under domain. A certificate that covers only names
// under domain, such as one for a.example.com or *.example.com asked about
// example.com, fails with ErrOnlySubdomains, and one that covers none with
// ErrNotCovered; both errors come with the coverage, so a caller that means
// to accept subdomains says so by handling ErrOnlySubdomains and then checks
// each name it grants with DomainCoverage.Covers. A self-signed certificate
// fails with ErrSelfSigned unless opts.Roots trusts it: anyone can make one
// for any name.
//
// Coverage of domain is not authority over the names under it: grant
// exactly the names Covers reports, never the subtree. A chain only shows
// that an authority vouched for the names, and it is public, so before
// taking it as a user's claim also have the user prove that they hold its
// private key, such as with a Challenger. Use explicit opts.Roots for
// uploaded certificates; see VerifyOptions.
func VerifyDomain(chain []*x509.Certificate, domain string, opts VerifyOptions) (DomainCoverage, error) {
	d, err := CanonicalName(domain)
	if err != nil {
		return DomainCoverage{}, err
	}
	if _, err := VerifyChain(chain, opts); err != nil {
		return DomainCoverage{}, err
	}
	c, err := CertNames(chain[0]).Under(d)
	if err != nil {
		return DomainCoverage{}, err
	}
	switch {
	case c.Empty():
		return c, ErrNotCovered
	case !c.Apex:
		return c, ErrOnlySubdomains
	}
	return c, nil
}

// sanName returns the canonical form of a DNS subject alternative name, or
// of the base of a wildcard one, or ok false for one that covers nothing.
// A certificate's names are ASCII (IA5String); non-ASCII ones are invalid.
func sanName(san string) (name string, wildcard, ok bool) {
	s := strings.TrimSuffix(san, ".")
	if base, found := strings.CutPrefix(s, "*."); found {
		s, wildcard = base, true
	}
	if !netutil.IsASCII(s) {
		return "", false, false
	}
	s = strings.ToLower(s)
	labels, ok := checkName(s)
	if !ok || wildcard && labels < 2 {
		return "", false, false
	}
	return s, wildcard, true
}

// checkName reports whether n, lowercase ASCII without a trailing dot, is a
// valid DNS host name by the rules of CanonicalName, and its label count.
// An IP address fails too: IPv4 by its last label of digits, IPv6 by its
// colons.
func checkName(n string) (labels int, ok bool) {
	if n == "" || len(n) > maxNameLen {
		return 0, false
	}
	start, allDigits := 0, true
	for i := 0; i <= len(n); i++ {
		if i < len(n) && n[i] != '.' {
			switch c := n[i]; {
			case c >= '0' && c <= '9':
			case c >= 'a' && c <= 'z', c == '-', c == '_':
				allDigits = false
			default:
				return 0, false
			}
			continue
		}
		label := n[start:i]
		if label == "" || len(label) > maxLabelLen || label[0] == '-' || label[len(label)-1] == '-' {
			return 0, false
		}
		labels++
		if i < len(n) {
			start, allDigits = i+1, true
		}
	}
	if allDigits {
		return 0, false
	}
	return labels, true
}

// parseIP returns the address that name is, unmapped, if it is one without
// a zone.
func parseIP(name string) (netip.Addr, bool) {
	// Skip names that cannot be one, as ParseAddr allocates its error.
	if name == "" || strings.IndexByte(name, ':') < 0 && (name[len(name)-1] < '0' || name[len(name)-1] > '9') {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(name)
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// parentOf returns name without its first label, or "" for a single label.
func parentOf(name string) string {
	if i := strings.IndexByte(name, '.'); i > 0 {
		return name[i+1:]
	}
	return ""
}

// isUnder reports whether name is domain or a name under it.
func isUnder(name, domain string) bool {
	return name == domain || len(name) > len(domain) && name[len(name)-len(domain)-1] == '.' && strings.HasSuffix(name, domain)
}
