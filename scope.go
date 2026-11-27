package netx

import (
	"net/netip"

	"github.com/djylb/netx/addrclass"
)

// Scope is the reachability class of an IP address. See addrclass.Scope.
type Scope = addrclass.Scope

// Scopes, from the narrowest to the widest reach. See addrclass.ScopeOf.
const (
	ScopeInvalid       = addrclass.ScopeInvalid
	ScopeUnspecified   = addrclass.ScopeUnspecified
	ScopeLoopback      = addrclass.ScopeLoopback
	ScopeLinkLocal     = addrclass.ScopeLinkLocal
	ScopePrivate       = addrclass.ScopePrivate
	ScopeShared        = addrclass.ScopeShared
	ScopeMulticast     = addrclass.ScopeMulticast
	ScopeBroadcast     = addrclass.ScopeBroadcast
	ScopeDocumentation = addrclass.ScopeDocumentation
	ScopeBenchmarking  = addrclass.ScopeBenchmarking
	ScopeReserved      = addrclass.ScopeReserved
	ScopeGlobal        = addrclass.ScopeGlobal
)

// ScopeOf returns the reachability class of a. See addrclass.ScopeOf.
func ScopeOf(a netip.Addr) Scope { return addrclass.ScopeOf(a) }

// IsGlobal reports whether a is globally reachable unicast.
func IsGlobal(a netip.Addr) bool { return addrclass.IsGlobal(a) }

// EmbeddedIPv4 returns the IPv4 address carried by a. See addrclass.EmbeddedIPv4.
func EmbeddedIPv4(a netip.Addr) (netip.Addr, bool) { return addrclass.EmbeddedIPv4(a) }
