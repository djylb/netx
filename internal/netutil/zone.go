package netutil

import (
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// ScopeZone returns the zone of a link-local IPv6 address with scope ID
// scope: the name of the interface with that index, or the index itself when
// no interface has it. It returns "" for other addresses.
func ScopeZone(ip netip.Addr, scope uint32) string {
	if scope == 0 || !ip.Is6() || ip.Is4In6() || !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() {
		return ""
	}
	zones.Lock()
	if now := time.Now(); zones.names == nil || now.After(zones.expires) {
		zones.names, zones.expires = make(map[uint32]string), now.Add(time.Minute)
	}
	name, ok := zones.names[scope]
	zones.Unlock()
	if ok {
		return name
	}
	// Looked up without the lock, as it lists every interface: other
	// readers keep going meanwhile, and concurrent misses look up alike.
	name = strconv.FormatUint(uint64(scope), 10)
	if ifi, err := net.InterfaceByIndex(int(scope)); err == nil {
		name = ifi.Name
	}
	zones.Lock()
	if zones.names != nil {
		zones.names[scope] = name
	}
	zones.Unlock()
	return name
}

// zones caches interface names by index for a minute, since a lookup lists
// every interface and UDP needs one per datagram.
var zones struct {
	expires time.Time         // under the mutex
	names   map[uint32]string // under the mutex
	sync.Mutex
}
