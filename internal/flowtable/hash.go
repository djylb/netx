package flowtable

import (
	"encoding/binary"
	"hash/maphash"
	"net/netip"
)

// WriteAddrPort writes an endpoint to a shard hash. The address family and
// length of the zone distinguish components when several endpoints are hashed.
func WriteAddrPort(h *maphash.Hash, ap netip.AddrPort) {
	addr := ap.Addr()
	var b [27]byte
	switch {
	case addr.Is4():
		b[0] = 4
	case addr.Is6():
		b[0] = 6
	}
	ip := addr.As16()
	copy(b[1:17], ip[:])
	binary.LittleEndian.PutUint16(b[17:19], ap.Port())
	zone := addr.Zone()
	binary.LittleEndian.PutUint64(b[19:], uint64(len(zone)))
	_, _ = h.Write(b[:]) // maphash.Hash writes never fail
	_, _ = h.WriteString(zone)
}
