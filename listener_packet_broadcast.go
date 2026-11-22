package netx

import (
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/djylb/timeshim"
)

// packetBroadcasts caches the broadcast addresses of local IPv4 subnets.
// Readers keep using their snapshot while one worker refreshes it.
type packetBroadcasts struct {
	snapshot atomic.Pointer[packetBroadcastSnapshot]
	refresh  chan struct{}
}

type packetBroadcastSnapshot struct {
	expires time.Time
	addrs   map[netip.Addr]struct{}
}

const packetBroadcastTTL = time.Second

func (b *packetBroadcasts) init(clock timeshim.Clock) {
	b.refresh = make(chan struct{}, 1)
	b.reload(clock)
}

func (b *packetBroadcasts) isGroup(addr netip.Addr, clock timeshim.Clock) bool {
	if isIntrinsicPacketGroup(addr) {
		return true
	}
	if !mayBeDirectedBroadcast(addr) {
		return false
	}
	s := b.snapshot.Load()
	if s == nil {
		return false
	}
	if !clock.Now().Before(s.expires) {
		select {
		case b.refresh <- struct{}{}:
		default:
		}
	}
	_, ok := s.addrs[addr]
	return ok
}

func (b *packetBroadcasts) run(clock timeshim.Clock, done <-chan struct{}) {
	for {
		select {
		case <-done:
			return
		case <-b.refresh:
		}
		// A request queued during the last refresh may already be satisfied.
		if !clock.Now().Before(b.snapshot.Load().expires) {
			b.reload(clock)
		}
	}
}

func (b *packetBroadcasts) reload(clock timeshim.Clock) {
	broadcasts, err := readPacketBroadcastAddrs()
	if err != nil {
		if previous := b.snapshot.Load(); previous != nil {
			broadcasts = previous.addrs
		}
	}
	b.snapshot.Store(&packetBroadcastSnapshot{expires: clock.Now().Add(packetBroadcastTTL), addrs: broadcasts})
}

func isIntrinsicPacketGroup(addr netip.Addr) bool {
	return addr.IsMulticast() || addr == netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

func mayBeDirectedBroadcast(addr netip.Addr) bool {
	return addr.Is4() && addr.As4()[3]&1 != 0
}

// confirmedPacketGroup uses current interface addresses on the write
// error path. A stale broadcast snapshot cannot permanently change a flow.
func confirmedPacketGroup(addr netip.Addr) bool {
	if isIntrinsicPacketGroup(addr) {
		return true
	}
	if !mayBeDirectedBroadcast(addr) {
		return false
	}
	broadcasts, err := readPacketBroadcastAddrs()
	if err != nil {
		return false
	}
	_, ok := broadcasts[addr]
	return ok
}

func readPacketBroadcastAddrs() (map[netip.Addr]struct{}, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	broadcasts := make(map[netip.Addr]struct{})
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := n.IP.To4()
		bits, size := n.Mask.Size()
		if ip == nil || size != 32 || bits >= 31 {
			continue
		}
		var addr [4]byte
		for i := range addr {
			addr[i] = ip[i] | ^n.Mask[i]
		}
		broadcasts[netip.AddrFrom4(addr)] = struct{}{}
	}
	return broadcasts, nil
}
