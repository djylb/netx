package socks5

import (
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/djylb/netx"
	"github.com/djylb/netx/internal/dgram"
)

// ErrLookupBusy drops a datagram to a name that a PacketConn of
// NewPacketConn is looking up, or is to look up, while it holds as many
// datagrams, or runs as many lookups, as it may.
var ErrLookupBusy = errors.New("socks5: too many datagrams wait for name lookups")

// The bounds of the datagrams that NewPacketConn holds for lookups.
const (
	maxLookups       = 64        // names looked up at once
	maxLookupQueue   = 16        // datagrams held per name
	maxLookupHeldLen = 256 << 10 // bytes held in all
)

// nameLookup holds the datagrams to a name while it is looked up.
type nameLookup struct {
	queue []heldDatagram
}

type heldDatagram struct {
	bp   *[]byte
	port uint16
}

// route returns the cached address of dst's name, or holds a copy of p for
// a lookup of the name, starting one if none runs, and reports whether it
// did.
func (u *udpPacketConn) route(p []byte, dst netx.Addr) (ip netip.Addr, held bool, err error) {
	name := dst.Name
	u.mu.Lock()
	defer u.mu.Unlock()
	// A running lookup takes the datagram even if the name has a fresh
	// entry, so that it is not sent before the datagrams held.
	l := u.lookups[name]
	if l == nil {
		if entry, ok := u.names[name]; ok && time.Now().Before(entry.expires) {
			return entry.ip, false, entry.err
		}
		if u.ctx.Err() != nil {
			return netip.Addr{}, false, net.ErrClosed
		}
		if len(u.lookups) >= maxLookups {
			return netip.Addr{}, false, ErrLookupBusy
		}
		l = new(nameLookup)
		u.lookups[name] = l
		go u.lookupAndSend(name, l)
	}
	if len(l.queue) >= maxLookupQueue || u.held+len(p) > maxLookupHeldLen {
		return netip.Addr{}, false, ErrLookupBusy
	}
	var bp *[]byte
	if len(p) <= dgram.SmallSize {
		bp = dgram.Small.Get()
		*bp = (*bp)[:len(p)]
	} else {
		bp = dgram.NewBuf(len(p))
	}
	copy(*bp, p)
	l.queue = append(l.queue, heldDatagram{bp: bp, port: dst.Port})
	u.held += len(p)
	return netip.Addr{}, true, nil
}

// lookupAndSend resolves name and then sends the datagrams that l holds,
// also those held while it sends, or drops them when the lookup failed or u
// is closed.
func (u *udpPacketConn) lookupAndSend(name string, l *nameLookup) {
	ip, err := u.resolve(name)
	var batch []heldDatagram
	for {
		u.mu.Lock()
		batch, l.queue = l.queue, batch[:0]
		if len(batch) == 0 {
			delete(u.lookups, name)
			u.mu.Unlock()
			return
		}
		for _, d := range batch {
			u.held -= len(*d.bp)
		}
		u.mu.Unlock()
		for i, d := range batch {
			if err == nil && u.ctx.Err() == nil {
				_, _ = u.c.WriteToUDPAddrPort(*d.bp, netip.AddrPortFrom(ip, d.port))
			}
			dgram.Release(d.bp)
			batch[i] = heldDatagram{}
		}
	}
}
