package udpflow

import (
	"hash/maphash"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/netx/internal/dgram"
	"github.com/djylb/netx/internal/flowtable"
	"github.com/djylb/netx/internal/netutil"
)

// peerKey names a peer of a PacketListener: a *net.UDPAddr peer by its
// address and port, and others by their address's String.
type peerKey struct {
	ap netip.AddrPort
	s  string
}

func hashPeer(seed maphash.Seed, peer peerKey) uint64 {
	if !peer.ap.IsValid() {
		return maphash.String(seed, peer.s)
	}
	var h maphash.Hash
	h.SetSeed(seed)
	flowtable.WriteAddrPort(&h, peer.ap)
	return h.Sum64()
}

// packetFlow identifies a connection by peer and, when packet information
// is available, local unicast destination and its link-local scope.
type packetFlow struct {
	peer  peerKey
	local packetDestination
}

type packetDestination struct {
	ap      netip.AddrPort
	ifindex uint32
}

// packetConn is one flow of a PacketListener.
type packetConn struct {
	datagramSource
	peer    net.Addr
	peerKey peerKey
	l       *PacketListener
	sock    *packetSocket // the packet connection it writes from
	// from records the explicit reply source, if fixed.
	from          atomic.Pointer[replySource]
	membership    flowtable.Membership[packetFlow, peerKey]
	writer        dgram.Writer
	q             dgram.Queue
	once          sync.Once
	routedReplies atomic.Bool
}

// The embedded Source lets netx.Relay and netx.Copy take datagrams whole.
type datagramSource = dgram.Source

// replySource is a local address that a connection replies from and the
// control message that sends from it.
type replySource struct {
	addr netip.AddrPort
	oob  []byte
}

func (c *packetConn) setReplySource(dst packetDestination) {
	ip := dst.ap.Addr()
	c.from.Store(&replySource{
		addr: netip.AddrPortFrom(ip.WithZone(netutil.ScopeZone(ip, dst.ifindex)), dst.ap.Port()),
		oob:  sourceOOB(ip, dst.ifindex),
	})
}

func (c *packetConn) queue() *dgram.Queue { return &c.q }

// Read returns the next datagram from the peer, truncated to len(b).
func (c *packetConn) Read(b []byte) (int, error) {
	if c == nil {
		return 0, net.ErrClosed
	}
	return c.q.Read(b)
}

// Write sends b to the peer as one datagram.
func (c *packetConn) Write(b []byte) (int, error) {
	if c == nil {
		return 0, net.ErrClosed
	}
	n, err := c.sock.gate.Write(&c.writer, c.q.Done(), func() (int, error) { return c.writeDatagram(b) })
	if err == nil {
		c.q.Touch()
	}
	return n, err
}

func (c *packetConn) writeDatagram(p []byte) (int, error) {
	peer := c.peerKey.ap
	if udp := c.sock.udp; udp != nil && peer.IsValid() {
		return c.writeUDP(udp, p, peer)
	}
	return c.sock.pc.WriteTo(p, c.peer)
}

type packetUDPWriter interface {
	WriteMsgUDPAddrPort(b, oob []byte, addr netip.AddrPort) (int, int, error)
	WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error)
}

func (c *packetConn) writeUDP(udp packetUDPWriter, p []byte, peer netip.AddrPort) (int, error) {
	if f := c.from.Load(); f != nil && !c.routedReplies.Load() {
		// A datagram goes out whole: report len(p) on success. On
		// Windows a WSASendMsg that completes at once reports 0 bytes
		// (the runtime passes no byte count), which callers would take
		// for a short write.
		n, _, err := udp.WriteMsgUDPAddrPort(p, f.oob, peer)
		if err == nil {
			return len(p), nil
		}
		if n != 0 {
			return 0, err
		}
		unavailable := netutil.IsAddrNotAvailable(err)
		if !unavailable && !isPacketSourceInvalidArgument(err) {
			return 0, err
		}
		if confirmedPacketGroup(f.addr.Addr()) {
			c.routedReplies.CompareAndSwap(false, true)
		} else if !unavailable {
			// EINVAL alone does not identify a source address error.
			return 0, err
		}
	}
	return udp.WriteToUDPAddrPort(p, peer)
}

// Close removes the connection from its listener.
func (c *packetConn) Close() error {
	if c == nil {
		return net.ErrClosed
	}
	c.shutdown(net.ErrClosed)
	return nil
}

func (c *packetConn) shutdown(err error) {
	c.once.Do(func() {
		c.l.conns.Remove(c)
		c.q.Close(err)
	})
	c.writer.Close()
}

// LocalAddr returns the flow's fixed local destination, or the packet
// connection's address when the flow uses OS-selected sources by default.
func (c *packetConn) LocalAddr() net.Addr {
	if c == nil {
		return nil
	}
	if f := c.from.Load(); f != nil && !c.routedReplies.Load() {
		return net.UDPAddrFromAddrPort(f.addr)
	}
	return c.sock.pc.LocalAddr()
}
func (c *packetConn) RemoteAddr() net.Addr {
	if c == nil {
		return nil
	}
	return c.peer
}

func (c *packetConn) SetDeadline(t time.Time) error {
	if c == nil || c.q.Closed() {
		return net.ErrClosed
	}
	c.q.SetReadDeadline(t)
	return c.writer.SetDeadline(t)
}

func (c *packetConn) SetReadDeadline(t time.Time) error {
	if c == nil || c.q.Closed() {
		return net.ErrClosed
	}
	c.q.SetReadDeadline(t)
	return nil
}

// SetWriteDeadline bounds waiting, active and future writes of this flow.
func (c *packetConn) SetWriteDeadline(t time.Time) error {
	if c == nil || c.q.Closed() {
		return net.ErrClosed
	}
	return c.writer.SetDeadline(t)
}
