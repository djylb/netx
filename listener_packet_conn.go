package netx

import (
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/netx/internal/dgram"
	"github.com/djylb/netx/internal/netutil"
)

// peerKey names a peer of a PacketListener: a *net.UDPAddr peer by its
// address and port, and others by their address's String.
type peerKey struct {
	ap netip.AddrPort
	s  string
}

// packetFlow identifies a connection by peer and, when packet information
// is available, local unicast destination and its link-local scope.
type packetFlow struct {
	peer         peerKey
	local        packetDestination
	wildcardDial bool // Dial has no local destination until the peer sends one
}

type packetDestination struct {
	ap      netip.AddrPort
	ifindex uint32
}

// packetConn is one flow of a PacketListener.
type packetConn struct {
	peer net.Addr
	l    *PacketListener
	sock *packetSocket // the packet connection it writes from
	// from records the local destination and the explicit reply source.
	// Route fallback preserves it for alias cleanup.
	from          atomic.Pointer[replySource]
	routedReplies atomic.Bool
	key           packetFlow
	counted       bool // registered in the peer index, under l.flowMu
	writeDeadline dgram.Deadline
	q             dgram.Queue
	once          sync.Once
}

// replySource is a local address that a connection replies from and the
// control message that sends from it.
type replySource struct {
	destination packetDestination
	addr        netip.AddrPort
	oob         []byte
}

func (c *packetConn) setReplySource(dst packetDestination, ifindex uint32) {
	ip := dst.ap.Addr()
	c.from.Store(&replySource{
		destination: dst,
		addr:        netip.AddrPortFrom(ip.WithZone(netutil.ScopeZone(ip, ifindex)), dst.ap.Port()),
		oob:         sourceOOB(ip, ifindex),
	})
}

func (c *packetConn) queue() *dgram.Queue { return &c.q }

// Read returns the next datagram from the peer, truncated to len(b).
func (c *packetConn) Read(b []byte) (int, error) { return c.q.Read(b) }

// nextDatagram returns the next datagram from the peer in its queued
// buffer, as Read would, for Relay; see datagramSource.
func (c *packetConn) nextDatagram() (*[]byte, error) { return c.q.Next() }

// Write sends b to the peer as one datagram.
func (c *packetConn) Write(b []byte) (int, error) {
	select {
	case <-c.q.Done():
		return 0, net.ErrClosed
	case <-c.writeDeadline.Wait():
		return 0, os.ErrDeadlineExceeded
	default:
	}
	n, err := c.writeDatagram(b)
	if err == nil {
		c.q.Touch()
	}
	return n, err
}

func (c *packetConn) writeDatagram(p []byte) (int, error) {
	peer := c.key.peer.ap
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
		unavailable := IsAddrNotAvailable(err)
		if !unavailable && !isPacketSourceInvalidArgument(err) {
			return 0, err
		}
		if confirmedPacketGroup(f.destination.ap.Addr()) {
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
	c.shutdown(net.ErrClosed)
	return nil
}

func (c *packetConn) shutdown(err error) {
	c.once.Do(func() {
		c.l.removeConn(c)
		c.q.Close(err)
		c.writeDeadline.Stop()
	})
}

// LocalAddr returns the flow's fixed local destination, or the packet
// connection's address when the flow uses OS-selected sources by default.
func (c *packetConn) LocalAddr() net.Addr {
	if f := c.from.Load(); f != nil && !c.routedReplies.Load() {
		return net.UDPAddrFromAddrPort(f.addr)
	}
	return c.sock.pc.LocalAddr()
}
func (c *packetConn) RemoteAddr() net.Addr { return c.peer }

func (c *packetConn) SetDeadline(t time.Time) error {
	if c.q.Closed() {
		return net.ErrClosed
	}
	c.q.SetReadDeadline(t)
	c.writeDeadline.Set(t)
	return nil
}

func (c *packetConn) SetReadDeadline(t time.Time) error {
	if c.q.Closed() {
		return net.ErrClosed
	}
	c.q.SetReadDeadline(t)
	return nil
}

// SetWriteDeadline makes later writes fail once t has passed. A write that is
// already in progress on the shared socket is not interrupted.
func (c *packetConn) SetWriteDeadline(t time.Time) error {
	if c.q.Closed() {
		return net.ErrClosed
	}
	c.writeDeadline.Set(t)
	return nil
}

// netxLayer describes c to Relay, which takes its queued datagrams whole.
func (c *packetConn) netxLayer() layerInfo {
	return layerInfo{self: c, datagrams: c}
}
