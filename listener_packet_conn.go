package netx

import (
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/netx/internal/dgram"
)

// peerKey names a peer of a PacketListener: a *net.UDPAddr peer by its
// address and port, and others by their address's String.
type peerKey struct {
	ap netip.AddrPort
	s  string
}

// packetConn is one peer of a PacketListener.
type packetConn struct {
	peer net.Addr
	l    *PacketListener
	sock *packetSocket // the packet connection it writes from; nil for l's own
	// from is the address the peer's last datagram was sent to, on a
	// socket bound to a wildcard address; writes go from it. nil: the
	// address routing picks (a socket bound to one address, or no
	// datagram yet).
	from          atomic.Pointer[replySource]
	key           peerKey
	writeDeadline dgram.Deadline
	q             dgram.Queue
	once          sync.Once
}

// replySource is a local address that a connection replies from and the
// control message that sends from it.
type replySource struct {
	addr    netip.Addr
	oob     []byte
	ifindex uint32
}

// replyFrom records the destination of a datagram from the peer, given
// its control data; it allocates only when the destination changes.
func (c *packetConn) replyFrom(oob []byte) {
	dst, ifindex := packetDst(oob)
	if !dst.IsValid() {
		return
	}
	if f := c.from.Load(); f != nil && f.addr == dst && f.ifindex == ifindex {
		return
	}
	c.from.Store(&replySource{addr: dst, ifindex: ifindex, oob: sourceOOB(dst, ifindex)})
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
	n, err := c.l.writeTo(b, c)
	if err == nil {
		c.q.Touch()
	}
	return n, err
}

// Close removes the connection from its listener.
func (c *packetConn) Close() error {
	c.shutdown(net.ErrClosed)
	return nil
}

func (c *packetConn) shutdown(err error) {
	c.once.Do(func() {
		c.l.conns.Remove(c.key, c)
		c.q.Close(err)
		c.writeDeadline.Stop()
	})
}

// LocalAddr returns the address the peer's datagrams are sent to, when
// the packet connection is bound to a wildcard address and reports it, and
// the packet connection's address otherwise.
func (c *packetConn) LocalAddr() net.Addr {
	la := c.l.pc.LocalAddr()
	if f := c.from.Load(); f != nil {
		if ua, ok := la.(*net.UDPAddr); ok {
			return net.UDPAddrFromAddrPort(netip.AddrPortFrom(f.addr, uint16(ua.Port)))
		}
	}
	return la
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
