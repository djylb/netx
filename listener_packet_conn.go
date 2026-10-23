package netx

import (
	"net"
	"net/netip"
	"os"
	"sync"
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
	l    *PacketListener
	key  peerKey
	peer net.Addr

	q             dgram.Queue
	once          sync.Once
	writeDeadline dgram.Deadline
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

func (c *packetConn) LocalAddr() net.Addr  { return c.l.pc.LocalAddr() }
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
