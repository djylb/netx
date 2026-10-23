package netx

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// The accept filter sees the first datagram and can answer it with WriteTo
// without starting a connection: a stateless retry.
func TestPacketListenerFilterFirstAndWriteTo(t *testing.T) {
	var self atomic.Pointer[PacketListener]
	l := newUDPListener(t, WithPacketAcceptFilter(func(peer net.Addr, first []byte) bool {
		if bytes.HasPrefix(first, []byte("cookie:")) {
			return true
		}
		_, _ = self.Load().WriteTo([]byte("retry"), peer)
		return false
	}))
	self.Store(l)
	c := dialUDP(t, l)
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = c.Write([]byte("hello"))
	buf := make([]byte, 64)
	if n, err := c.Read(buf); err != nil || string(buf[:n]) != "retry" {
		t.Fatalf("reply %q, %v; want retry", buf[:n], err)
	}
	if peerConn(l, c) != nil {
		t.Fatal("a rejected datagram started a connection")
	}
	_, _ = c.Write([]byte("cookie:1"))
	pc, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	_ = pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := pc.Read(buf); err != nil || string(buf[:n]) != "cookie:1" {
		t.Fatalf("accepted %q, %v", buf[:n], err)
	}
	_ = l.Close()
	if _, err := l.WriteTo([]byte("x"), c.LocalAddr()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("WriteTo() after Close = %v", err)
	}
}

// Dial reaches a known peer from the listener's socket, gets its datagrams
// without Accept, and refuses a peer that is connected.
func TestPacketListenerDial(t *testing.T) {
	l := newUDPListener(t, WithPacketIdleTimeout(200*time.Millisecond))
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	_ = peer.SetDeadline(time.Now().Add(5 * time.Second))

	c, err := l.Dial(peer.LocalAddr())
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	if _, err := l.Dial(peer.LocalAddr()); !errors.Is(err, ErrPacketPeerConnected) {
		t.Fatalf("second Dial() error = %v, want ErrPacketPeerConnected", err)
	}
	// An IPv4-mapped form of the same peer is the same peer.
	ap := peer.LocalAddr().(*net.UDPAddr).AddrPort()
	mapped := net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.AddrFrom16(ap.Addr().As16()), ap.Port()))
	if _, err := l.Dial(mapped); !errors.Is(err, ErrPacketPeerConnected) {
		t.Fatalf("Dial(mapped) error = %v, want ErrPacketPeerConnected", err)
	}
	if _, err := c.Write([]byte("punch")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, from, err := peer.ReadFromUDP(buf)
	if err != nil || string(buf[:n]) != "punch" || from.Port != l.Addr().(*net.UDPAddr).Port {
		t.Fatalf("peer read %q from %v, %v", buf[:n], from, err)
	}
	_, _ = peer.WriteToUDP([]byte("back"), from)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := c.Read(buf); err != nil || string(buf[:n]) != "back" {
		t.Fatalf("Read() = %q, %v", buf[:n], err)
	}
	// Not queued for Accept.
	if n := l.conns.Pending(); n != 0 {
		t.Fatalf("Dial()ed connection queued for Accept: %d pending", n)
	}
	// The idle timeout applies from Dial on, and the peer can then connect
	// again.
	waitUntil(t, func() bool { return c.(*packetConn).q.Closed() })
	if c2, err := l.Dial(peer.LocalAddr()); err != nil {
		t.Fatalf("Dial() after idle close = %v", err)
	} else {
		_ = c2.Close()
	}
	_ = l.Close()
	if _, err := l.Dial(peer.LocalAddr()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Dial() after Close = %v", err)
	}
}

// A connection that Dial made is closed with the listener.
func TestPacketListenerDialClosedWithListener(t *testing.T) {
	l := newUDPListener(t)
	c, err := l.Dial(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
	if err != nil {
		t.Fatal(err)
	}
	_ = l.Close()
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Read() after listener Close = %v", err)
	}
}

// On a dual-stack socket, which reports IPv4 peers as IPv4-mapped IPv6
// addresses, an IPv4 peer that Dial reached is found by its datagrams, and
// accepted IPv4 peers report IPv4 addresses.
func TestPacketListenerDualStackPeers(t *testing.T) {
	if runtime.GOOS == "js" || runtime.GOOS == "wasip1" {
		t.Skip("the simulated network has no dual-stack sockets")
	}
	pc, err := net.ListenPacket("udp", "[::]:0")
	if err != nil {
		t.Skip(err)
	}
	l := NewPacketListener(pc)
	t.Cleanup(func() { _ = l.Close() })
	port := l.Addr().(*net.UDPAddr).Port
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	c, err := l.Dial(peer.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := peer.WriteToUDP([]byte("in"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}); err != nil {
		t.Skip(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 8)
	if n, err := c.Read(buf); err != nil || string(buf[:n]) != "in" {
		t.Fatalf("Read() = %q, %v; want the peer's datagram on its Dial()ed connection", buf[:n], err)
	}
	other := dialUDPTo(t, port)
	_, _ = other.Write([]byte("x"))
	a, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if ua := a.RemoteAddr().(*net.UDPAddr); ua.IP.To4() == nil || len(ua.IP) != net.IPv4len {
		t.Fatalf("accepted peer %v, want an IPv4 address", ua)
	}
}

func dialUDPTo(t *testing.T, port int) *net.UDPConn {
	t.Helper()
	c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// A peer that Dial connects while the read loop handles its first datagram,
// here from the accept filter itself, keeps one connection, which gets the
// datagram, and nothing is queued for Accept.
func TestPacketListenerDialDuringFirstDatagram(t *testing.T) {
	var (
		self   atomic.Pointer[PacketListener]
		dialed = make(chan net.Conn, 1)
	)
	l := newUDPListener(t, WithPacketAcceptFilter(func(peer net.Addr, _ []byte) bool {
		c, err := self.Load().Dial(peer)
		if err != nil {
			t.Errorf("Dial() from the filter = %v", err)
			return false
		}
		dialed <- c
		return true
	}))
	self.Store(l)
	peer := dialUDP(t, l)
	_, _ = peer.Write([]byte("first"))
	c := <-dialed
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 16)
	if n, err := c.Read(buf); err != nil || string(buf[:n]) != "first" {
		t.Fatalf("Dial()ed connection read %q, %v; want the first datagram", buf[:n], err)
	}
	if n := l.conns.Pending(); n != 0 {
		t.Fatalf("a second connection was queued: %d pending", n)
	}
}
