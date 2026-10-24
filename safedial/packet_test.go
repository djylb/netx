package safedial

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/djylb/netx"
	"github.com/djylb/netx/internal/dgram"
)

type sentDatagram struct {
	dst  netx.Addr
	data string
}

// fakeAddrConn records the datagrams sent through it.
type fakeAddrConn struct {
	sentCh chan sentDatagram
	closed chan struct{}
	once   sync.Once
}

func newFakeAddrConn() *fakeAddrConn {
	return &fakeAddrConn{sentCh: make(chan sentDatagram, 256), closed: make(chan struct{})}
}

func (c *fakeAddrConn) WriteTo(p []byte, dst netx.Addr) (int, error) {
	c.sentCh <- sentDatagram{dst, string(p)}
	return len(p), nil
}

func (c *fakeAddrConn) ReadFrom([]byte) (int, netx.Addr, error) {
	<-c.closed
	return 0, netx.Addr{}, net.ErrClosed
}

func (c *fakeAddrConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

// next returns the next datagram sent, failing after a while.
func (c *fakeAddrConn) next(t *testing.T) sentDatagram {
	t.Helper()
	select {
	case d := <-c.sentCh:
		return d
	case <-time.After(5 * time.Second):
		t.Fatal("no datagram sent")
	}
	return sentDatagram{}
}

func (c *fakeAddrConn) none(t *testing.T) {
	t.Helper()
	select {
	case d := <-c.sentCh:
		t.Fatalf("sent %v", d)
	default:
	}
}

func TestAddrPacketConnIP(t *testing.T) {
	inner := newFakeAddrConn()
	r := newFakeResolver(nil)
	w := (&Dialer{Resolver: r}).WrapAddrPacketConn(inner)
	defer func() { _ = w.Close() }()
	public := netx.Addr{IP: netip.MustParseAddr("93.184.216.34"), Port: 53}
	if n, err := w.WriteTo([]byte("q"), public); n != 1 || err != nil {
		t.Fatalf("WriteTo public = %d, %v", n, err)
	}
	if d := inner.next(t); d.dst != public || d.data != "q" {
		t.Errorf("sent %v", d)
	}
	for _, dst := range []netx.Addr{
		{IP: netip.MustParseAddr("10.0.0.1"), Port: 53},
		{IP: netip.MustParseAddr("255.255.255.255"), Port: 53},
		{IP: netip.MustParseAddr("ff02::fb"), Port: 5353},
		{},
		{Name: "127.1", Port: 53},
		{Name: "0x7f000001", Port: 53},
		{Name: "localhost.", Port: 53}, // resolved, then refused
	} {
		if dst.Name == "localhost." {
			r.add(dst.Name, "127.0.0.1", "::1")
			// Held for the lookup, then dropped; the next is refused.
			if _, err := w.WriteTo([]byte("x"), dst); err != nil {
				t.Fatal(err)
			}
			waitLookups(t, w)
		}
		_, err := w.WriteTo([]byte("x"), dst)
		assertDenied(t, err, ErrScope, "")
	}
	if _, err := w.WriteTo([]byte("x"), netx.Addr{Name: "bad name", Port: 1}); !errors.Is(err, netx.ErrInvalidAddr) {
		t.Errorf("bad name: %v", err)
	}
	inner.none(t)
	if r.count("127.1") != 0 || r.count("0x7f000001") != 0 {
		t.Error("resolved a legacy IPv4 form")
	}
}

// waitLookups waits until w runs no lookups.
func waitLookups(t testing.TB, w AddrPacketConn) {
	t.Helper()
	g := w.(*addrPacketConn).g
	deadline := time.Now().Add(5 * time.Second)
	for g.names.Running() > 0 {
		if time.Now().After(deadline) {
			t.Fatal("lookups did not end")
		}
		time.Sleep(time.Millisecond)
	}
}

// Datagrams to a name are held during its lookup and sent, in order, to
// the first allowed address, IPv4 first; the name is resolved once.
func TestAddrPacketConnName(t *testing.T) {
	inner := newFakeAddrConn()
	r := newFakeResolver(map[string][]string{
		"dns.example":     {"127.0.0.1", "2606:2800:220:1::1", "93.184.216.34"},
		"private.example": {"10.0.0.1"},
	})
	r.block = make(chan struct{})
	w := (&Dialer{Resolver: r, Policy: All(DenyPorts(25), DefaultPolicy())}).WrapAddrPacketConn(inner)
	defer func() { _ = w.Close() }()
	dst := netx.Addr{Name: "dns.example", Port: 53}
	for i := range 3 {
		if n, err := w.WriteTo([]byte{byte('a' + i)}, dst); n != 1 || err != nil {
			t.Fatalf("WriteTo held = %d, %v", n, err)
		}
	}
	inner.none(t)
	close(r.block)
	want := netx.Addr{IP: netip.MustParseAddr("93.184.216.34"), Port: 53}
	for i := range 3 {
		if d := inner.next(t); d.dst != want || d.data != string('a'+rune(i)) {
			t.Errorf("sent %v; want %v %c", d, want, 'a'+i)
		}
	}
	waitLookups(t, w)
	if n, err := w.WriteTo([]byte("d"), dst); n != 1 || err != nil {
		t.Fatalf("WriteTo cached = %d, %v", n, err)
	}
	if d := inner.next(t); d.dst != want {
		t.Errorf("sent %v", d)
	}
	if n := r.count("dns.example"); n != 1 {
		t.Errorf("%d lookups", n)
	}
	// The port is checked for each datagram, before the name resolves.
	_, err := w.WriteTo([]byte("x"), netx.Addr{Name: "dns.example", Port: 25})
	assertDenied(t, err, ErrPort, "dns.example:25")
	// A name whose addresses are all refused drops the held datagram and
	// refuses the next.
	if _, err := w.WriteTo([]byte("x"), netx.Addr{Name: "private.example", Port: 53}); err != nil {
		t.Fatal(err)
	}
	waitLookups(t, w)
	_, err = w.WriteTo([]byte("x"), netx.Addr{Name: "private.example", Port: 53})
	assertDenied(t, err, ErrScope, "private.example:53 (10.0.0.1)")
	// A failed lookup is cached too.
	if _, err := w.WriteTo([]byte("x"), netx.Addr{Name: "missing.example", Port: 53}); err != nil {
		t.Fatal(err)
	}
	waitLookups(t, w)
	var dnsErr *net.DNSError
	if _, err := w.WriteTo([]byte("x"), netx.Addr{Name: "missing.example", Port: 53}); !errors.As(err, &dnsErr) {
		t.Errorf("missing: %v", err)
	}
	inner.none(t)
}

// Datagrams beyond the bounds of the lookups, which internal/dgram tests,
// fail with ErrLookupBusy, and Close ends the lookups.
func TestAddrPacketConnBounds(t *testing.T) {
	before, _ := goroutines()
	inner := newFakeAddrConn()
	r := newFakeResolver(nil)
	r.block = make(chan struct{}) // never answers
	w := (&Dialer{Resolver: r}).WrapAddrPacketConn(inner)
	dst := netx.Addr{Name: "slow.example", Port: 53}
	for range dgram.MaxLookupQueue {
		if _, err := w.WriteTo([]byte("x"), dst); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := w.WriteTo([]byte("x"), dst); !errors.Is(err, ErrLookupBusy) {
		t.Errorf("held beyond the bound: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := w.WriteTo([]byte("x"), netx.Addr{Name: "after.example", Port: 53}); !errors.Is(err, net.ErrClosed) {
		t.Errorf("after Close: %v", err)
	}
	waitGoroutines(t, before)
	inner.none(t)
}

// A held datagram is checked with its name, which a name policy may let
// reach an address that others may not.
func TestAddrPacketConnHeldName(t *testing.T) {
	inner := newFakeAddrConn()
	r := newFakeResolver(map[string][]string{"intranet.example": {"10.0.0.7"}, "evil.example": {"10.0.0.7"}})
	r.block = make(chan struct{})
	w := (&Dialer{Resolver: r, Policy: Any(AllowNames("intranet.example"), DefaultPolicy())}).WrapAddrPacketConn(inner)
	defer func() { _ = w.Close() }()
	for _, name := range []string{"evil.example", "intranet.example"} {
		if _, err := w.WriteTo([]byte(name), netx.Addr{Name: name, Port: 53}); err != nil {
			t.Fatal(err)
		}
	}
	close(r.block)
	if d := inner.next(t); d.data != "intranet.example" || d.dst.IP != netip.MustParseAddr("10.0.0.7") {
		t.Errorf("sent %v", d)
	}
	waitLookups(t, w)
	inner.none(t)
}

// discardAddrConn and discardPacketConn take datagrams without
// allocating.
type discardAddrConn struct{}

func (discardAddrConn) WriteTo(p []byte, _ netx.Addr) (int, error) { return len(p), nil }
func (discardAddrConn) ReadFrom([]byte) (int, netx.Addr, error)    { return 0, netx.Addr{}, net.ErrClosed }
func (discardAddrConn) Close() error                               { return nil }

type discardPacketConn struct{ net.PacketConn }

func (discardPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }
func (discardPacketConn) WriteToUDPAddrPort(p []byte, _ netip.AddrPort) (int, error) {
	return len(p), nil
}

func TestPacketAllocs(t *testing.T) {
	d := &Dialer{Policy: All(DenyPorts(25), DefaultPolicy())}
	w := d.WrapAddrPacketConn(discardAddrConn{})
	pc := d.WrapPacketConn(discardPacketConn{})
	dst := netx.Addr{IP: netip.MustParseAddr("93.184.216.34"), Port: 53}
	ap := netip.MustParseAddrPort("[2606:2800:220:1::1]:443")
	udp := net.UDPAddrFromAddrPort(ap)
	p := []byte("datagram")
	if n := testing.AllocsPerRun(100, func() {
		if _, err := w.WriteTo(p, dst); err != nil {
			t.Fatal(err)
		}
		if _, err := pc.WriteToUDPAddrPort(p, ap); err != nil {
			t.Fatal(err)
		}
		if _, err := pc.WriteTo(p, udp); err != nil {
			t.Fatal(err)
		}
	}); n != 0 {
		t.Errorf("%v allocations per datagram", n)
	}
}

func listenUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Skipf("listen: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func readUDP(t *testing.T, c *net.UDPConn) (string, netip.AddrPort) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	n, from, err := c.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatal(err)
	}
	return string(buf[:n]), from
}

// A wrapped UDP socket sends to allowed destinations only, also to names,
// and delivers replies from any source.
func TestPacketConnUDP(t *testing.T) {
	relay, peer, stranger := listenUDP(t), listenUDP(t), listenUDP(t)
	peerAP := netip.MustParseAddrPort(peer.LocalAddr().String())
	relayAP := netip.MustParseAddrPort(relay.LocalAddr().String())
	r := newFakeResolver(map[string][]string{"peer.example": {"127.0.0.1"}})
	pc := (&Dialer{Resolver: r, Policy: loopback}).WrapPacketConn(relay)
	defer func() { _ = pc.Close() }()

	if _, err := pc.WriteTo([]byte("one"), net.UDPAddrFromAddrPort(peerAP)); err != nil {
		t.Fatal(err)
	}
	if got, from := readUDP(t, peer); got != "one" || from != relayAP {
		t.Errorf("peer got %q from %v", got, from)
	}
	if _, err := pc.WriteToUDPAddrPort([]byte("two"), peerAP); err != nil {
		t.Fatal(err)
	}
	if got, _ := readUDP(t, peer); got != "two" {
		t.Errorf("peer got %q", got)
	}
	if _, err := pc.WriteTo([]byte("three"), netx.Addr{Name: "peer.example", Port: peerAP.Port()}); err != nil {
		t.Fatal(err)
	}
	if got, _ := readUDP(t, peer); got != "three" {
		t.Errorf("peer got %q", got)
	}
	_, err := pc.WriteToUDPAddrPort([]byte("x"), netip.MustParseAddrPort("10.0.0.1:53"))
	assertDenied(t, err, ErrPrefix, "10.0.0.1:53")
	_, err = pc.WriteTo([]byte("x"), &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53})
	assertDenied(t, err, ErrPrefix, "8.8.8.8:53")
	if _, err := pc.WriteTo([]byte("x"), nil); !errors.Is(err, netx.ErrInvalidAddr) {
		t.Errorf("nil address: %v", err)
	}

	// A source never sent to is delivered.
	if _, err := stranger.WriteToUDPAddrPort([]byte("hello"), relayAP); err != nil {
		t.Fatal(err)
	}
	_ = pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	n, from, err := pc.ReadFromUDPAddrPort(buf)
	if err != nil || string(buf[:n]) != "hello" || from.Port() != netip.MustParseAddrPort(stranger.LocalAddr().String()).Port() {
		t.Errorf("read %q from %v, %v", buf[:n], from, err)
	}
	if n := r.count("peer.example"); n != 1 {
		t.Errorf("%d lookups", n)
	}
	if pc.LocalAddr().Network() != "udp" {
		t.Errorf("LocalAddr %v", pc.LocalAddr())
	}
}
