package memnet

import (
	"context"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/djylb/timeshim"
)

func pair(t *testing.T, n *Net, from netip.Addr) (net.Conn, net.Conn, string) {
	t.Helper()
	ctx := context.Background()
	l, err := n.Listen(ctx, "tcp", "10.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	acc := make(chan net.Conn, 1)
	go func() { c, _ := l.Accept(); acc <- c }()
	var c net.Conn
	if from.IsValid() {
		c, err = n.From(from).Dial(ctx, "tcp", l.Addr().String())
	} else {
		c, err = n.Dial(ctx, "tcp", l.Addr().String())
	}
	if err != nil {
		t.Fatal(err)
	}
	s := <-acc
	t.Cleanup(func() { _, _ = c.Close(), s.Close() })
	return c, s, l.Addr().String()
}

func waitTimer(t *testing.T, c *timeshim.Fake) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.WaitPending(ctx, 1); err != nil {
		t.Fatal(err)
	}
}

// A delay holds a write until the clock passes it, in its direction only.
func TestLinkDelay(t *testing.T) {
	clk := timeshim.NewFake(time.Unix(0, 0))
	n := New()
	n.Clock = clk
	c, s, addr := pair(t, n, netip.Addr{})
	n.SetLink(addr, LinkPair{To: Link{Delay: time.Second}})
	got := make(chan []byte, 1)
	go func() { b := make([]byte, 2); _, _ = io.ReadFull(s, b); got <- b }()
	wrote := make(chan error, 1)
	go func() { _, err := c.Write([]byte("hi")); wrote <- err }()
	waitTimer(t, clk)
	select {
	case <-got:
		t.Fatal("delivered before the delay")
	default:
	}
	clk.Advance(time.Second)
	if err := <-wrote; err != nil {
		t.Fatal(err)
	}
	if b := <-got; string(b) != "hi" {
		t.Errorf("%q", b)
	}
	go func() { _, _ = s.Write([]byte("ok")) }()
	b := make([]byte, 2)
	if _, err := io.ReadFull(c, b); err != nil || string(b) != "ok" {
		t.Errorf("%q %v", b, err)
	}
}

// A rate holds a write for its transmission time.
func TestLinkRate(t *testing.T) {
	clk := timeshim.NewFake(time.Unix(0, 0))
	n := New()
	n.Clock = clk
	c, s, addr := pair(t, n, netip.Addr{})
	n.SetLink(addr, LinkPair{To: Link{Rate: 1000}})
	go func() { _, _ = io.Copy(io.Discard, s) }()
	wrote := make(chan error, 1)
	go func() { _, err := c.Write(make([]byte, 2000)); wrote <- err }()
	waitTimer(t, clk)
	clk.Advance(1999 * time.Millisecond)
	select {
	case err := <-wrote:
		t.Fatalf("written before its transmission time (%v)", err)
	default:
	}
	clk.Advance(time.Millisecond)
	if err := <-wrote; err != nil {
		t.Fatal(err)
	}
}

// Turning a link off closes its connections and refuses dials; clearing it
// restores them.
func TestLinkOff(t *testing.T) {
	n := New()
	c, _, addr := pair(t, n, netip.Addr{})
	n.SetLink(addr, LinkPair{To: Link{Off: true}})
	if _, err := c.Write([]byte("x")); !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("write on a cut link: %v", err)
	}
	if _, err := n.Dial(context.Background(), "tcp", addr); !errors.Is(err, syscall.ECONNREFUSED) {
		t.Errorf("dial over a cut link: %v", err)
	}
	n.SetLink(addr, LinkPair{})
	if n.LinkOf(addr) != (LinkPair{}) {
		t.Error("link not cleared")
	}
}

// A loss of 1 drops every datagram; 0 delivers them.
func TestLinkLoss(t *testing.T) {
	n := New()
	n.Rand = rand.New(rand.NewPCG(1, 2))
	ctx := context.Background()
	a, _ := n.ListenPacket(ctx, "udp", "10.0.0.1:0")
	b, _ := n.ListenPacket(ctx, "udp", "10.0.0.2:0")
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	n.SetLink(b.LocalAddr().String(), LinkPair{To: Link{Loss: 1}})
	_, _ = a.WriteTo([]byte("lost"), b.LocalAddr())
	n.SetLink(b.LocalAddr().String(), LinkPair{})
	_, _ = a.WriteTo([]byte("kept"), b.LocalAddr())
	buf := make([]byte, 16)
	_ = b.SetReadDeadline(time.Now().Add(5 * time.Second))
	k, from, err := b.ReadFrom(buf)
	if err != nil || string(buf[:k]) != "kept" || from.String() != a.LocalAddr().String() {
		t.Errorf("%q %v %v", buf[:k], from, err)
	}
}

// Both ends write before either reads: the bytes are buffered.
func TestPipeBuffersCrossWrites(t *testing.T) {
	a, b := Pipe()
	if _, err := a.Write([]byte("a")); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Write([]byte("b")); err != nil {
		t.Fatal(err)
	}
	_, _ = a.Close(), b.Close()
}

// CloseWrite ends one direction: the peer reads EOF and can still write.
func TestHalfClose(t *testing.T) {
	a, b := Pipe()
	defer a.Close()
	defer b.Close()
	if err := a.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("read after CloseWrite: %v", err)
	}
	if _, err := b.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	if _, err := io.ReadFull(a, buf); err != nil || buf[0] != 'x' {
		t.Fatalf("%q %v", buf, err)
	}
}

// After SetLinger(0), Close resets: the peer fails with ECONNRESET.
func TestLingerZeroResets(t *testing.T) {
	a, b := Pipe()
	defer b.Close()
	_ = a.(interface{ SetLinger(int) error }).SetLinger(0)
	_ = a.Close()
	if _, err := b.Read(make([]byte, 1)); !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("read after a reset: %v", err)
	}
}

// SetLinger and Close may run at once, as on a *net.TCPConn.
func TestSetLingerBesideClose(t *testing.T) {
	a, b := Pipe()
	defer b.Close()
	var wg sync.WaitGroup
	wg.Go(func() { _ = a.(interface{ SetLinger(int) error }).SetLinger(0) })
	wg.Go(func() { _ = a.Close() })
	wg.Wait()
}

// A deadline set while a read blocks ends it.
func TestDeadlines(t *testing.T) {
	a, b := Pipe()
	defer a.Close()
	defer b.Close()
	done := make(chan error, 1)
	go func() { _, err := a.Read(make([]byte, 1)); done <- err }()
	_ = a.SetReadDeadline(time.Now())
	if err := <-done; !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read: %v", err)
	}
	p, err := New().ListenPacket(context.Background(), "udp", "10.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	go func() { _, _, err := p.ReadFrom(make([]byte, 1)); done <- err }()
	_ = p.SetReadDeadline(time.Now())
	if err := <-done; !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("packet read: %v", err)
	}
}

// DialFrom gives both ends the source host; Dial leaves them "pipe".
func TestDialFrom(t *testing.T) {
	n := New()
	src := netip.MustParseAddr("192.0.2.7")
	c, s, addr := pair(t, n, src)
	ap, err := netip.ParseAddrPort(c.LocalAddr().String())
	if err != nil || ap.Addr() != src || s.RemoteAddr().String() != c.LocalAddr().String() || c.RemoteAddr().String() != addr {
		t.Errorf("addresses %v %v %v", c.LocalAddr(), s.RemoteAddr(), c.RemoteAddr())
	}
	c2, _, _ := pair(t, n, netip.Addr{})
	if c2.LocalAddr().String() != "pipe" {
		t.Errorf("Dial local %v", c2.LocalAddr())
	}
}

// Resolve answers from SetHost, then from IP literals.
func TestResolve(t *testing.T) {
	n := New()
	a := netip.MustParseAddr("10.1.2.3")
	n.SetHost("svc.test", a)
	if got, err := n.Resolve(context.Background(), "svc.test"); err != nil || len(got) != 1 || got[0] != a {
		t.Errorf("%v %v", got, err)
	}
	if got, err := n.Resolve(context.Background(), "::1"); err != nil || got[0] != netip.IPv6Loopback() {
		t.Errorf("%v %v", got, err)
	}
	n.SetHost("svc.test")
	var de *net.DNSError
	if _, err := n.Resolve(context.Background(), "svc.test"); !errors.As(err, &de) || !de.IsNotFound {
		t.Errorf("removed host: %v", err)
	}
}

// A dial to nothing is refused; a closed listener frees its address.
func TestListenerLifecycle(t *testing.T) {
	n := New()
	ctx := context.Background()
	if _, err := n.Dial(ctx, "tcp", "10.0.0.9:1"); !errors.Is(err, syscall.ECONNREFUSED) {
		t.Errorf("dial to nothing: %v", err)
	}
	l, err := n.Listen(ctx, "tcp", "10.0.0.9:1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.Listen(ctx, "tcp", "10.0.0.9:1"); err == nil {
		t.Error("address listened twice")
	}
	if !n.Listening("10.0.0.9:1") {
		t.Error("not listening")
	}
	_ = l.Close()
	if _, err := l.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("accept after close: %v", err)
	}
	l, err = n.Listen(ctx, "tcp", "10.0.0.9:1")
	if err != nil {
		t.Fatal(err)
	}
	_ = l.Close()
}

func TestLoopbackUDP(t *testing.T) {
	c, err := LoopbackUDP()
	if err != nil {
		t.Skip(err)
	}
	defer c.Close()
	if a := c.LocalAddr().(*net.UDPAddr); !a.IP.Equal(net.IPv4(127, 0, 0, 1)) || a.Port == 0 {
		t.Fatalf("bound %v", a)
	}
}
