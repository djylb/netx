package socks5

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/djylb/netx"
	"github.com/djylb/netx/internal/dgram"
)

// fakeStream is the relay's end of a message-preserving stream: the test
// queues datagrams on in and takes the relay's on out.
type fakeStream struct {
	in     chan []byte
	out    chan []byte
	eof    chan struct{} // closed by the test: Read returns io.EOF
	done   chan struct{} // closed by Close
	once   sync.Once
	closes atomic.Int32
}

func newFakeStream() *fakeStream {
	return &fakeStream{
		in:   make(chan []byte, 64),
		out:  make(chan []byte, 64),
		eof:  make(chan struct{}),
		done: make(chan struct{}),
	}
}

func (s *fakeStream) Read(p []byte) (int, error) {
	select {
	case b := <-s.in:
		return copy(p, b), nil
	case <-s.eof:
		return 0, io.EOF
	case <-s.done:
		return 0, net.ErrClosed
	}
}

func (s *fakeStream) Write(p []byte) (int, error) {
	select {
	case s.out <- bytes.Clone(p):
		return len(p), nil
	case <-s.done:
		return 0, net.ErrClosed
	}
}

func (s *fakeStream) Close() error {
	s.closes.Add(1)
	s.once.Do(func() { close(s.done) })
	return nil
}

// send queues a datagram to dst for the relay.
func (s *fakeStream) send(t *testing.T, dst netx.Addr, payload string) {
	t.Helper()
	b, err := AppendDatagram(nil, dst, []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	s.in <- b
}

// recv returns the source and payload of the next datagram the relay wrote.
func (s *fakeStream) recv(t *testing.T) (netx.Addr, string) {
	t.Helper()
	select {
	case b := <-s.out:
		src, h, err := DecodeDatagram(b)
		if err != nil {
			t.Fatalf("relay wrote a malformed datagram %x: %v", b, err)
		}
		return src, string(b[h:])
	case <-time.After(3 * time.Second):
		t.Fatal("no datagram from the relay")
		return netx.Addr{}, ""
	}
}

// expectNone fails if the relay writes a datagram within d.
func (s *fakeStream) expectNone(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case b := <-s.out:
		t.Fatalf("unexpected datagram %q", b)
	case <-time.After(d):
	}
}

// countingPacketConn counts the Close calls of a PacketConn.
type countingPacketConn struct {
	PacketConn
	closes atomic.Int32
}

func (c *countingPacketConn) Close() error {
	c.closes.Add(1)
	return c.PacketConn.Close()
}

// checkGoroutines fails the test, once its other cleanups have run, if
// goroutines of this module started during it remain. Runtime goroutines,
// such as the event handler of js/wasm, are not counted.
func checkGoroutines(t *testing.T) {
	t.Helper()
	base, _ := moduleGoroutines()
	t.Cleanup(func() {
		deadline := time.Now().Add(3 * time.Second)
		for {
			n, stacks := moduleGoroutines()
			if n <= base {
				return
			}
			if time.Now().After(deadline) {
				t.Errorf("%d goroutines of the module, want at most %d\n%s", n, base, stacks)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
}

// moduleGoroutines returns the number of goroutines, other than the
// caller's, that run code of this module, and their stacks.
func moduleGoroutines() (int, string) {
	buf := make([]byte, 1<<20)
	buf = buf[:runtime.Stack(buf, true)]
	n := 0
	var stacks strings.Builder
	for g := range strings.SplitSeq(string(buf), "\n\n") {
		if strings.Contains(g, "github.com/djylb/netx") && !strings.Contains(g, "checkGoroutines") && !strings.Contains(g, "moduleGoroutines") {
			n++
			stacks.WriteString(g + "\n\n")
		}
	}
	return n, stacks.String()
}

func newLoopbackUDP(t testing.TB) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// newEgress returns a PacketConn of NewPacketConn on a loopback socket, with
// resolver r if not nil, and the socket's address.
func newEgress(t testing.TB, r ipResolver) (*udpPacketConn, netip.AddrPort) {
	t.Helper()
	c := newLoopbackUDP(t)
	u := NewPacketConn(c).(*udpPacketConn)
	if r != nil {
		u.resolver = r
	}
	t.Cleanup(func() { _ = u.Close() })
	ap := c.LocalAddr().(*net.UDPAddr).AddrPort()
	return u, netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// echoUDP answers each datagram on c with "echo:" and the payload, from c,
// until the test ends, and returns c's address and a count of the
// datagrams received.
func echoUDP(t testing.TB, c *net.UDPConn) (netx.Addr, *atomic.Int32) {
	t.Helper()
	var (
		wg sync.WaitGroup
		n  atomic.Int32
	)
	t.Cleanup(func() {
		_ = c.Close()
		wg.Wait()
	})
	wg.Go(func() {
		buf := make([]byte, 65535)
		copy(buf, "echo:")
		for {
			m, peer, err := c.ReadFromUDPAddrPort(buf[5:])
			if err != nil {
				return
			}
			n.Add(1)
			_, _ = c.WriteToUDPAddrPort(buf[:5+m], peer)
		}
	})
	return netx.AddrFromAddrPort(c.LocalAddr().(*net.UDPAddr).AddrPort()), &n
}

// runRelay runs r between s and out until the test ends, and returns the
// channel that receives Relay's result.
func runRelay(t *testing.T, ctx context.Context, r *DatagramRelay, s io.ReadWriteCloser, out PacketConn) <-chan error {
	t.Helper()
	done := make(chan error, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		done <- r.Relay(ctx, s, out)
	}()
	t.Cleanup(func() {
		_ = s.Close()
		<-finished
	})
	return done
}

func waitRelay(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("Relay did not return")
		return nil
	}
}

// errorLog collects the errors of OnError.
type errorLog struct {
	mu   sync.Mutex
	errs []error
}

func (l *errorLog) add(err error) {
	l.mu.Lock()
	l.errs = append(l.errs, err)
	l.mu.Unlock()
}

// wait waits until an error that matches target is logged.
func (l *errorLog) wait(t *testing.T, target error) {
	t.Helper()
	l.waitFunc(t, target.Error(), func(err error) bool { return errors.Is(err, target) })
}

func (l *errorLog) waitFunc(t *testing.T, target string, match func(error) bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		l.mu.Lock()
		found := slices.ContainsFunc(l.errs, match)
		l.mu.Unlock()
		if found {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("OnError did not get %v; got %v", target, l.errs)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Replies from any address and port reach the stream, with their source,
// also from peers never sent to: the relay is a full-cone NAT.
func TestDatagramRelayFullCone(t *testing.T) {
	checkGoroutines(t)
	out, egress := newEgress(t, nil)
	echo, _ := echoUDP(t, newLoopbackUDP(t))
	s := newFakeStream()
	runRelay(t, t.Context(), nil, s, out)

	s.send(t, echo, "ping")
	if src, got := s.recv(t); src != echo || got != "echo:ping" {
		t.Fatalf("reply = %v %q, want %v %q", src, got, echo, "echo:ping")
	}
	// A peer that was never sent to, on another port.
	third := newLoopbackUDP(t)
	defer func() { _ = third.Close() }()
	if _, err := third.WriteToUDPAddrPort([]byte("unsolicited"), egress); err != nil {
		t.Fatal(err)
	}
	want := netx.AddrFromAddrPort(third.LocalAddr().(*net.UDPAddr).AddrPort())
	if src, got := s.recv(t); src != want || got != "unsolicited" {
		t.Fatalf("third-party datagram = %v %q, want %v %q", src, got, want, "unsolicited")
	}
	// The echo's peer port is the egress socket's for every destination.
	s.send(t, want, "back")
	buf := make([]byte, 64)
	_ = third.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, from, err := third.ReadFromUDPAddrPort(buf)
	if err != nil || string(buf[:n]) != "back" || from != egress {
		t.Fatalf("third peer got %q from %v (%v), want %q from %v", buf[:n], from, err, "back", egress)
	}
}

// IPv6 destinations are sent to, and their replies come with IPv6 sources.
func TestDatagramRelayIPv6(t *testing.T) {
	checkGoroutines(t)
	c6, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skip("no IPv6 loopback:", err)
	}
	echo, _ := echoUDP(t, c6)
	c, err := netx.ListenEphemeralUDP(t.Context(), nil)
	if err != nil {
		t.Skip("no dual-stack socket:", err)
	}
	out := NewPacketConn(c)
	s := newFakeStream()
	runRelay(t, t.Context(), nil, s, out)
	s.send(t, echo, "six")
	if src, got := s.recv(t); src != echo || got != "echo:six" {
		t.Fatalf("reply = %v %q, want %v %q", src, got, echo, "echo:six")
	}
	if !echo.IP.Is6() {
		t.Fatalf("echo address %v is not IPv6", echo)
	}
}

// fakeResolver resolves fast.test at once, names that start with "slow"
// once slow is closed, and nothing else.
type fakeResolver struct {
	slow  chan struct{}
	calls atomic.Int32
}

func (r *fakeResolver) LookupNetIP(ctx context.Context, _, host string) ([]netip.Addr, error) {
	r.calls.Add(1)
	switch {
	case host == "fast.test":
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	case strings.HasPrefix(host, "slow"):
		select {
		case <-r.slow:
			return []netip.Addr{netip.MustParseAddr("::1"), netip.MustParseAddr("127.0.0.1")}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

// A name being looked up holds its datagrams without holding up the others,
// sends them in order once it resolves, and replies come from its IP
// address.
func TestDatagramRelaySlowNameDoesNotBlock(t *testing.T) {
	checkGoroutines(t)
	res := &fakeResolver{slow: make(chan struct{})}
	out, _ := newEgress(t, res)
	echo, _ := echoUDP(t, newLoopbackUDP(t))
	s := newFakeStream()
	var log errorLog
	runRelay(t, t.Context(), &DatagramRelay{OnError: log.add}, s, out)

	slow := netx.Addr{Name: "slow.test", Port: echo.Port}
	for _, p := range []string{"s1", "s2", "s3"} {
		s.send(t, slow, p)
	}
	s.send(t, echo, "ip")
	if _, got := s.recv(t); got != "echo:ip" {
		t.Fatalf("first reply = %q, want the IP destination's while the name is looked up", got)
	}
	s.send(t, netx.Addr{Name: "fast.test", Port: echo.Port}, "fast")
	if src, got := s.recv(t); got != "echo:fast" || src != echo {
		t.Fatalf("reply = %v %q, want %v %q", src, got, echo, "echo:fast")
	}
	close(res.slow)
	for _, p := range []string{"s1", "s2", "s3"} {
		src, got := s.recv(t)
		if got != "echo:"+p || src != echo {
			t.Fatalf("held datagram reply = %v %q, want %v %q", src, got, echo, "echo:"+p)
		}
	}
	s.send(t, slow, "s4")
	if _, got := s.recv(t); got != "echo:s4" {
		t.Fatalf("reply = %q, want %q", got, "echo:s4")
	}
	if n := res.calls.Load(); n != 2 {
		t.Fatalf("%d lookups, want 2", n)
	}

	// A name that does not resolve drops its held datagram; the cached
	// failure is reported for the next.
	nx := netx.Addr{Name: "nx.test", Port: echo.Port}
	calls := res.calls.Load()
	s.send(t, nx, "lost")
	for res.calls.Load() == calls {
		time.Sleep(time.Millisecond)
	}
	waitLookups(t, out)
	s.send(t, nx, "lost")
	log.waitFunc(t, "a DNS error", func(err error) bool {
		var dnsErr *net.DNSError
		return errors.As(err, &dnsErr)
	})
	s.expectNone(t, 50*time.Millisecond)
}

func waitLookups(t *testing.T, u *udpPacketConn) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		n := u.names.Running()
		if n == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d lookups still run", n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// NewPacketConn fails datagrams beyond the bounds of its lookups, which
// internal/dgram tests, with ErrLookupBusy, and Close ends the lookups and
// drops their datagrams.
func TestPacketConnLookupBounds(t *testing.T) {
	checkGoroutines(t)
	res := &fakeResolver{slow: make(chan struct{})}
	out, _ := newEgress(t, res)
	slow := netx.Addr{Name: "slow.test", Port: 9}
	for i := range dgram.MaxLookupQueue {
		if n, err := out.WriteTo([]byte("x"), slow); n != 1 || err != nil {
			t.Fatalf("WriteTo %d = %d, %v; want it held", i, n, err)
		}
	}
	if _, err := out.WriteTo([]byte("x"), slow); !errors.Is(err, ErrLookupBusy) {
		t.Fatalf("WriteTo beyond the queue error = %v, want ErrLookupBusy", err)
	}
	_ = out.Close()
	if _, err := out.WriteTo([]byte("x"), netx.Addr{Name: "fast.test", Port: 9}); !netx.IsClosed(err) {
		t.Fatalf("WriteTo after Close error = %v, want net.ErrClosed", err)
	}
	waitLookups(t, out)
	if n := out.names.Held(); n != 0 {
		t.Fatalf("%d bytes held after Close", n)
	}
}

// Fragments, truncated and oversize datagrams are dropped and reported, and
// the relay goes on.
func TestDatagramRelayDropsInvalid(t *testing.T) {
	checkGoroutines(t)
	out, _ := newEgress(t, nil)
	echo, received := echoUDP(t, newLoopbackUDP(t))
	s := newFakeStream()
	var log errorLog
	runRelay(t, t.Context(), &DatagramRelay{OnError: log.add}, s, out)

	frag, _ := AppendDatagram(nil, echo, []byte("fragment"))
	frag[2] = 1
	s.in <- frag
	log.wait(t, ErrFragmented)
	s.in <- []byte{0, 0}
	log.wait(t, ErrMalformed)
	s.in <- []byte{0, 0, 0, 9, 1, 2}
	log.wait(t, ErrAddrType)
	oversize, _ := AppendDatagram(nil, echo, make([]byte, 70000))
	s.in <- oversize
	log.wait(t, ErrDatagramTooLarge)

	s.send(t, echo, "ok")
	if _, got := s.recv(t); got != "echo:ok" {
		t.Fatalf("reply = %q", got)
	}
	if n := received.Load(); n != 1 {
		t.Fatalf("echo received %d datagrams, want 1", n)
	}
}

// Allow drops datagrams, and Sent and Received see the others.
func TestDatagramRelayHooks(t *testing.T) {
	checkGoroutines(t)
	out, _ := newEgress(t, nil)
	echo, received := echoUDP(t, newLoopbackUDP(t))
	denied, deniedCount := echoUDP(t, newLoopbackUDP(t))
	var sent, recv atomic.Int64
	r := &DatagramRelay{
		Allow: func(dst netx.Addr) bool { return dst != denied },
		Sent: func(dst netx.Addr, n int) {
			if dst == echo {
				sent.Add(int64(n))
			}
		},
		Received: func(src netx.Addr, n int) {
			if src == echo {
				recv.Add(int64(n))
			}
		},
	}
	s := newFakeStream()
	runRelay(t, t.Context(), r, s, out)
	s.send(t, denied, "no")
	s.send(t, echo, "hello")
	if _, got := s.recv(t); got != "echo:hello" {
		t.Fatalf("reply = %q", got)
	}
	// The hooks run after the datagrams pass.
	deadline := time.Now().Add(3 * time.Second)
	for sent.Load() != 5 || recv.Load() != 10 {
		if time.Now().After(deadline) {
			t.Fatalf("Sent %d, Received %d bytes; want 5 and 10", sent.Load(), recv.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if deniedCount.Load() != 0 || received.Load() != 1 {
		t.Fatal("Allow did not drop the denied datagram")
	}
}

// The end of ctx, the stream's EOF, and a close of either side stop both
// directions and close both sides.
func TestDatagramRelayStops(t *testing.T) {
	cause := errors.New("quota used up")
	tests := []struct {
		name string
		stop func(ctxCancel context.CancelCauseFunc, s *fakeStream, out PacketConn)
		want error
	}{
		{"context", func(cancel context.CancelCauseFunc, _ *fakeStream, _ PacketConn) { cancel(cause) }, cause},
		{"stream EOF", func(_ context.CancelCauseFunc, s *fakeStream, _ PacketConn) { close(s.eof) }, nil},
		{"stream closed", func(_ context.CancelCauseFunc, s *fakeStream, _ PacketConn) { _ = s.Close() }, nil},
		{"egress closed", func(_ context.CancelCauseFunc, _ *fakeStream, out PacketConn) { _ = out.Close() }, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkGoroutines(t)
			u, _ := newEgress(t, &fakeResolver{slow: make(chan struct{})})
			out := &countingPacketConn{PacketConn: u}
			echo, _ := echoUDP(t, newLoopbackUDP(t))
			s := newFakeStream()
			ctx, cancel := context.WithCancelCause(t.Context())
			defer cancel(nil)
			done := runRelay(t, ctx, nil, s, out)
			s.send(t, echo, "x")
			s.recv(t)
			// A lookup in progress ends with the relay too.
			s.send(t, netx.Addr{Name: "slow.test", Port: 9}, "held")
			tt.stop(cancel, s, out)
			if err := waitRelay(t, done); !errors.Is(err, tt.want) || (tt.want == nil && err != nil) {
				t.Fatalf("Relay() = %v, want %v", err, tt.want)
			}
			if s.closes.Load() == 0 || out.closes.Load() == 0 {
				t.Fatalf("stream closed %d times, egress %d times; want both closed", s.closes.Load(), out.closes.Load())
			}
		})
	}
}

// A context that is done already passes nothing.
func TestDatagramRelayDoneContext(t *testing.T) {
	checkGoroutines(t)
	u, _ := newEgress(t, nil)
	out := &countingPacketConn{PacketConn: u}
	s := newFakeStream()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := new(DatagramRelay).Relay(ctx, s, out); !errors.Is(err, context.Canceled) {
		t.Fatalf("Relay() = %v, want context.Canceled", err)
	}
	if s.closes.Load() != 1 || out.closes.Load() != 1 {
		t.Fatal("sides not closed")
	}
}

// IdleTimeout ends a relay without datagrams, and datagrams keep it going.
func TestDatagramRelayIdleTimeout(t *testing.T) {
	checkGoroutines(t)
	out, _ := newEgress(t, nil)
	echo, _ := echoUDP(t, newLoopbackUDP(t))
	s := newFakeStream()
	const idle = 150 * time.Millisecond
	done := runRelay(t, t.Context(), &DatagramRelay{IdleTimeout: idle}, s, out)
	start := time.Now()
	for time.Since(start) < 2*idle {
		s.send(t, echo, "keep")
		s.recv(t)
		time.Sleep(idle / 5)
	}
	select {
	case err := <-done:
		t.Fatalf("Relay() = %v while active", err)
	default:
	}
	if err := waitRelay(t, done); !errors.Is(err, netx.ErrRelayIdle) {
		t.Fatalf("Relay() = %v, want netx.ErrRelayIdle", err)
	}
}

// The relay runs over a FramedConn with datagram framing, and ends when
// the stream's other end closes.
func TestDatagramRelayFramedConn(t *testing.T) {
	checkGoroutines(t)
	out, _ := newEgress(t, nil)
	echo, _ := echoUDP(t, newLoopbackUDP(t))
	a, b := net.Pipe()
	client := netx.NewFramedConn(a, netx.WithFramedDatagrams())
	stream := netx.NewFramedConn(b, netx.WithFramedDatagrams())
	done := runRelay(t, t.Context(), nil, stream, out)
	msg, _ := AppendDatagram(nil, echo, []byte("framed"))
	if err := client.WriteFrame(msg); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 128)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if src, h, err := DecodeDatagram(buf[:n]); err != nil || src != echo || string(buf[h:n]) != "echo:framed" {
		t.Fatalf("reply %q from %v (%v)", buf[:n], src, err)
	}
	_ = client.Close()
	if err := waitRelay(t, done); err != nil {
		t.Fatalf("Relay() = %v, want nil after the stream's EOF", err)
	}
}

// recordingPacketConn records the datagrams sent to it.
type recordingPacketConn struct {
	dst     []netx.Addr
	payload [][]byte
}

func (c *recordingPacketConn) WriteTo(p []byte, dst netx.Addr) (int, error) {
	c.dst = append(c.dst, dst)
	c.payload = append(c.payload, bytes.Clone(p))
	return len(p), nil
}
func (c *recordingPacketConn) ReadFrom([]byte) (int, netx.Addr, error) { return 0, netx.Addr{}, io.EOF }
func (c *recordingPacketConn) Close() error                            { return nil }

// oneDatagram returns b once, then io.EOF.
type oneDatagram struct {
	b    []byte
	read bool
}

func (o *oneDatagram) Read(p []byte) (int, error) {
	if o.read {
		return 0, io.EOF
	}
	o.read = true
	return copy(p, o.b), nil
}
func (o *oneDatagram) Write(p []byte) (int, error) { return len(p), nil }

func FuzzDatagramRelayRequests(f *testing.F) {
	f.Add([]byte{0, 0, 0, 1, 127, 0, 0, 1, 0, 53, 'h', 'i'})
	f.Add([]byte{0, 0, 1, 1, 127, 0, 0, 1, 0, 53})
	f.Add([]byte{0, 0, 0, 3, 4, 'h', 'o', 's', 't', 0, 80, 'x'})
	f.Add([]byte{0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0})
	f.Add([]byte{0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		out := &recordingPacketConn{}
		d := &datagramRelay{stream: &oneDatagram{b: b}, out: out, onError: func(error) {}}
		if err := d.requests(); err != nil {
			t.Fatal(err)
		}
		dst, h, err := DecodeDatagram(b)
		if err != nil || len(b) >= MaxDatagramHeaderLen+65535 {
			if len(out.dst) != 0 {
				t.Fatalf("invalid datagram %x sent", b)
			}
			return
		}
		if len(out.dst) != 1 || out.dst[0] != dst || !bytes.Equal(out.payload[0], b[h:]) {
			t.Fatalf("datagram %x sent as %v %x", b, out.dst, out.payload)
		}
	})
}

func BenchmarkDatagramRelay(b *testing.B) {
	for _, size := range []int{64, 1400} {
		b.Run("ipv4/"+strconv.Itoa(size), func(b *testing.B) { benchmarkDatagramRelay(b, size, false) })
	}
	b.Run("name/64", func(b *testing.B) { benchmarkDatagramRelay(b, 64, true) })
}

// benchmarkDatagramRelay measures round trips from a FramedConn over TCP
// through the relay to a UDP echo and back.
func benchmarkDatagramRelay(b *testing.B, size int, name bool) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Skip(err)
	}
	defer func() { _ = ln.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	cc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		b.Fatal(err)
	}
	sc := <-accepted
	client := netx.NewFramedConn(cc, netx.WithFramedDatagrams())
	stream := netx.NewFramedConn(sc, netx.WithFramedDatagrams())

	out, _ := newEgress(b, &fakeResolver{})
	echoConn := newLoopbackUDP(b)
	echo, _ := echoUDP(b, echoConn)
	dst := echo
	if name {
		dst = netx.Addr{Name: "fast.test", Port: echo.Port}
	}
	done := make(chan error, 1)
	go func() { done <- new(DatagramRelay).Relay(context.Background(), stream, out) }()
	defer func() {
		_ = client.Close()
		<-done
	}()
	msg, _ := AppendDatagram(nil, dst, make([]byte, size))
	buf := make([]byte, 65535)
	roundTrip := func() {
		if err := client.WriteFrame(msg); err != nil {
			b.Fatal(err)
		}
		if _, err := client.Read(buf); err != nil {
			b.Fatal(err)
		}
	}
	for range 100 {
		roundTrip()
	}
	b.SetBytes(int64(size))
	b.ReportAllocs()
	for b.Loop() {
		roundTrip()
	}
}
