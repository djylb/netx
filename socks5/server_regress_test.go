package socks5_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/djylb/netx/socks5"
)

// checkNoAuth is a NoAuth authenticator that decides by the connection
// itself, as an IP allowlist or a TLS client certificate check does.
type checkNoAuth struct {
	user string
	err  error
}

func (checkNoAuth) Method() socks5.Method { return socks5.MethodNoAuth }

func (a checkNoAuth) Authenticate(context.Context, net.Conn) (string, error) {
	return a.user, a.err
}

func TestServerNoAuthAuthenticatorDecides(t *testing.T) {
	target := echoTCP(t)
	deny := serve(t, &socks5.Server{SOCKS4: true, Auth: []socks5.Authenticator{checkNoAuth{err: errors.New("not allowed")}}})
	dst, _ := socks5.ParseAddr(target)

	// A NoAuth method, an empty list and an unknown method all reach it.
	for _, methods := range [][]byte{{byte(socks5.MethodNoAuth)}, {}, {byte(socks5.MethodGSSAPI)}} {
		c, err := net.Dial("tcp", deny)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write(append([]byte{socks5.Version, byte(len(methods))}, methods...))
		if m, err := socks5.ReadMethod(c); err != nil || m != socks5.MethodNoAuth {
			t.Fatalf("methods %v: selected %v, %v", methods, m, err)
		}
		_ = socks5.WriteRequest(c, socks5.CmdConnect, dst)
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := socks5.ReadReply(c); err == nil {
			t.Fatalf("methods %v: CONNECT succeeded past the authenticator", methods)
		}
		_ = c.Close()
	}

	// Username/password alone: any credentials, then the authenticator.
	c, err := net.Dial("tcp", deny)
	if err != nil {
		t.Fatal(err)
	}
	_ = socks5.WriteMethods(c, socks5.MethodUserPass)
	if m, err := socks5.ReadMethod(c); err != nil || m != socks5.MethodUserPass {
		t.Fatalf("user/pass: selected %v, %v", m, err)
	}
	_ = socks5.WriteUserPass(c, "any", "thing")
	if err := socks5.ReadUserPassStatus(c); !errors.Is(err, socks5.ErrAuthFailed) {
		t.Fatalf("user/pass status = %v, want %v", err, socks5.ErrAuthFailed)
	}
	_ = c.Close()

	// SOCKS4 has no authentication of its own.
	_, err = (&socks5.Dialer{ProxyAddr: deny, SOCKS4: true}).Dial("tcp", target)
	var replyErr *socks5.ReplyError
	if !errors.As(err, &replyErr) || replyErr.Reply != socks5.Reply4Rejected {
		t.Fatalf("SOCKS4 error = %v, want %v", err, socks5.Reply4Rejected)
	}

	// An accepting authenticator names SOCKS4 clients.
	users := make(chan string, 1)
	allow := serve(t, &socks5.Server{
		SOCKS4: true,
		Auth:   []socks5.Authenticator{checkNoAuth{user: "trusted-net"}},
		Allow: func(_ context.Context, req *socks5.Request) error {
			users <- req.User
			return nil
		},
	})
	c, err = (&socks5.Dialer{ProxyAddr: allow, SOCKS4: true}).Dial("tcp", target)
	if err != nil {
		t.Fatalf("SOCKS4 Dial() error = %v", err)
	}
	_ = c.Close()
	if user := <-users; user != "trusted-net" {
		t.Fatalf("Request.User = %q, want the authenticator's identity", user)
	}
}

// TestServerUDPIgnoresForeignAnnouncement checks that a client cannot claim
// the datagrams of another IP address by announcing it.
func TestServerUDPIgnoresForeignAnnouncement(t *testing.T) {
	victimUDP, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skip("no IPv6 loopback:", err)
	}
	defer func() { _ = victimUDP.Close() }()
	pc, err := net.ListenPacket("udp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	handlers := make(chan string, 1)
	s := &socks5.Server{
		PacketConn: pc,
		AllowPacket: func(req *socks5.Request, _ socks5.Addr) bool {
			handlers <- req.Conn.RemoteAddr().String()
			return false
		},
	}
	go func() { _ = s.Serve(ln) }()
	t.Cleanup(func() { _ = s.Close() })
	port := ln.Addr().(*net.TCPAddr).Port
	probe, err := net.Dial("tcp", net.JoinHostPort("::1", strconv.Itoa(port)))
	if err != nil {
		t.Skip("listener is not dual-stack:", err)
	}
	_ = probe.Close()

	victim, _ := associate(t, net.JoinHostPort("::1", strconv.Itoa(port)), socks5.Addr{})
	attacker, _ := associate(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), socks5.AddrFromNetAddr(victimUDP.LocalAddr()))
	defer func() { _ = attacker.Close() }()

	packet, _ := socks5.AppendDatagram(nil, socks5.Addr{IP: netip.MustParseAddr("192.0.2.1"), Port: 9}, []byte("victim"))
	relay := &net.UDPAddr{IP: net.IPv6loopback, Port: pc.LocalAddr().(*net.UDPAddr).Port}
	if _, err := victimUDP.WriteToUDP(packet, relay); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-handlers:
		if got != victim.LocalAddr().String() {
			t.Fatalf("datagram handled by the association of %s, want the victim's %s", got, victim.LocalAddr())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the victim's datagram was not routed")
	}
}

// TestServerCloseEndsOutlivingAssociation checks that Close ends an
// association kept by UDPOutlivesControl and its own socket.
func TestServerCloseEndsOutlivingAssociation(t *testing.T) {
	echo := udpEcho(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &socks5.Server{
		UDPOutlivesControl: true,
		ListenUDP: func(context.Context, *socks5.Request) (net.PacketConn, error) {
			return net.ListenPacket("udp", "127.0.0.1:0")
		},
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(ln) }()
	ctl, relay := associate(t, ln.Addr().String(), socks5.Addr{})
	client := newUDPClient(t)
	if got, _ := exchange(t, client, relay, echo, "before"); got != "echo:before" {
		t.Fatalf("reply = %q", got)
	}
	_ = ctl.Close()
	_ = s.Close()
	<-done
	time.Sleep(50 * time.Millisecond)
	if got, _ := exchange(t, client, relay, echo, "after"); got != "" {
		t.Fatalf("reply %q after Close", got)
	}
}

// noAddrConn has no remote address, like some multiplexed streams.
type noAddrConn struct{ net.Conn }

func (noAddrConn) RemoteAddr() net.Addr { return nil }

// associateWithoutAddr sends a UDP ASSOCIATE announcing announced over a
// control connection without a remote address and returns the reply.
func associateWithoutAddr(t *testing.T, s *socks5.Server, announced socks5.Addr) (socks5.Addr, error) {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	go func() { _ = s.ServeConn(noAddrConn{server}) }()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	_ = socks5.WriteMethods(client, socks5.MethodNoAuth)
	if _, err := socks5.ReadMethod(client); err != nil {
		t.Fatal(err)
	}
	_ = socks5.WriteRequest(client, socks5.CmdUDPAssociate, announced)
	return socks5.ReadReply(client)
}

// TestServerUDPWithoutRemoteAddr checks that the shared socket, which routes
// datagrams by client IP address, needs one from the control connection or
// the request, and refuses rather than accepts an association it cannot
// route.
func TestServerUDPWithoutRemoteAddr(t *testing.T) {
	echo := udpEcho(t)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &socks5.Server{PacketConn: pc}
	defer func() { _ = s.Close() }()
	var replyErr *socks5.ReplyError
	if _, err := associateWithoutAddr(t, s, socks5.Addr{}); !errors.As(err, &replyErr) {
		t.Fatalf("unannounced UDP ASSOCIATE reply error = %v, want a refusal", err)
	}
	client := newUDPClient(t)
	relay, err := associateWithoutAddr(t, s, socks5.AddrFromNetAddr(client.LocalAddr()))
	if err != nil {
		t.Fatalf("announced UDP ASSOCIATE reply error = %v", err)
	}
	if got, _ := exchange(t, client, net.UDPAddrFromAddrPort(netip.AddrPortFrom(relay.IP, relay.Port)), echo, "announced"); got != "echo:announced" {
		t.Fatalf("reply = %q", got)
	}
}

// TestServerUDPOwnSocketWithoutRemoteAddr checks that an association with a
// socket of its own and no known client IP address takes the first source
// that sends, and only that one.
func TestServerUDPOwnSocketWithoutRemoteAddr(t *testing.T) {
	echo := udpEcho(t)
	s := &socks5.Server{ListenUDP: func(context.Context, *socks5.Request) (net.PacketConn, error) {
		return net.ListenPacket("udp", "127.0.0.1:0")
	}}
	defer func() { _ = s.Close() }()
	bound, err := associateWithoutAddr(t, s, socks5.Addr{})
	if err != nil {
		t.Fatalf("UDP ASSOCIATE reply error = %v", err)
	}
	relay := net.UDPAddrFromAddrPort(netip.AddrPortFrom(bound.IP, bound.Port))
	first, other := newUDPClient(t), newUDPClient(t)
	if got, _ := exchange(t, first, relay, echo, "first"); got != "echo:first" {
		t.Fatalf("first source reply = %q", got)
	}
	if got, _ := exchange(t, other, relay, echo, "other"); got != "" {
		t.Fatalf("second source got reply %q", got)
	}
	if got, _ := exchange(t, first, relay, echo, "again"); got != "echo:again" {
		t.Fatalf("first source reply = %q", got)
	}
}

func TestReplyForTranslatesSOCKS4(t *testing.T) {
	for in, want := range map[socks5.Reply]socks5.Reply{
		socks5.ReplyConnectionRefused: socks5.ReplyConnectionRefused,
		socks5.Reply4Rejected:         socks5.ReplyGeneralFailure,
		socks5.Reply4IdentdMismatch:   socks5.ReplyNotAllowed,
		socks5.Reply(200):             socks5.ReplyGeneralFailure,
		socks5.ReplySucceeded:         socks5.ReplyGeneralFailure, // an error is no success
	} {
		if got := socks5.ReplyFor(&socks5.ReplyError{Reply: in}); got != want {
			t.Errorf("ReplyFor(%v) = %v, want %v", in, got, want)
		}
	}
	if got := socks5.ReplyFor(io.EOF); got != socks5.ReplyGeneralFailure {
		t.Errorf("ReplyFor(EOF) = %v", got)
	}
}

// temporaryError is a temporary Accept error such as EMFILE.
type temporaryError struct{}

func (temporaryError) Error() string   { return "too many open files" }
func (temporaryError) Timeout() bool   { return false }
func (temporaryError) Temporary() bool { return true }

// failingListener returns its errors from Accept before accepting.
type failingListener struct {
	net.Listener
	mu   sync.Mutex
	errs []error
}

func (l *failingListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if len(l.errs) > 0 {
		err := l.errs[0]
		l.errs = l.errs[1:]
		l.mu.Unlock()
		return nil, err
	}
	l.mu.Unlock()
	return l.Listener.Accept()
}

func TestServeRetriesTemporaryAcceptErrors(t *testing.T) {
	target := echoTCP(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	emfile := &net.OpError{Op: "accept", Net: "tcp", Err: os.NewSyscallError("accept", temporaryError{})}
	s := &socks5.Server{}
	done := make(chan error, 1)
	go func() { done <- s.Serve(&failingListener{Listener: ln, errs: []error{emfile, emfile}}) }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := (&socks5.Dialer{ProxyAddr: ln.Addr().String()}).DialContext(ctx, "tcp", target)
	if err != nil {
		t.Fatalf("Dial() after temporary Accept errors = %v", err)
	}
	assertEcho(t, c, "still serving")
	_ = c.Close()
	_ = s.Close()
	if err := <-done; !errors.Is(err, socks5.ErrServerClosed) {
		t.Fatalf("Serve() = %v, want %v", err, socks5.ErrServerClosed)
	}

	// Other errors still end Serve.
	fatal := errors.New("listener broken")
	ln, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	if err := (&socks5.Server{}).Serve(&failingListener{Listener: ln, errs: []error{fatal}}); !errors.Is(err, fatal) {
		t.Fatalf("Serve() = %v, want %v", err, fatal)
	}
}

// TestServerAllowSeesEveryIPForm checks that Allow sees an IPv4-mapped IPv6
// address and an IP literal sent as a name, also with a trailing dot, as the
// IP address, so that an
// address policy cannot be bypassed with them, and that a refusal without a
// reply code is not reported as success.
func TestServerAllowSeesEveryIPForm(t *testing.T) {
	target := netip.MustParseAddrPort(echoTCP(t))
	ip, port := target.Addr(), target.Port()
	loopback := netip.MustParsePrefix("127.0.0.0/8")
	seen := make(chan socks5.Addr, 1)
	addr := serve(t, &socks5.Server{
		SOCKS4: true,
		Allow: func(_ context.Context, req *socks5.Request) error {
			if req.Dst.Name == "refused.example" {
				return &socks5.ReplyError{}
			}
			seen <- req.Dst
			if loopback.Contains(req.Dst.IP) {
				return errors.New("loopback")
			}
			return nil
		},
	})
	portBytes := []byte{byte(port >> 8), byte(port)}
	name := func(host string) []byte {
		return append(append([]byte{3, byte(len(host))}, host...), portBytes...)
	}
	mapped := netip.AddrFrom16(ip.As16()).AsSlice()
	for desc, wire := range map[string][]byte{
		"IPv4":                 append(append([]byte{1}, ip.AsSlice()...), portBytes...),
		"IPv4-mapped IPv6":     append(append([]byte{4}, mapped...), portBytes...),
		"IPv4 literal name":    name(ip.String()),
		"mapped literal name":  name("::ffff:" + ip.String()),
		"trailing dot name":    name(ip.String() + "."),
		"refused without code": name("refused.example"),
	} {
		c := handshake(t, addr)
		_, _ = c.Write(append([]byte{socks5.Version, byte(socks5.CmdConnect), 0}, wire...))
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := socks5.ReadReply(c); err == nil {
			t.Errorf("%s: CONNECT allowed", desc)
		}
		if desc == "refused without code" {
			continue
		}
		if got := <-seen; got != (socks5.Addr{IP: ip, Port: port}) {
			t.Errorf("%s: Allow saw IP %v, Name %q", desc, got.IP, got.Name)
		}
	}

	// SOCKS4a names that are IP literals too.
	for _, host := range []string{ip.String(), ip.String() + "."} {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write(append([]byte{4, 1, portBytes[0], portBytes[1], 0, 0, 0, 1, 0}, host+"\x00"...))
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := socks5.ReadReply4(c); err == nil {
			t.Errorf("SOCKS4a CONNECT to %q allowed", host)
		}
		_ = c.Close()
		if got := <-seen; got != (socks5.Addr{IP: ip, Port: port}) {
			t.Errorf("SOCKS4a %q: Allow saw IP %v, Name %q", host, got.IP, got.Name)
		}
	}
}

// oversizePacketConn fails to send datagrams larger than limit, as a socket
// does with EMSGSIZE.
type oversizePacketConn struct {
	net.PacketConn
	limit int
}

func (c oversizePacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if len(p) > c.limit {
		return 0, &net.OpError{Op: "write", Net: "udp", Addr: addr, Err: errors.New("message too long")}
	}
	return c.PacketConn.WriteTo(p, addr)
}

// TestServerUDPKeepsAssociationAfterUndeliverableReply checks that a reply
// that cannot be sent to the client, here one too large once wrapped, is
// reported and dropped without ending the association.
func TestServerUDPKeepsAssociationAfterUndeliverableReply(t *testing.T) {
	echo := udpEcho(t)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	errs := make(chan error, 8)
	addr := serve(t, &socks5.Server{
		PacketConn: oversizePacketConn{PacketConn: pc, limit: 1024},
		OnError: func(_ net.Conn, err error) {
			select {
			case errs <- err:
			default:
			}
		},
	})
	ctl, relay := associate(t, addr, socks5.Addr{})
	client := newUDPClient(t)
	if got, _ := exchange(t, client, relay, echo, strings.Repeat("x", 1500)); got != "" {
		t.Fatalf("oversized reply delivered: %d bytes", len(got))
	}
	select {
	case err := <-errs:
		if !strings.Contains(err.Error(), "message too long") {
			t.Fatalf("OnError(%v), want the send error", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("undeliverable reply not reported")
	}
	if got, _ := exchange(t, client, relay, echo, "small"); got != "echo:small" {
		t.Fatalf("reply after an undeliverable one = %q", got)
	}
	_ = ctl.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, err := ctl.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("control connection read = %v, want it still open", err)
	}
}

// sliceConn and sliceListener are value types that cannot be map keys, like
// wrappers that carry a buffer.
type sliceConn struct {
	net.Conn
	scratch []byte
}

type sliceListener struct {
	net.Listener
	tags []string
}

func TestServerServesUncomparableConnsAndListeners(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &socks5.Server{}
	served := make(chan error, 1)
	go func() { served <- s.Serve(sliceListener{Listener: ln, tags: []string{"socks"}}) }()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	done := make(chan error, 1)
	go func() { done <- s.ServeConn(sliceConn{Conn: server, scratch: make([]byte, 1)}) }()
	if _, err := client.Write([]byte{socks5.Version}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := <-served; !errors.Is(err, socks5.ErrServerClosed) {
		t.Fatalf("Serve() = %v, want ErrServerClosed", err)
	}
	<-done // Close closed the connection
}

// A client that does not know its address announces its port with 0.0.0.0
// (RFC 1928) or a name such as "0"; the port still tells two associations of
// one IP address apart.
func TestServerUDPAnnouncedPortWithoutAddress(t *testing.T) {
	echo := udpEcho(t)
	for _, tt := range []struct {
		name     string
		announce func(port uint16) socks5.Addr
	}{
		{"exact address", func(p uint16) socks5.Addr { return socks5.Addr{IP: netip.MustParseAddr("127.0.0.1"), Port: p} }},
		{"unspecified address", func(p uint16) socks5.Addr { return socks5.Addr{IP: netip.IPv4Unspecified(), Port: p} }},
		{"name", func(p uint16) socks5.Addr { return socks5.Addr{Name: "0", Port: p} }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			pc, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			addr := serve(t, &socks5.Server{PacketConn: pc})
			a, b := newUDPClient(t), newUDPClient(t)
			port := func(c *net.UDPConn) uint16 { return uint16(c.LocalAddr().(*net.UDPAddr).Port) }
			_, relayA := associate(t, addr, tt.announce(port(a)))
			_, relayB := associate(t, addr, tt.announce(port(b)))
			gotA, _ := exchange(t, a, relayA, echo, "a")
			gotB, _ := exchange(t, b, relayB, echo, "b")
			if gotA != "echo:a" || gotB != "echo:b" {
				t.Fatalf("replies a=%q b=%q, want both echoed", gotA, gotB)
			}
		})
	}
}

// An association that ends closes its control connection also when that
// connection has no deadlines to interrupt the read with.
func TestServerUDPIdleClosesControlWithoutDeadlines(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &socks5.Server{PacketConn: pc, UDPIdleTimeout: 100 * time.Millisecond}
	defer func() { _ = s.Close() }()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	served := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			served <- err
			return
		}
		served <- s.ServeConn(noDeadlineConn{c})
	}()
	ctl, _ := associate(t, ln.Addr().String(), socks5.Addr{})
	defer func() { _ = ctl.Close() }()
	_ = ctl.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := ctl.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("control Read() error = %v, want EOF once the association idles out", err)
	}
	if err := <-served; err != nil {
		t.Fatalf("ServeConn() = %v, want nil", err)
	}
}
