package socks5_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/djylb/netx/internal/nettest"
	"github.com/djylb/netx/socks5"
)

// serve runs s on a loopback listener and returns its address.
func serve(t *testing.T, s *socks5.Server) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(ln) }()
	t.Cleanup(func() {
		_ = s.Close()
		if err := <-done; !errors.Is(err, socks5.ErrServerClosed) {
			t.Errorf("Serve() = %v, want ErrServerClosed", err)
		}
	})
	return ln.Addr().String()
}

// echoTCP starts a TCP echo server.
func echoTCP(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return nettest.ServeEcho(t, ln)
}

func assertEcho(t *testing.T, c net.Conn, msg string) {
	t.Helper()
	if _, err := io.WriteString(c, msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != msg {
		t.Fatalf("echo = %q, %v; want %q", buf, err, msg)
	}
}

func TestServerConnect(t *testing.T) {
	target := echoTCP(t)
	addr := serve(t, &socks5.Server{})
	c, err := (&socks5.Dialer{ProxyAddr: addr}).Dial("tcp", target)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer func() { _ = c.Close() }()
	assertEcho(t, c, "ping")
}

func TestServerUserPassAuth(t *testing.T) {
	target := echoTCP(t)
	var gotUser string
	var mu sync.Mutex
	addr := serve(t, &socks5.Server{
		Auth: []socks5.Authenticator{socks5.UserPassAuth{Check: socks5.Credentials(map[string]string{"alice": "pw"})}},
		Allow: func(_ context.Context, req *socks5.Request) error {
			mu.Lock()
			gotUser = req.User
			mu.Unlock()
			return nil
		},
	})
	c, err := (&socks5.Dialer{ProxyAddr: addr, Username: "alice", Password: "pw"}).Dial("tcp", target)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	assertEcho(t, c, "auth")
	_ = c.Close()
	mu.Lock()
	if gotUser != "alice" {
		t.Fatalf("Request.User = %q, want alice", gotUser)
	}
	mu.Unlock()

	if _, err := (&socks5.Dialer{ProxyAddr: addr, Username: "alice", Password: "bad"}).Dial("tcp", target); !errors.Is(err, socks5.ErrAuthFailed) {
		t.Fatalf("wrong password error = %v", err)
	}
	if _, err := (&socks5.Dialer{ProxyAddr: addr}).Dial("tcp", target); !errors.Is(err, socks5.ErrNoAcceptableMethod) {
		t.Fatalf("anonymous error = %v", err)
	}
}

func TestServerReplies(t *testing.T) {
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	refused := closed.Addr().String()
	_ = closed.Close()
	addr := serve(t, &socks5.Server{
		Allow: func(_ context.Context, req *socks5.Request) error {
			switch req.Dst.Name {
			case "denied.example":
				return errors.New("policy")
			case "unreachable.example":
				return &socks5.ReplyError{Reply: socks5.ReplyHostUnreachable}
			}
			return nil
		},
	})
	d := &socks5.Dialer{ProxyAddr: addr}
	for target, want := range map[string]socks5.Reply{
		"denied.example:80":      socks5.ReplyNotAllowed,
		"unreachable.example:80": socks5.ReplyHostUnreachable,
		refused:                  socks5.ReplyConnectionRefused,
	} {
		_, err := d.Dial("tcp", target)
		var replyErr *socks5.ReplyError
		if !errors.As(err, &replyErr) || replyErr.Reply != want {
			t.Errorf("Dial(%s) error = %v, want %v", target, err, want)
		}
	}

	// BIND and, without a UDP socket, UDP ASSOCIATE are not supported.
	for _, cmd := range []socks5.Command{socks5.CmdBind, socks5.CmdUDPAssociate} {
		c := handshake(t, addr)
		if err := socks5.WriteRequest(c, cmd, socks5.Addr{}); err != nil {
			t.Fatal(err)
		}
		_, err := socks5.ReadReply(c)
		var replyErr *socks5.ReplyError
		if !errors.As(err, &replyErr) || replyErr.Reply != socks5.ReplyCommandNotSupported {
			t.Errorf("%v reply = %v", cmd, err)
		}
	}
}

func TestServerHooks(t *testing.T) {
	type call struct {
		dst  socks5.Addr
		user string
	}
	calls := make(chan call, 1)
	relayed := make(chan struct{}, 1)
	addr := serve(t, &socks5.Server{
		Dial: func(_ context.Context, req *socks5.Request) (net.Conn, error) {
			calls <- call{req.Dst, req.User}
			client, server := net.Pipe()
			go func() {
				defer func() { _ = server.Close() }()
				_, _ = io.Copy(server, server)
			}()
			return client, nil
		},
		ConnectAddr: func(*socks5.Request, net.Conn) socks5.Addr {
			return socks5.Addr{IP: netip.MustParseAddr("192.0.2.1"), Port: 1234}
		},
		Relay: func(_ context.Context, _ *socks5.Request, client, target net.Conn) error {
			relayed <- struct{}{}
			defer func() { _ = client.Close(); _ = target.Close() }()
			go func() { _, _ = io.Copy(target, client) }()
			_, err := io.Copy(client, target)
			return err
		},
	})
	c := handshake(t, addr)
	if err := socks5.WriteRequest(c, socks5.CmdConnect, socks5.Addr{Name: "virtual.example", Port: 9}); err != nil {
		t.Fatal(err)
	}
	bound, err := socks5.ReadReply(c)
	if err != nil || bound.String() != "192.0.2.1:1234" {
		t.Fatalf("ReadReply() = %v, %v", bound, err)
	}
	if got := <-calls; got.dst.String() != "virtual.example:9" || got.user != "" {
		t.Fatalf("Dial request = %+v", got)
	}
	<-relayed
	assertEcho(t, c, "hooked")
}

// handshake connects to a SOCKS5 server without authentication.
func handshake(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if err := socks5.WriteMethods(c, socks5.MethodNoAuth); err != nil {
		t.Fatal(err)
	}
	if m, err := socks5.ReadMethod(c); err != nil || m != socks5.MethodNoAuth {
		t.Fatalf("ReadMethod() = %v, %v", m, err)
	}
	return c
}

func TestServerSOCKS4(t *testing.T) {
	target := echoTCP(t)
	tAddr := netip.MustParseAddrPort(target)
	request4 := func(addr string, ip [4]byte, port uint16, name string) (net.Conn, byte) {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		msg := []byte{4, 1, byte(port >> 8), byte(port)}
		msg = append(msg, ip[:]...)
		msg = append(msg, "user\x00"...)
		if name != "" {
			msg = append(msg, name+"\x00"...)
		}
		_, _ = c.Write(msg)
		reply := make([]byte, 8)
		if _, err := io.ReadFull(c, reply); err != nil {
			return c, 0
		}
		return c, reply[1]
	}

	var dialed []string
	var mu sync.Mutex
	addr := serve(t, &socks5.Server{
		SOCKS4: true,
		Dial: func(ctx context.Context, req *socks5.Request) (net.Conn, error) {
			mu.Lock()
			dialed = append(dialed, req.Dst.String())
			mu.Unlock()
			if req.Version != 4 {
				t.Errorf("Request.Version = %d", req.Version)
			}
			var d net.Dialer
			if req.Dst.Name == "echo.example" {
				return d.DialContext(ctx, "tcp", target)
			}
			return d.DialContext(ctx, "tcp", req.Dst.String())
		},
	})
	c, code := request4(addr, tAddr.Addr().As4(), tAddr.Port(), "")
	if code != 90 {
		t.Fatalf("SOCKS4 reply = %d, want 90", code)
	}
	assertEcho(t, c, "v4")
	c, code = request4(addr, [4]byte{0, 0, 0, 1}, tAddr.Port(), "echo.example")
	if code != 90 {
		t.Fatalf("SOCKS4a reply = %d, want 90", code)
	}
	assertEcho(t, c, "v4a")
	mu.Lock()
	if len(dialed) != 2 || dialed[1] != "echo.example:"+tAddrPort(tAddr) {
		t.Fatalf("dialed = %v", dialed)
	}
	mu.Unlock()

	// Refused while authentication is required, and when disabled.
	authAddr := serve(t, &socks5.Server{SOCKS4: true, Auth: []socks5.Authenticator{socks5.UserPassAuth{}}})
	if _, code := request4(authAddr, tAddr.Addr().As4(), tAddr.Port(), ""); code != 91 {
		t.Fatalf("SOCKS4 with auth reply = %d, want 91", code)
	}
	if _, code := request4(serve(t, &socks5.Server{}), tAddr.Addr().As4(), tAddr.Port(), ""); code != 0 {
		t.Fatalf("SOCKS4 disabled reply = %d, want a closed connection", code)
	}
}

func tAddrPort(ap netip.AddrPort) string {
	return strings.TrimPrefix(ap.String(), ap.Addr().String()+":")
}

// udpEcho starts a UDP echo server.
func udpEcho(t *testing.T) *net.UDPAddr {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteToUDP(append([]byte("echo:"), buf[:n]...), from)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr)
}

// associate opens a UDP association announcing announced and returns the
// control connection and the relay address.
func associate(t *testing.T, addr string, announced socks5.Addr) (net.Conn, *net.UDPAddr) {
	t.Helper()
	c := handshake(t, addr)
	if err := socks5.WriteRequest(c, socks5.CmdUDPAssociate, announced); err != nil {
		t.Fatal(err)
	}
	bound, err := socks5.ReadReply(c)
	if err != nil {
		t.Fatalf("UDP ASSOCIATE reply error = %v", err)
	}
	return c, net.UDPAddrFromAddrPort(netip.AddrPortFrom(bound.IP, bound.Port))
}

// exchange sends payload to dst through relay from client and returns the
// reply, or "" on timeout.
func exchange(t *testing.T, client *net.UDPConn, relay *net.UDPAddr, dst *net.UDPAddr, payload string) (string, socks5.Addr) {
	t.Helper()
	packet, _ := socks5.AppendDatagram(nil, socks5.AddrFromNetAddr(dst), []byte(payload))
	if _, err := client.WriteToUDP(packet, relay); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	_ = client.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	n, _, err := client.ReadFromUDP(buf)
	if err != nil {
		return "", socks5.Addr{}
	}
	src, data, err := socks5.ParseDatagram(buf[:n])
	if err != nil {
		t.Fatalf("reply datagram error = %v", err)
	}
	return string(data), src
}

func newUDPClient(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestServerUDPSharedSocket(t *testing.T) {
	echo := udpEcho(t)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := serve(t, &socks5.Server{PacketConn: pc})

	ctl, relay := associate(t, addr, socks5.Addr{})
	if relay.String() != pc.LocalAddr().String() {
		t.Fatalf("relay address = %v, want the shared socket %v", relay, pc.LocalAddr())
	}
	client := newUDPClient(t)
	got, src := exchange(t, client, relay, echo, "one")
	if got != "echo:one" || src.String() != echo.String() {
		t.Fatalf("reply = %q from %v", got, src)
	}

	// Two associations of the same IP that announced their sources.
	a, b := newUDPClient(t), newUDPClient(t)
	_, relayA := associate(t, addr, socks5.AddrFromNetAddr(a.LocalAddr()))
	_, relayB := associate(t, addr, socks5.AddrFromNetAddr(b.LocalAddr()))
	if got, _ := exchange(t, b, relayB, echo, "b"); got != "echo:b" {
		t.Fatalf("announced b reply = %q", got)
	}
	if got, _ := exchange(t, a, relayA, echo, "a"); got != "echo:a" {
		t.Fatalf("announced a reply = %q", got)
	}

	// Two unannounced associations of one IP are ambiguous for a new source.
	associate(t, addr, socks5.Addr{})
	associate(t, addr, socks5.Addr{})
	if got, _ := exchange(t, newUDPClient(t), relay, echo, "ambiguous"); got != "" {
		t.Fatalf("ambiguous source got reply %q", got)
	}

	// Closing the control connection ends the association.
	_ = ctl.Close()
	time.Sleep(50 * time.Millisecond)
	if got, _ := exchange(t, client, relay, echo, "after close"); got != "" {
		t.Fatalf("reply %q after the control connection closed", got)
	}
}

// closeNotifyPacketConn reports when it is closed.
type closeNotifyPacketConn struct {
	net.PacketConn
	closed chan struct{}
	once   sync.Once
}

func (c *closeNotifyPacketConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.PacketConn.Close()
}

func TestServerUDPPerAssociationSocket(t *testing.T) {
	echo := udpEcho(t)
	sockets := make(chan *closeNotifyPacketConn, 1)
	addr := serve(t, &socks5.Server{
		ListenUDP: func(context.Context, *socks5.Request) (net.PacketConn, error) {
			pc, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				return nil, err
			}
			c := &closeNotifyPacketConn{PacketConn: pc, closed: make(chan struct{})}
			sockets <- c
			return c, nil
		},
	})
	ctl, relay := associate(t, addr, socks5.Addr{})
	pc := <-sockets
	if relay.String() != pc.LocalAddr().String() {
		t.Fatalf("relay = %v, want the association socket %v", relay, pc.LocalAddr())
	}
	if got, _ := exchange(t, newUDPClient(t), relay, echo, "own"); got != "echo:own" {
		t.Fatalf("reply = %q", got)
	}
	_ = ctl.Close()
	select {
	case <-pc.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("association socket still open after the control connection closed")
	}
}

func TestServerUDPIdleTimeout(t *testing.T) {
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	addr := serve(t, &socks5.Server{PacketConn: pc, UDPIdleTimeout: 100 * time.Millisecond})
	ctl, _ := associate(t, addr, socks5.Addr{})
	_ = ctl.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := ctl.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("control Read() error = %v, want EOF after the idle timeout", err)
	}
}

// memPacketConn answers every datagram from a made-up source.
type memPacketConn struct {
	replies chan []byte
	closed  chan struct{}
	once    sync.Once
}

func (m *memPacketConn) WriteTo(p []byte, dst socks5.Addr) (int, error) {
	select {
	case m.replies <- append([]byte(dst.String()+"|"), p...):
	default:
	}
	return len(p), nil
}

func (m *memPacketConn) ReadFrom(p []byte) (int, socks5.Addr, error) {
	select {
	case r := <-m.replies:
		return copy(p, r), socks5.Addr{Name: "tunnel.example", Port: 7}, nil
	case <-m.closed:
		return 0, socks5.Addr{}, net.ErrClosed
	}
}

func (m *memPacketConn) Close() error {
	m.once.Do(func() { close(m.closed) })
	return nil
}

func TestServerUDPCustomEgress(t *testing.T) {
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	addr := serve(t, &socks5.Server{
		PacketConn: pc,
		DialPacket: func(context.Context, *socks5.Request) (socks5.PacketConn, error) {
			return &memPacketConn{replies: make(chan []byte, 8), closed: make(chan struct{})}, nil
		},
		AllowPacket: func(_ *socks5.Request, dst socks5.Addr) bool { return dst.Name != "blocked.example" },
		UDPAddr: func(_ *socks5.Request, socket net.Addr) socks5.Addr {
			return socks5.AddrFromNetAddr(socket)
		},
	})
	_, relay := associate(t, addr, socks5.Addr{})
	client := newUDPClient(t)
	send := func(dst socks5.Addr, payload string) (string, socks5.Addr) {
		packet, _ := socks5.AppendDatagram(nil, dst, []byte(payload))
		_, _ = client.WriteToUDP(packet, relay)
		buf := make([]byte, 2048)
		_ = client.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, _, err := client.ReadFromUDP(buf)
		if err != nil {
			return "", socks5.Addr{}
		}
		src, data, _ := socks5.ParseDatagram(buf[:n])
		return string(data), src
	}
	// Domain names reach the custom egress unresolved.
	got, src := send(socks5.Addr{Name: "dns.example", Port: 53}, "q")
	if got != "dns.example:53|q" || src.String() != "tunnel.example:7" {
		t.Fatalf("reply = %q from %v", got, src)
	}
	if got, _ := send(socks5.Addr{Name: "blocked.example", Port: 53}, "q"); got != "" {
		t.Fatalf("blocked destination got reply %q", got)
	}
}

func TestServerCloseEndsConnections(t *testing.T) {
	s := &socks5.Server{}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	done := make(chan error, 1)
	go func() { done <- s.Serve(ln) }()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	time.Sleep(20 * time.Millisecond) // let ServeConn start
	if err := s.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := <-done; !errors.Is(err, socks5.ErrServerClosed) {
		t.Fatalf("Serve() = %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil || errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("Read() after Close error = %v, want the connection closed", err)
	}
	if err := s.Serve(ln); !errors.Is(err, socks5.ErrServerClosed) {
		t.Fatalf("Serve() after Close = %v", err)
	}
	if err := s.ServeConn(nopConn{}); !errors.Is(err, socks5.ErrServerClosed) {
		t.Fatalf("ServeConn() after Close = %v", err)
	}
}

type nopConn struct{ net.Conn }

func (nopConn) Close() error { return nil }

// Clients that do not follow the method negotiation are still served when the
// server does not require authentication.
func TestServerLenientNegotiation(t *testing.T) {
	target := echoTCP(t)
	addr := serve(t, &socks5.Server{})
	dst, _ := socks5.ParseAddr(target)
	connect := func(methods []byte, auth bool) net.Conn {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		_, _ = c.Write(append([]byte{5, byte(len(methods))}, methods...))
		method, err := socks5.ReadMethod(c)
		if err != nil {
			t.Fatalf("methods %v: ReadMethod() error = %v", methods, err)
		}
		if auth != (method == socks5.MethodUserPass) {
			t.Fatalf("methods %v: selected %v", methods, method)
		}
		if auth {
			_ = socks5.WriteUserPass(c, "anyone", "anything")
			if err := socks5.ReadUserPassStatus(c); err != nil {
				t.Fatalf("credentials refused: %v", err)
			}
		}
		// A non-zero reserved byte in the request.
		req, _ := dst.AppendBinary([]byte{5, byte(socks5.CmdConnect), 0x7f})
		_, _ = c.Write(req)
		if _, err := socks5.ReadReply(c); err != nil {
			t.Fatalf("methods %v: reply error = %v", methods, err)
		}
		return c
	}
	assertEcho(t, connect(nil, false), "empty list")
	assertEcho(t, connect([]byte{byte(socks5.MethodGSSAPI)}, false), "gssapi only")
	assertEcho(t, connect([]byte{byte(socks5.MethodUserPass)}, true), "userpass only")
}

func TestServerUDPOutlivesControl(t *testing.T) {
	echo := udpEcho(t)
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	addr := serve(t, &socks5.Server{PacketConn: pc, UDPOutlivesControl: true, UDPIdleTimeout: 300 * time.Millisecond})
	ctl, relay := associate(t, addr, socks5.Addr{})
	client := newUDPClient(t)
	_ = ctl.(*net.TCPConn).CloseWrite()
	_ = ctl.Close()
	time.Sleep(50 * time.Millisecond)
	if got, _ := exchange(t, client, relay, echo, "still here"); got != "echo:still here" {
		t.Fatalf("reply after the control connection closed = %q", got)
	}
	time.Sleep(500 * time.Millisecond) // past the idle timeout
	if got, _ := exchange(t, client, relay, echo, "gone"); got != "" {
		t.Fatalf("reply %q after the idle timeout", got)
	}
}
